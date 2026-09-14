"""Manage an OpenSSH dynamic tunnel and connect with remote SOCKS5 DNS."""
from __future__ import annotations

import asyncio
import ipaddress
import logging
import os
from pathlib import Path
import shutil
import socket
import struct
import subprocess

LOG = logging.getLogger('gbf-local-proxy')


async def open_socks(upstream_port, host, port, timeout=15):
    async def connect():
        reader, writer = await asyncio.open_connection('127.0.0.1', upstream_port)
        success = False
        try:
            writer.write(b'\x05\x01\x00')
            await writer.drain()
            if await reader.readexactly(2) != b'\x05\x00':
                raise OSError('Upstream SOCKS5 authentication rejected')
            try:
                ip = ipaddress.ip_address(host)
            except ValueError:
                encoded = host.encode('idna')
                if not 1 <= len(encoded) <= 255:
                    raise OSError('Destination name is too long')
                address = bytes([3, len(encoded)]) + encoded
            else:
                address = bytes([1 if ip.version == 4 else 4]) + ip.packed
            writer.write(b'\x05\x01\x00' + address + struct.pack('!H', port))
            await writer.drain()
            version, result, reserved, atyp = await reader.readexactly(4)
            if version != 5 or result != 0 or reserved != 0:
                raise OSError(f'Upstream SOCKS5 CONNECT failed ({result})')
            if atyp == 1:
                await reader.readexactly(4)
            elif atyp == 4:
                await reader.readexactly(16)
            elif atyp == 3:
                await reader.readexactly((await reader.readexactly(1))[0])
            else:
                raise OSError('Invalid upstream SOCKS5 reply')
            await reader.readexactly(2)
            success = True
            return reader, writer
        except (asyncio.IncompleteReadError, ValueError, UnicodeError) as error:
            raise OSError('Upstream SOCKS5 handshake failed') from error
        finally:
            if not success:
                writer.close()
                try:
                    await writer.wait_closed()
                except OSError:
                    pass
    return await asyncio.wait_for(connect(), timeout)


class SshTunnel:
    def __init__(self, config, root, runtime):
        self.config = config
        self.root = Path(root)
        self.runtime = Path(runtime)
        self.process = None
        self.monitor = None
        self.stderr_task = None
        self.ready = False
        self.stopping = False
        self.reconnects = 0
        self.last_error = None

    def command(self):
        c = self.config
        executable = shutil.which('ssh')
        if not executable:
            raise FileNotFoundError('Windows OpenSSH client (ssh.exe) is required')
        key = (self.root / c['private_key']).resolve()
        known = (self.root / c['known_hosts']).resolve().as_posix()
        return [executable, '-F', 'none', '-N', '-T', '-i', str(key),
                '-D', f"127.0.0.1:{c['socks_port']}", '-p', str(c.get('port', 22)),
                '-o', 'BatchMode=yes', '-o', 'IdentitiesOnly=yes',
                '-o', 'IdentityAgent=none', '-o', 'PreferredAuthentications=publickey',
                '-o', 'StrictHostKeyChecking=yes', '-o', f'UserKnownHostsFile="{known}"',
                '-o', 'ExitOnForwardFailure=yes', '-o', 'ConnectTimeout=10',
                '-o', 'ServerAliveInterval=15', '-o', 'ServerAliveCountMax=3',
                '-o', 'Compression=no', '-o', 'LogLevel=ERROR',
                f"{c['username']}@{c['host']}"]

    async def start(self):
        c = self.config
        for key, label in [('private_key', 'private key'), ('known_hosts', 'pinned host key file')]:
            if not (self.root / c[key]).is_file():
                raise FileNotFoundError(f'Missing SSH {label}: {c[key]}')
        await self.launch()
        self.monitor = asyncio.create_task(self.watch())

    async def read_stderr(self, process):
        while line := await process.stderr.readline():
            message = line.decode('utf-8', 'replace').strip()
            if message:
                self.last_error = message[:200]
                LOG.warning('SSH: %s', message[:500])

    async def launch(self):
        self.ready = False
        self.last_error = None
        # A foreign listener must not be mistaken for this SSH tunnel.
        with socket.socket() as probe:
            if os.name == 'nt':
                probe.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
            probe.bind(('127.0.0.1', self.config['socks_port']))
        self.process = await asyncio.create_subprocess_exec(
            *self.command(), stdin=asyncio.subprocess.DEVNULL,
            stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.PIPE,
            creationflags=subprocess.CREATE_NO_WINDOW if os.name == 'nt' else 0)
        self.stderr_task = asyncio.create_task(self.read_stderr(self.process))
        try:
            for _ in range(120):
                if self.process.returncode is not None:
                    raise OSError(f'SSH tunnel exited ({self.process.returncode}); see runtime/proxy.log')
                writer = None
                try:
                    reader, writer = await asyncio.wait_for(
                        asyncio.open_connection('127.0.0.1', self.config['socks_port']), 0.3)
                    writer.write(b'\x05\x01\x00')
                    await writer.drain()
                    reply = await asyncio.wait_for(reader.readexactly(2), 0.5)
                    if reply == b'\x05\x00' and self.process.returncode is None:
                        self.ready = True
                        LOG.info('Japan SSH tunnel ready; server=%s; reconnects=%s',
                                 self.config['host'], self.reconnects)
                        return
                except (OSError, TimeoutError, asyncio.IncompleteReadError):
                    pass
                finally:
                    if writer:
                        writer.close()
                        try:
                            await writer.wait_closed()
                        except OSError:
                            pass
                await asyncio.sleep(0.1)
            raise OSError('SSH tunnel startup timed out; see runtime/proxy.log')
        except BaseException:
            await self.stop_process()
            raise

    async def watch(self):
        delay = 2
        while not self.stopping:
            await self.process.wait()
            self.ready = False
            await self.stop_process()
            while not self.stopping:
                LOG.warning('SSH disconnected; retrying in %ss; direct fallback disabled', delay)
                await asyncio.sleep(delay)
                self.reconnects += 1
                try:
                    await self.launch()
                    delay = 2
                    break
                except OSError:
                    delay = min(delay * 2, 30)

    async def stop_process(self):
        process = self.process
        if process and process.returncode is None:
            try:
                process.terminate()
            except ProcessLookupError:
                pass
            try:
                await asyncio.wait_for(process.wait(), 3)
            except TimeoutError:
                process.kill()
                await process.wait()
        if self.stderr_task:
            await asyncio.gather(self.stderr_task, return_exceptions=True)
        self.process = None

    async def close(self):
        self.stopping = True
        self.ready = False
        if self.monitor:
            self.monitor.cancel()
            await asyncio.gather(self.monitor, return_exceptions=True)
        await self.stop_process()

    def status(self):
        return dict(connected=self.ready, server=self.config['host'],
                    reconnects=self.reconnects,
                    ssh_pid=self.process.pid if self.process else None)
