import asyncio
import importlib.util
import json
from pathlib import Path
import socket
import struct
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]/'proxy_core'
sys.path.insert(0, str(ROOT))
import gbf_proxy


class ModuleTests(unittest.TestCase):
    def test_ssh_tunnel_module_exists(self):
        self.assertIsNotNone(importlib.util.find_spec('ssh_tunnel'), 'SSH lifecycle is not implemented')


class UpstreamTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.server = None
        self.backend = None
        self.seen = []

    async def asyncTearDown(self):
        if self.server:
            self.server.close()
            await self.server.wait_closed()
        if self.backend:
            self.backend.close()
            await self.backend.wait_closed()
        self.tmp.cleanup()

    async def make_proxy(self, callback):
        self.server = await asyncio.start_server(callback, '127.0.0.1', 0)
        proxy = gbf_proxy.ProxyServer(port=0, runtime_dir=Path(self.tmp.name))
        proxy.upstream_port = self.server.sockets[0].getsockname()[1]
        return proxy

    async def test_destination_dns_is_resolved_by_upstream(self):
        async def socks(reader, writer):
            self.assertEqual(await reader.readexactly(3), b'\x05\x01\x00')
            writer.write(b'\x05\x00')
            await writer.drain()
            self.assertEqual(await reader.readexactly(4), b'\x05\x01\x00\x03')
            count = (await reader.readexactly(1))[0]
            host = (await reader.readexactly(count)).decode()
            port = struct.unpack('!H', await reader.readexactly(2))[0]
            self.seen.append((host, port))
            writer.write(b'\x05\x00\x00\x01' + b'\x00' * 6 + b'upstream-ok')
            await writer.drain()
            writer.close()
            await writer.wait_closed()
        proxy = await self.make_proxy(socks)
        reader, writer = await proxy.open_remote('resolves-only-in-japan.invalid', 443)
        self.assertEqual(await reader.readexactly(11), b'upstream-ok')
        writer.close()
        await writer.wait_closed()
        self.assertEqual(self.seen, [('resolves-only-in-japan.invalid', 443)])

    async def test_upstream_failure_never_falls_back_to_direct(self):
        reached_origin = []
        async def origin(reader, writer):
            reached_origin.append(True)
            writer.close()
        self.backend = await asyncio.start_server(origin, '127.0.0.1', 0)
        async def refusal(reader, writer):
            await reader.readexactly(3)
            writer.write(b'\x05\xff')
            await writer.drain()
            writer.close()
        proxy = await self.make_proxy(refusal)
        with self.assertRaises(OSError):
            await proxy.open_remote('127.0.0.1', self.backend.sockets[0].getsockname()[1])
        self.assertEqual(reached_origin, [])

    async def test_proxy_reports_upstream_failure_as_http_502(self):
        async def refusal(reader, writer):
            await reader.readexactly(3)
            writer.write(b'\x05\xff')
            await writer.drain()
            writer.close()
        proxy = await self.make_proxy(refusal)
        await proxy.start()
        try:
            reader, writer = await asyncio.open_connection('127.0.0.1', proxy.port)
            writer.write(b'CONNECT upstream-only.invalid:443 HTTP/1.1\r\nHost: upstream-only.invalid\r\n\r\n')
            response = await asyncio.wait_for(reader.read(), 3)
            self.assertIn(b'502 Bad Gateway', response)
            self.assertNotIn(b'stage 1', response)
            writer.close()
            await writer.wait_closed()
        finally:
            await proxy.close()


@unittest.skipUnless(importlib.util.find_spec('ssh_tunnel'), 'Awaiting SSH lifecycle implementation')
class TunnelTests(unittest.IsolatedAsyncioTestCase):
    def settings(self):
        return dict(host='192.0.2.20', port=22, username='gbfproxy', socks_port=18124,
                    private_key='runtime/ssh/id_ed25519', known_hosts='runtime/ssh/known_hosts')

    async def test_command_pins_host_key_and_binds_loopback(self):
        from ssh_tunnel import SshTunnel
        tunnel = SshTunnel(self.settings(), ROOT, ROOT / 'runtime')
        command = tunnel.command()
        self.assertIn('127.0.0.1:18124', command)
        self.assertIn('StrictHostKeyChecking=yes', command)
        self.assertIn('ExitOnForwardFailure=yes', command)
        self.assertIn('BatchMode=yes', command)
        self.assertIn('gbfproxy@192.0.2.20', command)
        self.assertNotIn('-C', command)

    async def test_missing_key_fails_clearly_without_launch(self):
        from ssh_tunnel import SshTunnel
        with tempfile.TemporaryDirectory() as directory:
            tunnel = SshTunnel(self.settings(), Path(directory), Path(directory))
            with self.assertRaisesRegex(FileNotFoundError, 'private key'):
                await tunnel.start()
            await tunnel.close()


if __name__ == '__main__':
    unittest.main()
