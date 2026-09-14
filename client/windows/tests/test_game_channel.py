"""Independent game SSH routing; all network fixtures stay on loopback."""
import asyncio
import copy
import importlib
import inspect
import json
from pathlib import Path
import re
import shutil
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]/'proxy_core'
sys.path.insert(0, str(ROOT))
import gbf_proxy as proxy


def config():
    return dict(port=8123, connect_timeout_seconds=2, idle_timeout_seconds=2,
                max_connections=16, ssh=dict(host='test.example', username='test', port=22,
                socks_port=18124, private_key='test-key', known_hosts='test-hosts'))


class ConfigTests(unittest.TestCase):
    def helper(self):
        self.assertTrue((ROOT / 'game_channel.py').exists(), 'game channel configuration is missing')
        return importlib.import_module('game_channel').game_channel_config

    def test_default_disabled_and_original_config_unchanged(self):
        resolve = self.helper()
        c = config()
        self.assertIsNone(resolve(c))
        c['game_channel'] = {'enabled': False}
        self.assertIsNone(resolve(c))
        c['game_channel']['enabled'] = True
        original = copy.deepcopy(c)
        resolved = resolve(c)
        self.assertEqual(resolved, {**c['ssh'], 'socks_port': 18125})
        self.assertEqual(c, original)
        self.assertIsNot(resolved, c['ssh'])

    def test_strict_config_types_ports_and_conflicts(self):
        resolve = self.helper()
        bad = [None, False, [], 'yes', {}, {'enabled': 1}, {'enabled': 'true'},
               *[dict(enabled=True, socks_port=x) for x in (True, False, None, '18125', 1.0, 0, -1, 65536, 8123, 18124)],
               dict(enabled=False, socks_port='18125')]
        for value in bad:
            with self.subTest(value=value), self.assertRaises(ValueError):
                resolve({**config(), 'game_channel': value})
        for port in (1, 65535):
            self.assertEqual(resolve({**config(), 'game_channel': dict(enabled=True, socks_port=port)})['socks_port'], port)
        for ssh in (None, {}, False, 'bad'):
            with self.subTest(ssh=ssh), self.assertRaises(ValueError):
                resolve({**config(), 'ssh': ssh, 'game_channel': {'enabled': True}})

    def test_extension_cannot_override_server_or_credentials(self):
        c = config()
        c['game_channel'] = dict(enabled=True, socks_port=18126, host='evil.example',
                                 username='other', private_key='other-key', known_hosts='other-hosts', port=99)
        self.assertEqual(self.helper()(c), {**c['ssh'], 'socks_port': 18126})


class LocalSocks:
    def __init__(self):
        self.requests = []
        self.tasks = set()
        self.writers = set()

    async def start(self):
        self.server = await asyncio.start_server(self.handle, '127.0.0.1', 0)
        self.port = self.server.sockets[0].getsockname()[1]
        return self

    async def close(self):
        self.server.close()
        await self.server.wait_closed()
        for writer in tuple(self.writers):
            writer.close()
        await asyncio.gather(*tuple(self.tasks), return_exceptions=True)

    async def handle(self, reader, writer):
        self.tasks.add(asyncio.current_task())
        self.writers.add(writer)
        try:
            if await reader.readexactly(3) != b'\x05\x01\x00':
                return
            writer.write(b'\x05\x00')
            await writer.drain()
            header = await reader.readexactly(4)
            if header[:3] != b'\x05\x01\x00':
                return
            if header[3] == 1:
                host = socket.inet_ntoa(await reader.readexactly(4))
            elif header[3] == 3:
                host = (await reader.readexactly((await reader.readexactly(1))[0])).decode('ascii')
            else:
                return
            port = struct.unpack('!H', await reader.readexactly(2))[0]
            self.requests.append((host, port))
            writer.write(b'\x05\x00\x00\x01' + b'\x00' * 6 + b'\x00\xffserver-first\r\n')
            await writer.drain()
            while data := await reader.read(65536):
                writer.write(data)
                await writer.drain()
        except (OSError, asyncio.IncompleteReadError):
            pass
        finally:
            writer.close()
            await writer.wait_closed()
            self.writers.discard(writer)
            self.tasks.discard(asyncio.current_task())


class TunnelState:
    def __init__(self, port, pid):
        self.config = {**config()['ssh'], 'socks_port': port}
        self.ready = True
        self.pid = pid

    def status(self):
        return dict(connected=self.ready, ssh_pid=self.pid, server=self.config['host'], reconnects=0)


class RoutingTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.assertIn('game_tunnel', inspect.signature(proxy.ProxyServer).parameters,
                      'ProxyServer does not accept the independent channel')
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.shared = await LocalSocks().start()
        self.addAsyncCleanup(self.shared.close)
        self.game = await LocalSocks().start()
        self.addAsyncCleanup(self.game.close)
        self.game_tunnel = TunnelState(self.game.port, 222)
        self.server = proxy.ProxyServer(port=0, runtime_dir=self.temp.name,
            upstream_port=self.shared.port, ssh_tunnel=TunnelState(self.shared.port, 111),
            game_tunnel=self.game_tunnel)
        await self.server.start()
        self.addAsyncCleanup(self.server.close)

    async def request(self, path):
        reader, writer = await asyncio.open_connection('127.0.0.1', self.server.port)
        writer.write(f'GET {path} HTTP/1.1\r\nHost: 127.0.0.1:{self.server.port}\r\n\r\n'.encode())
        await writer.drain()
        reply = await reader.read()
        writer.close()
        await writer.wait_closed()
        return reply.split(b'\r\n\r\n', 1)[1]

    async def connect(self, host, port, socks=False, success=True):
        reader, writer = await asyncio.open_connection('127.0.0.1', self.server.port)
        try:
            if socks:
                writer.write(b'\x05\x01\x00')
                await writer.drain()
                self.assertEqual(await reader.readexactly(2), b'\x05\x00')
                name = host.encode()
                writer.write(b'\x05\x01\x00\x03' + bytes([len(name)]) + name + struct.pack('!H', port))
                await writer.drain()
                result = await reader.readexactly(10)
                self.assertEqual(result[1] == 0, success)
            else:
                writer.write(f'CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}:{port}\r\n\r\n'.encode())
                await writer.drain()
                result = await reader.readuntil(b'\r\n\r\n')
                self.assertEqual(result.startswith(b'HTTP/1.1 200'), success, result)
            if success:
                self.assertEqual(await reader.readexactly(16), b'\x00\xffserver-first\r\n')
                data = bytes(range(256)) * 512
                writer.write(data)
                await writer.drain()
                self.assertEqual(await reader.readexactly(len(data)), data)
        finally:
            writer.close()
            await writer.wait_closed()

    async def test_exact_battle_hosts_use_priority_channel(self):
        battle_hosts = ['GAME.GRANBLUEFANTASY.JP.', 'WS.GAME.GRANBLUEFANTASY.JP.',
                        ('203.104.' + '248.14')]
        for host in battle_hosts:
            for socks in (False, True):
                await self.connect(host, 443, socks=socks)
        self.assertEqual(len(self.game.requests), 6)
        self.assertEqual(self.shared.requests, [])
        status = json.loads(await self.request('/status.json'))['game_channel']
        self.assertEqual(status['hosts'], ['game.granbluefantasy.jp',
                                           'ws.game.granbluefantasy.jp',
                                           ('203.104.' + '248.14')])
        self.assertEqual((status['enabled'], status['connected'], status['connections'], status['ssh_pid']),
                         (True, True, 6, 222))
        self.assertIn('B', (await self.request('/')).decode())
        self.assertIn('战斗优先', (await self.request('/')).decode())

    async def test_exact_realtime_endpoints_on_11240_use_priority_channel(self):
        for host in ('WS.GAME.GRANBLUEFANTASY.JP.', ('203.104.' + '248.14')):
            for socks in (False, True):
                await self.connect(host, 11240, socks=socks)
        self.assertEqual(self.game.requests, [
            ('ws.game.granbluefantasy.jp.', 11240),
            ('WS.GAME.GRANBLUEFANTASY.JP.', 11240),
            (('203.104.' + '248.14'), 11240),
            (('203.104.' + '248.14'), 11240),
        ])
        self.assertEqual(self.shared.requests, [])

    async def test_assets_other_ports_and_lookalikes_use_shared(self):
        cases = [('prd-game-a-granbluefantasy.akamaized.net', 443), ('example.com', 443),
                 ('game.granbluefantasy.jp', 80), ('sub.game.granbluefantasy.jp', 443),
                 ('game.granbluefantasy.jp', 11240), ('ws.game.granbluefantasy.jp', 11241),
                 ('ws.game.granbluefantasy.jp.evil.test', 11240),
                 ('game.granbluefantasy.jp.evil.test', 443), ('notgame.granbluefantasy.jp', 443)]
        for host, port in cases:
            await self.connect(host, port)
        self.assertEqual(self.shared.requests, cases)
        self.assertEqual(self.game.requests, [])

    async def test_game_disconnect_fails_closed_and_shared_remains_working(self):
        self.game_tunnel.ready = False
        for host in ('game.granbluefantasy.jp', 'ws.game.granbluefantasy.jp', ('203.104.' + '248.14')):
            await self.connect(host, 443, success=False)
            await self.connect(host, 443, socks=True, success=False)
        self.assertEqual(self.shared.requests, [])
        self.assertEqual(self.game.requests, [])
        await self.connect('example.com', 443)
        status = json.loads(await self.request('/status.json'))['game_channel']
        self.assertEqual((status['connected'], status['connections']), (False, 0))

    async def test_failed_socks_connection_never_falls_back(self):
        self.game.server.close()
        await self.game.server.wait_closed()
        await self.connect('game.granbluefantasy.jp', 443, success=False)
        self.assertEqual(self.shared.requests, [])
        status = json.loads(await self.request('/status.json'))['game_channel']
        self.assertEqual(status['connections'], 0)

    async def test_disabled_preserves_shared_routing_and_status(self):
        self.server.game_tunnel = None
        await self.connect('game.granbluefantasy.jp', 443)
        self.assertEqual(self.shared.requests, [('game.granbluefantasy.jp', 443)])
        status = json.loads(await self.request('/status.json'))['game_channel']
        self.assertEqual((status['enabled'], status['connected'], status['connections'], status['ssh_pid']),
                         (False, False, 0, None))
        self.assertIn('A', (await self.request('/')).decode())
        self.assertIn('共享', (await self.request('/')).decode())


class LifecycleTests(unittest.IsolatedAsyncioTestCase):
    async def exercise(self, fail_start=None, enabled=True):
        self.assertIn('game_tunnel', inspect.signature(proxy.ProxyServer).parameters,
                      'run lifecycle needs the independent channel API')
        self.assertIn('runtime_dir=runtime', inspect.getsource(proxy.run),
                      'lifecycle tests require explicit isolated runtime injection')
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            instances = []
            started = asyncio.Event()

            class OfflineSsh:
                def __init__(self, cfg, root, runtime):
                    self.config, self.ready, self.closed = cfg, False, False
                    instances.append(self)

                async def start(self):
                    self.ready = True
                    if len([x for x in instances if x.ready]) == fail_start:
                        raise OSError('deliberate SSH startup failure')
                    if all(x.ready for x in instances):
                        started.set()

                async def close(self):
                    self.closed, self.ready = True, False

            c = config()
            c['port'] = 0
            c['game_channel'] = dict(enabled=enabled)
            with patch.object(proxy, 'ROOT', root), patch.object(proxy, 'SshTunnel', OfflineSsh):
                task = asyncio.create_task(proxy.run(c))
                if fail_start:
                    with self.assertRaisesRegex(OSError, 'deliberate'):
                        await asyncio.wait_for(task, 2)
                else:
                    try:
                        await asyncio.wait_for(started.wait(), 2)
                    finally:
                        task.cancel()
                        with self.assertRaises(asyncio.CancelledError):
                            await task
            self.assertEqual(len(instances), 2 if enabled else 1)
            self.assertTrue(all(x.closed for x in instances), 'all allocated SSH instances must close')
            if enabled:
                self.assertEqual(instances[1].config, {**c['ssh'], 'socks_port': 18125})
            self.assertFalse((root / 'runtime/state.json').exists())

    async def test_both_tunnels_closed_on_cancellation(self):
        await self.exercise()

    async def test_first_start_failure_cleans_both_allocated_tunnels(self):
        await self.exercise(fail_start=1)

    async def test_second_start_failure_cleans_first_tunnel_and_listener(self):
        await self.exercise(fail_start=2)

    async def test_disabled_creates_only_original_tunnel(self):
        await self.exercise(enabled=False)
