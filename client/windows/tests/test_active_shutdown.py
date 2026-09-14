"""Real loopback connections stay open while shutdown must complete.

Every runtime/certificate/cache path is isolated in a temporary directory.
"""
import asyncio
from pathlib import Path
import ssl
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]/'proxy_core'))
from gbf_proxy import ProxyServer
from asset_gateway import AssetGateway
from asset_cache import AssetCache
from cache_certificate import prepare_certificate


class ActiveShutdownTests(unittest.IsolatedAsyncioTestCase):
    async def test_proxy_aborts_pending_output_on_shutdown(self):
        with tempfile.TemporaryDirectory() as folder:
            proxy = ProxyServer(port=0, runtime_dir=Path(folder) / 'runtime')
            await proxy.start()
            reader, writer = await asyncio.open_connection('127.0.0.1', proxy.port)
            writer.transport.pause_reading()
            closing = None
            try:
                while not proxy.writers:
                    await asyncio.sleep(.01)
                accepted = next(iter(proxy.writers))
                accepted.write(b'x' * (16 * 1024 * 1024))
                accepted.write(b'y' * (16 * 1024 * 1024))
                self.assertGreater(accepted.transport.get_write_buffer_size(), 0)
                closing = asyncio.create_task(proxy.close())
                done, _ = await asyncio.wait([closing], timeout=3)
                self.assertIn(closing, done, 'Pending browser output blocks shutdown')
                await closing
            finally:
                writer.transport.abort()
                for stream in tuple(proxy.writers):
                    stream.transport.abort()
                if closing:
                    await asyncio.wait_for(closing, 5)
                else:
                    await proxy.close()

    async def test_gateway_closes_unfinished_tls_handshake(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            await asyncio.to_thread(prepare_certificate, root / 'certs')
            cache = AssetCache(root / 'cache')
            async def unused_origin(*_):
                self.fail('Handshake shutdown must not contact origin')
            gateway = AssetGateway(cache, root / 'certs', unused_origin)
            await gateway.start()
            reader, writer = await gateway.open('prd-game-a-granbluefantasy.akamaized.net')
            await asyncio.sleep(.05)
            try:
                self.assertFalse(gateway.tasks, 'Fixture must stay before TLS handle()')
                await self.assert_closes_without_client_help(gateway, writer, timeout=3)
            finally:
                await gateway.close()
                cache.close()

    async def close_writer(self, writer):
        writer.close()
        try:
            await writer.wait_closed()
        except OSError:
            pass

    async def assert_closes_without_client_help(self, service, writer, timeout=1):
        closing = asyncio.create_task(service.close())
        try:
            done, _ = await asyncio.wait([closing], timeout=timeout)
            completed = closing in done
        finally:
            # Only cleanup AFTER recording whether shutdown needed the client.
            await self.close_writer(writer)
            await asyncio.wait_for(closing, 5)
        self.assertTrue(completed, 'Shutdown waits for client disconnect before closing its clients')

    async def test_proxy_closes_active_connect_without_browser_disconnect(self):
        with tempfile.TemporaryDirectory() as folder:
            async def origin(reader, writer):
                try:
                    await reader.read()
                finally:
                    await self.close_writer(writer)

            backend = await asyncio.start_server(origin, '127.0.0.1', 0)
            proxy = ProxyServer(port=0, runtime_dir=Path(folder) / 'runtime')
            await proxy.start()
            try:
                reader, writer = await asyncio.open_connection('127.0.0.1', proxy.port)
                port = backend.sockets[0].getsockname()[1]
                writer.write(f'CONNECT 127.0.0.1:{port} HTTP/1.1\r\nHost: local\r\n\r\n'.encode())
                await writer.drain()
                self.assertIn(b'200', await reader.readuntil(b'\r\n\r\n'))
                await self.assert_closes_without_client_help(proxy, writer)
                self.assertFalse((Path(folder) / 'runtime/state.json').exists())
                self.assertFalse(proxy.tasks)
            finally:
                await proxy.close()
                backend.close()
                await backend.wait_closed()

    async def test_gateway_closes_idle_tls_without_browser_disconnect(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            await asyncio.to_thread(prepare_certificate, root / 'certs')
            cache = AssetCache(root / 'cache')
            async def unused_origin(*_):
                self.fail('Idle TLS shutdown must not contact an origin')
            gateway = AssetGateway(cache, root / 'certs', unused_origin)
            await gateway.start()
            try:
                host = 'prd-game-a-granbluefantasy.akamaized.net'
                reader, writer = await gateway.open(host)
                await writer.start_tls(ssl.create_default_context(cafile=str(root / 'certs/ca.pem')),
                                       server_hostname=host)
                async def entered():
                    while not gateway.tasks:
                        await asyncio.sleep(.01)
                await asyncio.wait_for(entered(), 1)
                await self.assert_closes_without_client_help(gateway, writer, timeout=3)
                self.assertFalse(gateway.tasks)
                self.assertTrue(gateway.origin_pool.closed)
            finally:
                await gateway.close()
                cache.close()
