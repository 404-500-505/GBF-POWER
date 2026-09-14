"""Real TLS integration tests; no live GBF accounts or services involved."""
import asyncio
import ssl
import unittest

import h11
try:
    from . import test_cache_tls as fixtures
except ImportError:
    import test_cache_tls as fixtures
HOST = fixtures.HOST


class KeepAliveTests(fixtures.GatewayTests):
    async def asyncSetUp(self):
        self.origin_connections = 0
        self.origin_writers = set()
        self.close_origin = False
        self.drop_request_number = None
        self.response_gate = None
        self.request_arrived = asyncio.Event()
        await super().asyncSetUp()

    async def asyncTearDown(self):
        for writer in self.origin_writers.copy():
            writer.close()
        await super().asyncTearDown()

    async def origin_handler(self, reader, writer):
        from asset_gateway import event
        self.origin_connections += 1
        self.origin_writers.add(writer)
        conn = h11.Connection(h11.SERVER)
        try:
            while True:
                req = await event(conn, reader)
                if isinstance(req, h11.ConnectionClosed):
                    break
                self.assertIsInstance(req, h11.Request)
                self.assertIsInstance(await event(conn, reader), h11.EndOfMessage)
                self.requests.append(req.method+b' '+req.target+b' '+b'\r\n'.join(k+b': '+v for k,v in req.headers))
                self.request_arrived.set()
                if self.response_gate is not None:
                    await self.response_gate.wait()
                if len(self.requests) == self.drop_request_number:
                    break  # Simulate the peer closing as a pooled request arrives.
                headers = self.origin_headers + [('Content-Length',str(len(self.origin_body) if self.origin_status != 304 else 0))]
                if self.close_origin:
                    headers.append(('Connection','close'))
                writer.write(conn.send(h11.Response(status_code=self.origin_status,headers=headers)))
                if self.origin_status != 304 and req.method != b'HEAD':
                    writer.write(conn.send(h11.Data(data=self.origin_body[:4] if self.truncated else self.origin_body)))
                if not self.truncated:
                    writer.write(conn.send(h11.EndOfMessage()))
                await writer.drain()
                if self.truncated or conn.our_state is h11.MUST_CLOSE:
                    break
                conn.start_next_cycle()
        except (OSError, h11.ProtocolError, asyncio.IncompleteReadError):
            pass
        finally:
            self.origin_writers.discard(writer)
            writer.close()
            try:
                await writer.wait_closed()
            except OSError:
                pass

    async def connect_browser(self):
        reader,writer = await asyncio.open_connection('127.0.0.1',self.proxy.port)
        writer.write(f'CONNECT {HOST}:443 HTTP/1.1\r\nHost: {HOST}:443\r\n\r\n'.encode())
        await writer.drain()
        await reader.readuntil(b'\r\n\r\n')
        await writer.start_tls(ssl.create_default_context(cafile=str(self.path/'certs/ca.pem')), server_hostname=HOST)
        return reader,writer

    async def test_different_assets_reuse_one_origin_tls_connection(self):
        for name in ('a','b','c'):
            self.assertTrue((await self.get(f'/assets/img/{name}.png')).endswith(self.origin_body))
        self.assertEqual(len(self.requests),3)
        self.assertEqual(self.origin_connections,1, 'Each asset unnecessarily reconnects and handshakes')

    async def test_browser_connection_accepts_multiple_requests_and_checks_each_host(self):
        reader,writer = await self.connect_browser()
        try:
            for host in (HOST, HOST, 'accounts.dmm.com'):
                writer.write(f'GET /assets/img/keep.png HTTP/1.1\r\nHost: {host}\r\n\r\n'.encode())
                await writer.drain()
                head = await asyncio.wait_for(reader.readuntil(b'\r\n\r\n'),3)
                if host != HOST:
                    self.assertIn(b'421',head)
                    break
                self.assertNotIn(b'connection: close',head.lower(), 'Gateway forces browser reconnect')
                length = int(next(x.split(b':',1)[1] for x in head.lower().split(b'\r\n') if x.startswith(b'content-length:')))
                self.assertEqual(await reader.readexactly(length),self.origin_body)
            self.assertEqual(len(self.requests),1)
        finally:
            writer.close()
            await writer.wait_closed()

    async def test_origin_close_is_never_reused(self):
        self.close_origin = True
        await self.get('/assets/img/a.png')
        await self.get('/assets/img/b.png')
        self.assertEqual(self.origin_connections,2)

    async def test_closed_idle_origin_reconnects(self):
        await self.get('/assets/img/a.png')
        for writer in self.origin_writers.copy():
            writer.close()
            await writer.wait_closed()
        result = await self.get('/assets/img/b.png')
        self.assertTrue(result.endswith(self.origin_body))
        self.assertEqual(self.origin_connections,2)

    async def test_peer_close_race_retries_get_once_before_headers(self):
        await self.get('/assets/img/a.png')
        self.drop_request_number = 2
        result = await self.get('/assets/img/b.png')
        self.assertTrue(result.endswith(self.origin_body))
        self.assertEqual(self.origin_connections,2)
        self.assertEqual(self.gateway.origin_pool.retries,1)

    async def test_truncated_response_connection_is_discarded(self):
        self.truncated = True
        await self.get('/assets/img/a.png')
        self.truncated = False
        self.assertTrue((await self.get('/assets/img/b.png')).endswith(self.origin_body))
        self.assertEqual(self.origin_connections,2)

    async def test_idle_expiry_closes_pool_connection(self):
        self.gateway.origin_pool.idle_seconds = 0.01
        await self.get('/assets/img/a.png')
        await asyncio.sleep(0.03)
        self.assertEqual(self.gateway.origin_pool.status()['origin_idle'],0)
        await self.get('/assets/img/b.png')
        self.assertEqual(self.origin_connections,2)

    async def test_pool_shutdown_closes_idle_connections(self):
        await self.get()
        pool = self.gateway.origin_pool
        self.assertEqual(pool.status()['origin_idle'],1)
        await pool.close()
        self.assertFalse(pool.connections)
        self.assertEqual(pool.status()['origin_idle'],0)

    async def test_idle_capacity_is_bounded_under_parallel_fetches(self):
        pool = self.gateway.origin_pool
        pool.max_idle = 2
        pool.per_host = 1
        await asyncio.gather(*(self.get(f'/assets/img/{n}.png') for n in range(8)))
        self.assertEqual(len(self.requests),8)
        self.assertLessEqual(pool.status()['origin_idle'],1)

    async def test_tls_context_change_does_not_reuse_old_trusted_connection(self):
        await self.get('/assets/img/a.png')
        self.gateway.origin_context = ssl.create_default_context()
        result = await self.get('/assets/img/b.png')
        self.assertIn(b'502',result.split(b'\r\n')[0])
        self.assertEqual(len(self.requests),1)

    async def test_per_host_idle_limit_spans_tls_contexts(self):
        self.gateway.origin_pool.per_host = 1
        await self.get('/assets/img/a.png')
        self.gateway.origin_context = ssl.create_default_context(cafile=str(self.path/'certs/ca.pem'))
        await self.get('/assets/img/b.png')
        self.assertEqual(self.origin_connections,2)
        self.assertEqual(self.gateway.origin_pool.status()['origin_idle'],1)

    async def test_cancelling_origin_request_discards_active_connection(self):
        pool = self.gateway.origin_pool
        self.response_gate = asyncio.Event()
        async def fetch():
            async with pool.request(HOST,self.gateway.origin_context,'GET','/assets/img/a.png', [('Host',HOST)]):
                self.fail('Response must remain blocked by the test gate')
        task = asyncio.create_task(fetch())
        try:
            await asyncio.wait_for(self.request_arrived.wait(),3)
            task.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await task
            self.assertFalse(pool.connections)
            self.assertEqual(pool.status()['origin_idle'],0)
        finally:
            self.response_gate.set()
            task.cancel()
            await asyncio.gather(task,return_exceptions=True)

    async def test_two_cdn_hosts_never_share_origin_connection(self):
        from asset_gateway import event
        pool = self.gateway.origin_pool
        async def open_origin(host,port):
            return await asyncio.open_connection('127.0.0.1',self.origin_port)
        pool.open_origin = open_origin
        for host in (HOST,'prd-game-a1-granbluefantasy.akamaized.net',HOST):
            async with pool.request(host,self.gateway.origin_context,'GET','/assets/img/a.png',[('Host',host)]) as (up,response):
                self.assertEqual(response.status_code,200)
                while not isinstance(await event(up.protocol,up.reader),h11.EndOfMessage):
                    pass
        self.assertEqual(self.origin_connections,2)
        self.assertEqual(pool.reused,1)

    async def test_disconnected_origin_never_serves_stale(self):
        # Closing a listener does not close established keep-alive connections.
        await self.get()
        for writer in self.origin_writers.copy():
            writer.close()
            await writer.wait_closed()
        self.origin.close()
        await self.origin.wait_closed()
        result = await self.get(headers='Cache-Control: no-cache\r\n')
        self.assertIn(b'502',result.split(b'\r\n')[0])


if __name__ == '__main__':
    unittest.main()
