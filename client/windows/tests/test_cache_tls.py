import asyncio
import importlib.util
from pathlib import Path
import ssl
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]/'proxy_core'
sys.path.insert(0,str(ROOT))
HOST = 'prd-game-a-granbluefantasy.akamaized.net'


class CertificateFeatureTests(unittest.TestCase):
    def test_certificate_module_exists(self):
        self.assertIsNotNone(importlib.util.find_spec('cache_certificate'), 'Scoped TLS certificates are not implemented')


@unittest.skipUnless(importlib.util.find_spec('cache_certificate'), 'Awaiting scoped TLS implementation')
class CertificateTests(unittest.TestCase):
    def test_unique_ca_constrained_leaf_and_no_saved_ca_private_key(self):
        from cache_certificate import prepare_certificate
        from asset_cache import ASSET_HOSTS
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            one = prepare_certificate(directory/'one')
            two = prepare_certificate(directory/'two')
            root = x509.load_pem_x509_certificate((directory/'one/ca.pem').read_bytes())
            leaf = x509.load_pem_x509_certificate((directory/'one/leaf.pem').read_bytes())
            names = leaf.extensions.get_extension_for_class(x509.SubjectAlternativeName).value.get_values_for_type(x509.DNSName)
            self.assertEqual(set(names),set(ASSET_HOSTS))
            self.assertFalse(leaf.extensions.get_extension_for_class(x509.BasicConstraints).value.ca)
            constraints = root.extensions.get_extension_for_class(x509.NameConstraints)
            self.assertTrue(constraints.critical)
            self.assertEqual({x.value for x in constraints.value.permitted_subtrees},set(ASSET_HOSTS))
            self.assertNotEqual(one['thumbprint'],two['thumbprint'])
            self.assertEqual(one['thumbprint'],root.fingerprint(hashes.SHA1()).hex().upper())
            self.assertFalse((directory/'one/ca-key.pem').exists())
            self.assertEqual(one,prepare_certificate(directory/'one'))


class GatewayFeatureTests(unittest.TestCase):
    def test_gateway_module_exists(self):
        self.assertIsNotNone(importlib.util.find_spec('asset_gateway'), 'HTTPS asset cache gateway is not implemented')


@unittest.skipUnless(importlib.util.find_spec('asset_gateway'), 'Awaiting HTTPS cache gateway')
class GatewayTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        from cache_certificate import prepare_certificate
        from asset_cache import AssetCache
        from asset_gateway import AssetGateway
        from gbf_proxy import ProxyServer
        self.tmp = tempfile.TemporaryDirectory()
        self.path = Path(self.tmp.name)
        await asyncio.to_thread(prepare_certificate,self.path/'certs')
        self.requests = []
        self.origin_headers = [('Content-Type','image/png'),('Cache-Control','max-age=60'),('ETag','"v1"')]
        self.origin_status = 200
        self.truncated = False
        self.origin_body = b'PNG-actual-origin-body'
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(self.path/'certs/leaf.pem',self.path/'certs/leaf-key.pem')
        self.origin = await asyncio.start_server(self.origin_handler,'127.0.0.1',0,ssl=context)
        self.origin_port = self.origin.sockets[0].getsockname()[1]
        self.cache = AssetCache(self.path/'cache')
        async def open_origin(host,port):
            self.assertEqual(host,HOST)
            self.assertEqual(port,443)
            return await asyncio.open_connection('127.0.0.1',self.origin_port)
        self.gateway = AssetGateway(self.cache,self.path/'certs',open_origin,
                                   origin_context=ssl.create_default_context(cafile=str(self.path/'certs/ca.pem')))
        self.proxy = ProxyServer(port=0,runtime_dir=self.path/'run',asset_gateway=self.gateway)
        await self.gateway.start()
        await self.proxy.start()

    async def asyncTearDown(self):
        await self.proxy.close()
        await self.gateway.close()
        self.origin.close()
        await self.origin.wait_closed()
        self.cache.close()
        self.tmp.cleanup()

    async def origin_handler(self,reader,writer):
        import h11
        connection = h11.Connection(h11.SERVER)
        try:
            request = await reader.readuntil(b'\r\n\r\n')
            self.requests.append(request)
            connection.receive_data(request)
            request_event=connection.next_event()
            connection.next_event()
            headers = self.origin_headers + [('Connection','close'),('Content-Length',str(len(self.origin_body) if self.origin_status!=304 else 0))]
            writer.write(connection.send(h11.Response(status_code=self.origin_status,headers=headers)))
            if self.origin_status != 304 and request_event.method != b'HEAD':
                writer.write(connection.send(h11.Data(data=self.origin_body[:4] if self.truncated else self.origin_body)))
            if not self.truncated:
                writer.write(connection.send(h11.EndOfMessage()))
            await writer.drain()
        finally:
            writer.close()
            await writer.wait_closed()

    async def get(self,path='/assets/img/test.png',headers='',sni=HOST,host=HOST,trust=True):
        reader,writer = await asyncio.open_connection('127.0.0.1',self.proxy.port)
        try:
            writer.write(f'CONNECT {HOST}:443 HTTP/1.1\r\nHost: {HOST}:443\r\n\r\n'.encode())
            await writer.drain()
            self.assertIn(b'200',await reader.readuntil(b'\r\n\r\n'))
            context = ssl.create_default_context(cafile=str(self.path/'certs/ca.pem') if trust else None)
            await writer.start_tls(context,server_hostname=sni)
            writer.write(f'GET {path} HTTP/1.1\r\nHost: {host}\r\n{headers}Connection: close\r\n\r\n'.encode())
            await writer.drain()
            return await asyncio.wait_for(reader.read(),5)
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except (OSError,ssl.SSLError):
                pass

    async def test_real_tls_miss_then_hit_without_second_origin_request(self):
        first = await self.get()
        second = await self.get()
        self.assertIn(self.origin_body,first)
        self.assertIn(self.origin_body,second)
        self.assertIn(b'x-gbf-cache: hit',second.lower())
        self.assertEqual(len(self.requests),1)
        self.assertEqual(self.gateway.stats['hits'],1)

    async def test_cookie_query_range_and_api_bypass_cache(self):
        for path,headers in [('/assets/img/a.png','Cookie: private=x\r\n'),
                             ('/assets/img/a.png?version=2',''),('/assets/img/a.png','Range: bytes=0-2\r\n'),
                             ('/battle/start.json','')]:
            before = len(self.requests)
            await self.get(path,headers)
            await self.get(path,headers)
            self.assertEqual(len(self.requests)-before,2)
        self.assertEqual(self.cache.status()['entries'],0)

    async def test_forced_revalidation_304_reuses_exact_body(self):
        await self.get()
        self.origin_status = 304
        second = await self.get(headers='Cache-Control: no-cache\r\n')
        self.assertIn(self.origin_body,second)
        self.assertIn(b'if-none-match: "v1"',self.requests[-1].lower())
        self.assertEqual(self.gateway.stats['revalidated'],1)

    async def test_404_after_expiry_does_not_return_stale_body(self):
        await self.get()
        self.origin_status, self.origin_body = 404,b'not found'
        second = await self.get(headers='Cache-Control: no-cache\r\n')
        self.assertIn(b'404',second.split(b'\r\n')[0])
        self.assertNotIn(b'PNG-actual-origin-body',second)

    async def test_host_mismatch_is_rejected(self):
        response = await self.get(host='accounts.dmm.com')
        self.assertIn(b'421',response.split(b'\r\n')[0])
        self.assertEqual(self.requests,[])

    async def test_untrusted_local_ca_is_rejected(self):
        with self.assertRaises(ssl.SSLCertVerificationError):
            await self.get(trust=False)

    async def test_origin_certificate_validation_is_not_disabled(self):
        self.gateway.origin_context = ssl.create_default_context()
        response = await self.get()
        self.assertIn(b'502',response.split(b'\r\n')[0])
        self.assertEqual(self.cache.status()['entries'],0)

    async def test_unknown_sni_is_rejected(self):
        with self.assertRaises((ssl.SSLError,ConnectionError)):
            await self.get(sni='accounts.dmm.com')

    async def test_parallel_identical_requests_use_single_origin_fetch(self):
        results = await asyncio.gather(*(self.get() for _ in range(6)))
        self.assertTrue(all(self.origin_body in result for result in results))
        self.assertEqual(len(self.requests),1)

    async def test_large_asset_streams_fully_without_being_cached(self):
        self.cache.max_item_bytes=100
        self.origin_body=b'x'*200000
        response=await self.get()
        self.assertTrue(response.endswith(self.origin_body))
        self.assertEqual(self.cache.status()['entries'],0)

    async def test_no_store_response_never_enters_cache(self):
        self.origin_headers=[('Content-Type','image/png'),('Cache-Control','no-store')]
        await self.get()
        await self.get()
        self.assertEqual(len(self.requests),2)
        self.assertEqual(self.cache.status()['entries'],0)

    async def test_legacy_304_imports_verified_wire_bytes_without_modifying_old_file(self):
        import gzip,hashlib,json
        legacy=self.path/'legacy/https/assets/img/test.png'
        legacy.parent.mkdir(parents=True)
        wire=gzip.compress(b'LEGACY-IMAGE')
        legacy.write_bytes(wire)
        Path(str(legacy)+'.ext').write_text(json.dumps({'ct':'image/png','ce':'gzip',
            'md5':hashlib.md5(wire).hexdigest(),'ETag':'"v1"'}))
        self.cache.legacy_dir=self.path/'legacy'
        self.origin_status=304
        response=await self.get(headers='Accept-Encoding: gzip\r\n')
        self.assertTrue(response.endswith(wire))
        self.assertEqual(legacy.read_bytes(),wire)
        self.assertEqual(self.gateway.stats['legacy_hits'],1)
        self.assertEqual(self.cache.status()['entries'],1)
        await self.get(headers='Accept-Encoding: gzip\r\n')
        self.assertEqual(len(self.requests),1)

    async def test_legacy_can_validate_with_head_when_origin_ignores_conditional_get(self):
        import hashlib,json
        legacy=self.path/'legacy/https/assets/img/test.png'
        legacy.parent.mkdir(parents=True)
        legacy.write_bytes(self.origin_body)
        Path(str(legacy)+'.ext').write_text(json.dumps({'ct':'image/png','ce':None,
            'md5':hashlib.md5(self.origin_body).hexdigest(),'ETag':'"v1"'}))
        self.cache.legacy_dir=self.path/'legacy'
        response=await self.get()
        self.assertTrue(response.endswith(self.origin_body))
        self.assertTrue(self.requests[0].startswith(b'HEAD '))
        self.assertEqual(len(self.requests),1)
        self.assertEqual(self.gateway.stats['legacy_hits'],1)

    async def test_disconnected_origin_never_serves_stale(self):
        await self.get()
        self.origin.close()
        await self.origin.wait_closed()
        response=await self.get(headers='Cache-Control: no-cache\r\n')
        self.assertIn(b'502',response.split(b'\r\n')[0])
        self.assertNotIn(self.origin_body,response)

    async def test_truncated_origin_body_is_never_committed(self):
        self.truncated=True
        response=await self.get()
        self.assertNotIn(self.origin_body,response)
        self.assertEqual(self.cache.status()['entries'],0)

    async def test_game_login_and_battle_hosts_are_not_intercepted(self):
        for host in ['game.granbluefantasy.jp','gbf.game.mbga.jp','connect.mobage.jp',
                     'accounts.dmm.com','gamewith.jp',HOST+'.evil.test']:
            self.assertFalse(self.gateway.handles(host,443))
        self.assertFalse(self.gateway.handles(HOST,80))


if __name__ == '__main__':
    unittest.main()
