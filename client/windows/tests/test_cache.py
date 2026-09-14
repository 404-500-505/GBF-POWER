import asyncio
import gzip
import hashlib
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import time
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]/'proxy_core'))
HOST = 'prd-game-a-granbluefantasy.akamaized.net'
PATH = '/assets/img/sp/test.png'


class FeatureTests(unittest.TestCase):
    def test_asset_cache_exists(self):
        self.assertIsNotNone(importlib.util.find_spec('asset_cache'), 'GBF asset cache is not implemented')


@unittest.skipUnless(importlib.util.find_spec('asset_cache'), 'Cache module not implemented yet')
class CacheTests(unittest.TestCase):
    def setUp(self):
        from asset_cache import AssetCache
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.cache = AssetCache(self.root / 'new', self.root / 'legacy', max_bytes=1000, max_item_bytes=500)

    def tearDown(self):
        self.cache.close()
        self.tmp.cleanup()

    def put(self, path=PATH, body=b'PNG', headers=None, request=None):
        return self.cache.store(HOST, path, request or {}, 200,
                                headers or [('Content-Type', 'image/png'), ('Cache-Control', 'max-age=60')], body)

    def test_only_cdn_static_assets_are_eligible(self):
        from asset_cache import eligible
        self.assertTrue(eligible(HOST, PATH, {}))
        self.assertTrue(eligible(HOST, '/assets/1789040290/js/main.js', {}))
        for host, path, headers in [
            ('game.granbluefantasy.jp', PATH, {}), ('connect.mobage.jp', PATH, {}),
            (HOST + '.evil.test', PATH, {}), (HOST, '/battle/start.json', {}),
            (HOST, '/assets/img/../account.png', {}), (HOST, '/assets/%2e%2e/account.png', {}),
            (HOST, '/assets/img/a.png?token=secret', {}), (HOST, '/assets/img/a.png:stream', {}),
            (HOST, PATH, {'cookie': 'account=secret'}), (HOST, PATH, {'authorization': 'secret'}),
            (HOST, PATH, {'range': 'bytes=0-2'}), (HOST, PATH, {'cache-control': 'no-store'})]:
            with self.subTest(host=host, path=path, headers=headers):
                self.assertFalse(eligible(host, path, headers))

    def test_hit_is_exact_host_path_and_accept_encoding(self):
        self.assertTrue(self.put(request={'accept-encoding': 'gzip'}))
        entry = self.cache.lookup(HOST, PATH, {'accept-encoding': 'gzip'})
        self.assertEqual(entry.body, b'PNG')
        self.assertTrue(entry.fresh({}))
        self.assertIsNone(self.cache.lookup(HOST, PATH, {}))
        self.assertIsNone(self.cache.lookup('prd-game-a1-granbluefantasy.akamaized.net', PATH, {'accept-encoding':'gzip'}))
        self.assertIsNone(self.cache.lookup(HOST, '/assets/img/sp/new.png', {'accept-encoding':'gzip'}))

    def test_personalized_or_unsupported_responses_never_stored(self):
        for extra in [('Cache-Control','private, max-age=999'), ('Cache-Control','no-store'),
                      ('Set-Cookie','secret=x'), ('Vary','Cookie'), ('Vary','*'),
                      ('Content-Type','text/html'), ('Content-Range','bytes 0-2/10')]:
            with self.subTest(extra=extra):
                self.assertFalse(self.put(headers=[('Content-Type','image/png'), extra]))
        self.assertFalse(self.cache.store(HOST, PATH, {}, 404, [('Content-Type','image/png')], b'404'))

    def test_cache_control_and_age_respected(self):
        for value in ['no-cache, max-age=60', 'max-age=0', 'max-age=1']:
            self.put(headers=[('Content-Type','image/png'),('Cache-Control',value),('Age','2')])
            self.assertFalse(self.cache.lookup(HOST, PATH, {}).fresh({}))
        self.put()
        for request in [{'cache-control':'no-cache'}, {'cache-control':'max-age=0'}, {'pragma':'no-cache'}]:
            self.assertFalse(self.cache.lookup(HOST, PATH, {}).fresh(request))

    def test_unversioned_assets_without_explicit_ttl_use_bounded_http_heuristic(self):
        headers=[('Content-Type','image/png'),('Last-Modified','Wed, 01 Jan 2025 00:00:00 GMT')]
        self.put(headers=headers)
        entry=self.cache.lookup(HOST,PATH,{})
        self.assertTrue(entry.fresh({}))
        self.assertLessEqual(entry.expires_at-entry.stored_at,60)
        self.put(headers=headers+[('Cache-Control','no-cache')])
        self.assertFalse(self.cache.lookup(HOST,PATH,{}).fresh({}))
        self.put(headers=[('Content-Type','image/png')])
        self.assertFalse(self.cache.lookup(HOST,PATH,{}).fresh({}))

    def test_quota_evicts_oldest_without_touching_legacy(self):
        self.put('/assets/img/one.png', b'1'*450)
        self.put('/assets/img/two.png', b'2'*450)
        self.put('/assets/img/three.png', b'3'*450)
        self.assertLessEqual(self.cache.status()['bytes'], 1000)
        self.assertIsNone(self.cache.lookup(HOST, '/assets/img/one.png', {}))
        self.assertIsNotNone(self.cache.lookup(HOST, '/assets/img/three.png', {}))
        self.assertFalse(self.put(body=b'x'*501))

    def legacy(self, body=b'old'):
        path = self.root / 'legacy' / 'https' / PATH.lstrip('/')
        path.parent.mkdir(parents=True)
        wire = gzip.compress(body)
        path.write_bytes(wire)
        Path(str(path)+'.ext').write_text(json.dumps({'md5':hashlib.md5(wire).hexdigest(),
            'ce':'gzip','ct':'image/png','ETag':'"old"','LastModified':'Wed, 01 Jan 2025 00:00:00 GMT','v':1}))
        return path, wire

    def test_legacy_requires_origin_validation_and_valid_wire_checksum(self):
        path, wire = self.legacy()
        entry = self.cache.legacy(HOST, PATH, {'accept-encoding':'gzip'})
        self.assertEqual(entry.body, wire)
        self.assertFalse(entry.fresh({}))
        self.assertEqual(entry.validators(), {'if-none-match':'"old"'})
        self.assertIsNone(self.cache.legacy(HOST, PATH, {'accept-encoding':'identity'}))
        path.write_bytes(b'corrupt')
        self.assertIsNone(self.cache.legacy(HOST, PATH, {'accept-encoding':'gzip'}))

    def test_legacy_gzip_q_zero_is_not_accepted(self):
        self.legacy()
        self.assertIsNone(self.cache.legacy(HOST, PATH, {'accept-encoding':'gzip;q=0, br'}))

    def test_legacy_uncompressed_null_encoding_is_supported(self):
        path,wire=self.legacy()
        meta=json.loads(Path(str(path)+'.ext').read_text())
        meta['ce']=None
        path.write_bytes(b'UNCOMPRESSED-IMAGE')
        meta['md5']=hashlib.md5(path.read_bytes()).hexdigest()
        Path(str(path)+'.ext').write_text(json.dumps(meta))
        self.assertIsNotNone(self.cache.legacy(HOST,PATH,{}))

    def test_new_cache_survives_reopen(self):
        from asset_cache import AssetCache
        self.put()
        self.cache.close()
        self.cache = AssetCache(self.root/'new', self.root/'legacy',1000,500)
        self.assertEqual(self.cache.lookup(HOST, PATH, {}).body, b'PNG')


if __name__ == '__main__':
    unittest.main()
