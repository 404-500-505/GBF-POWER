"""Memory-cache behavior using temporary SQLite storage and a controlled clock."""
from pathlib import Path
import json
import sqlite3
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]/'proxy_core'))
from asset_cache import AssetCache

HOST = 'prd-game-a-granbluefantasy.akamaized.net'
PATH = '/assets/img/sp/test.png'
HEADERS = [('Content-Type', 'image/png'), ('Cache-Control', 'max-age=60')]


class MemoryCacheTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.cache = AssetCache(self.tmp.name)
        self.addCleanup(lambda: self.cache.close())

    def put(self, path=PATH, body=b'PNG', request=None, headers=None):
        self.assertTrue(self.cache.store(HOST, path, request or {}, 200,
                                         HEADERS if headers is None else headers, body))

    def configure(self, **options):
        self.cache.close()
        self.cache = AssetCache(self.tmp.name, **options)

    def is_hot(self, path=PATH, request=None):
        statements = []
        self.cache.db.set_trace_callback(statements.append)
        try:
            entry = self.cache.lookup(HOST, path, request or {})
        finally:
            self.cache.db.set_trace_callback(None)
        self.assertIsNotNone(entry)
        return not statements

    def test_warm_lookup_avoids_sqlite_reads_and_writes(self):
        self.put()
        self.assertEqual(self.cache.lookup(HOST, PATH, {}).body, b'PNG')
        statements = []
        self.cache.db.set_trace_callback(statements.append)
        self.assertEqual(self.cache.lookup(HOST, PATH, {}).body, b'PNG')
        self.assertEqual(statements, [])
        self.cache.db.set_trace_callback(None)
        self.assertGreaterEqual(self.cache.status()['memory_hits'], 1)

    def test_entry_limit_evicts_least_recently_used_memory_only(self):
        self.configure(max_memory_entries=2)
        paths = ['/assets/img/%s.png' % name for name in ('one', 'two', 'three')]
        for path in paths[:2]:
            self.put(path)
            self.cache.lookup(HOST, path, {})
        self.assertTrue(self.is_hot(paths[0]))
        self.put(paths[2])
        self.cache.lookup(HOST, paths[2], {})
        self.assertEqual(self.cache.status()['memory_entries'], 2)
        self.assertTrue(self.is_hot(paths[0]))
        self.assertTrue(self.is_hot(paths[2]))
        self.assertFalse(self.is_hot(paths[1]))
        self.assertEqual(self.cache.status()['entries'], 3)

    def test_byte_limit_accounts_for_headers_and_evicts_or_bypasses(self):
        self.put()
        self.cache.lookup(HOST, PATH, {})
        cost = self.cache.status()['memory_bytes']
        self.assertGreater(cost, len(b'PNG') + len(json.dumps(HEADERS).encode()))
        self.configure(max_memory_bytes=cost)
        self.assertFalse(self.is_hot())
        self.assertTrue(self.is_hot())
        other = '/assets/img/other.png'
        self.put(other)
        self.cache.lookup(HOST, other, {})
        self.assertLessEqual(self.cache.status()['memory_bytes'], cost)
        self.assertTrue(self.is_hot(other))
        self.assertFalse(self.is_hot())
        large = '/assets/img/large.png'
        self.put(large, body=b'x' * (cost + 1))
        self.assertFalse(self.is_hot(large))
        self.assertFalse(self.is_hot(large))
        self.assertEqual(self.cache.status()['max_memory_bytes'], cost)

    def test_replacement_discards_old_hot_entry_even_when_new_body_is_too_large_for_memory(self):
        self.configure(max_memory_bytes=1024)
        self.put()
        self.cache.lookup(HOST, PATH, {})
        self.put(body=b'new' * 1024)
        self.assertEqual(self.cache.lookup(HOST, PATH, {}).body, b'new' * 1024)
        self.assertEqual(self.cache.status()['memory_entries'], 0)

    def test_invalidation_removes_hot_entry_and_its_accounted_bytes(self):
        self.put()
        self.cache.lookup(HOST, PATH, {})
        self.cache.invalidate(HOST, PATH, {})
        self.assertIsNone(self.cache.lookup(HOST, PATH, {}))
        self.assertEqual(self.cache.status()['memory_entries'], 0)
        self.assertEqual(self.cache.status()['memory_bytes'], 0)

    def test_returned_entry_and_nested_headers_cannot_poison_future_hits(self):
        headers = [list(pair) for pair in HEADERS]
        self.put(headers=headers)
        first = self.cache.lookup(HOST, PATH, {})
        headers[0][1] = 'text/html'
        first.headers[0][1] = 'text/plain'
        first.headers.append(['Set-Cookie', 'bad'])
        first.body = b'changed'
        first.expires_at = 0
        second = self.cache.lookup(HOST, PATH, {})
        self.assertEqual(second.headers, [list(pair) for pair in HEADERS])
        self.assertEqual(second.body, b'PNG')
        self.assertTrue(second.fresh({}))
        second.headers.clear()
        self.assertEqual(self.cache.lookup(HOST, PATH, {}).headers, [list(pair) for pair in HEADERS])

    def test_disk_quota_eviction_also_removes_hot_entry(self):
        self.configure(max_bytes=6)
        with patch('asset_cache.time.time', return_value=100):
            self.put()
            self.cache.lookup(HOST, PATH, {})
        with patch('asset_cache.time.time', return_value=101):
            self.put('/assets/img/two.png')
        with patch('asset_cache.time.time', return_value=102):
            self.assertTrue(self.is_hot())
            self.put('/assets/img/three.png')
        self.assertIsNone(self.cache.lookup(HOST, PATH, {}))
        self.assertEqual(self.cache.status()['memory_bytes'], 0)

    def test_hot_entries_keep_original_expiry_and_respect_request_revalidation(self):
        with patch('asset_cache.time.time', return_value=100):
            self.put(headers=HEADERS + [('ETag', '"v1"')])
            first = self.cache.lookup(HOST, PATH, {})
            self.assertTrue(first.fresh({}))
        with patch('asset_cache.time.time', return_value=130):
            for request in ({'cache-control': 'no-cache'}, {'cache-control': 'max-age=0'},
                            {'pragma': 'no-cache'}):
                entry = self.cache.lookup(HOST, PATH, request)
                self.assertFalse(entry.fresh(request))
            self.assertIsNone(self.cache.lookup(HOST, PATH, {'cache-control': 'no-store'}))
        with patch('asset_cache.time.time', return_value=160):
            self.assertTrue(self.is_hot())
            stale = self.cache.lookup(HOST, PATH, {})
            self.assertFalse(stale.fresh({}))
            self.assertEqual((stale.stored_at, stale.expires_at), (100, 160))
            self.assertEqual(stale.validators(), {'if-none-match': '"v1"'})

    def test_hot_response_no_cache_remains_stale(self):
        with patch('asset_cache.time.time', return_value=100):
            self.put(headers=[('Content-Type', 'image/png'), ('Cache-Control', 'no-cache, max-age=600')])
            self.cache.lookup(HOST, PATH, {})
            self.assertTrue(self.is_hot())
            self.assertFalse(self.cache.lookup(HOST, PATH, {}).fresh({}))

    def test_hot_entries_isolate_host_path_encoding_and_origin(self):
        variants = [({}, b'identity'), ({'accept-encoding': 'gzip'}, b'gzip'),
                    ({'origin': 'https://game.granbluefantasy.jp'}, b'origin'),
                    ({'origin': 'https://game.granbluefantasy.jp', 'accept-encoding': 'gzip'}, b'both')]
        for request, body in variants:
            self.put(body=body, request=request)
            self.cache.lookup(HOST, PATH, request)
        for request, body in variants:
            self.assertTrue(self.is_hot(request=request))
            self.assertEqual(self.cache.lookup(HOST, PATH, request).body, body)
        self.assertIsNone(self.cache.lookup('prd-game-a1-granbluefantasy.akamaized.net', PATH, {}))
        self.assertIsNone(self.cache.lookup(HOST, '/assets/img/elsewhere.png', {}))
        self.assertIsNone(self.cache.lookup(HOST, PATH, {'origin': 'https://other.example'}))

    def test_zero_budgets_disable_memory_without_disabling_disk(self):
        for options in ({'max_memory_entries': 0}, {'max_memory_bytes': 0}):
            with self.subTest(options=options):
                self.configure(**options)
                self.put()
                self.assertFalse(self.is_hot())
                self.assertFalse(self.is_hot())
                self.assertEqual(self.cache.status()['memory_entries'], 0)
                self.assertEqual(self.cache.status()['memory_bytes'], 0)

    def test_close_releases_memory_and_reopen_loads_persistent_entry(self):
        self.put()
        self.cache.lookup(HOST, PATH, {})
        self.assertGreater(self.cache.memory_bytes, 0)
        self.cache.close()
        self.assertEqual(self.cache.memory_bytes, 0)
        with self.assertRaises(sqlite3.ProgrammingError):
            self.cache.lookup(HOST, PATH, {})
        self.cache = AssetCache(self.tmp.name)
        self.assertEqual(self.cache.status()['memory_entries'], 0)
        self.assertEqual(self.cache.status()['memory_hits'], 0)
        self.assertFalse(self.is_hot())
        self.assertTrue(self.is_hot())


if __name__ == '__main__':
    unittest.main()
