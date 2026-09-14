import sys
from pathlib import Path
import unittest
sys.path.insert(0, str(Path(__file__).resolve().parents[1]/'app'))
try:
    import client_model as m
except ModuleNotFoundError:
    m=None

class ModelTests(unittest.TestCase):
    def setUp(self):
        self.assertIsNotNone(m, 'client_model 尚未实现')
    def test_tunnels_never_called_requests(self):
        v=m.display_stats({'connect_tunnels':9,'socks5_tunnels':4,'cache':{'requests':7,'hits':3}})
        self.assertEqual(v['tunnels'],13)
        self.assertEqual(v['asset_requests'],7)
        self.assertEqual(v['cache_hits'],3)
    def test_old_engine_does_not_guess_requests(self):
        self.assertIsNone(m.display_stats({'cache':{'hits':5,'misses':8}})['asset_requests'])
    def test_unknown_not_zero(self):
        self.assertEqual(m.number(None),'—')
        self.assertEqual(m.number(0),'0')
    def test_ping_missing_and_unanswered_are_distinct(self):
        p=m.PingWindow()
        self.assertIsNone(p.view(5)['loss'])
        p.add(None,1)
        self.assertIsNone(p.view(5)['loss'])
        p.add(80,2)
        self.assertEqual(p.view(5)['loss'],50)
        self.assertEqual(p.view(5)['sent'],2)
        self.assertIsNone(p.view(700)['loss'])
    def test_node_quality_uses_p95_and_consecutive_timeouts(self):
        p=m.PingWindow();p.add(100,1);p.add(900,2);p.add(None,3);p.add(None,4)
        self.assertEqual(p.quality(5),{'p95_ms':900,'consecutive_timeouts':2})
        self.assertEqual(p.quality(700),{'p95_ms':0,'consecutive_timeouts':0})
    def test_operation_reentrance(self):
        g=m.OperationGate()
        self.assertTrue(g.begin('starting'))
        self.assertFalse(g.begin('stopping'))
        g.finish('running')
        self.assertTrue(g.begin('stopping'))
    def test_counter_reset(self):
        p=m.Rates()
        self.assertIsNone(p.update('a',100,1))
        self.assertEqual(p.update('a',300,2),200)
        self.assertIsNone(p.update('b',30,3))
        self.assertIsNone(p.update('b',20,4))
        self.assertIsNone(p.update('b',30,20))

if __name__=='__main__':unittest.main()
