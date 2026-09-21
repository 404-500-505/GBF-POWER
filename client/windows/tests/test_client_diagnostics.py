import importlib.util
import sys
import threading
import subprocess
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]/'app'))


class DiagnosticTests(unittest.TestCase):
    def test_stalled_node_does_not_spawn_duplicates_or_starve_other_nodes(self):
        m=self.module();release=threading.Event();calls=[]
        def probe(node):
            calls.append(node['host'])
            if node['host']=='slow':release.wait(1)
            return 60
        try:
            self.assertEqual(m.probe_nodes({'tokyo':{'host':'slow'}},probe=probe,timeout=.02),{'tokyo':None})
            result=m.probe_nodes({'tokyo':{'host':'slow'},'tokyo_cn2':{'host':'fast'}},probe=probe,timeout=.02)
            self.assertEqual(result['tokyo_cn2'],60)
            self.assertEqual(calls.count('slow'),1)
        finally:release.set()

    def test_daemon_probe_does_not_delay_process_exit(self):
        module_path=Path(__file__).resolve().parents[1]/'app'
        code=(f'import sys;sys.path.insert(0,{str(module_path)!r})\n'
              'import threading,time\nfrom client_diagnostics import probe_nodes\n'
              'started=threading.Event()\n'
              'def slow(node):\n started.set();time.sleep(4);return 1\n'
              'threading.Thread(target=lambda:probe_nodes({"tokyo":{}},probe=slow),daemon=True).start()\n'
              'assert started.wait(1)\n')
        try:
            result=subprocess.run([sys.executable,'-c',code],capture_output=True,timeout=2)
        except subprocess.TimeoutExpired:
            self.fail('Background node probes must not hold the process open at shutdown')
        self.assertEqual(result.returncode,0,result.stderr.decode(errors='replace'))

    def module(self):
        self.assertIsNotNone(importlib.util.find_spec('client_diagnostics'), 'Client diagnostics helper is missing')
        import client_diagnostics
        return client_diagnostics

    def test_node_probes_are_parallel_and_unknown_nodes_are_ignored(self):
        m = self.module()
        barrier = threading.Barrier(2)
        def probe(node):
            barrier.wait(timeout=2)
            return node['latency']
        results = m.probe_nodes({'tokyo': {'latency': 70}, 'tokyo_cn2': {'latency': 60},
                                 'unknown': {'latency': 1}}, probe=probe)
        self.assertEqual(results, {'tokyo': 70, 'tokyo_cn2': 60})

    def test_live_route_ignores_assignment_and_rejects_split_route(self):
        m = self.module()
        status = {'instance': 'session', 'tunnel': {'connected': True, 'server': 'live.example'}}
        self.assertEqual(m.runtime_route(status), ('session', 'live.example'))
        status['game_channel'] = {'enabled': True, 'connected': True, 'server': 'other.example'}
        self.assertIsNone(m.runtime_route(status))
        self.assertIsNone(m.runtime_route(None))

    def test_certificate_snapshot_is_cached_but_can_be_invalidated(self):
        m = self.module()
        calls = []
        def read(root):
            calls.append(root)
            return {'trusted': len(calls)}
        cache = m.CertificateSnapshot(read)
        self.assertEqual(cache.get('a', 0), {'trusted': 1})
        self.assertEqual(cache.get('a', 1), {'trusted': 1})
        self.assertEqual(cache.get('a', 30), {'trusted': 2})
        self.assertEqual(cache.get('a', 31, refresh=True), {'trusted': 3})
        self.assertEqual(cache.get('b', 32), {'trusted': 4})


if __name__ == '__main__': unittest.main()
