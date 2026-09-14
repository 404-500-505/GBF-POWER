import importlib.util
from pathlib import Path
import sys
import unittest
import http.client
import threading
from unittest.mock import patch

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'proxy_core'))


class FeatureTests(unittest.TestCase):
    def test_metrics_module_exists(self):
        self.assertIsNotNone(importlib.util.find_spec('monitor_metrics'))

    def test_server_module_exists(self):
        self.assertIsNotNone(importlib.util.find_spec('monitor'))


@unittest.skipUnless(importlib.util.find_spec('monitor_metrics'),'Awaiting implementation')
class MetricsTests(unittest.TestCase):
    def setUp(self):
        from monitor_metrics import Metrics
        self.m=Metrics()

    def source(self,down=100,up=20,uptime=10,connected=True):
        return dict(app='gbf-local-proxy',instance='test',version='0.3.0',uptime_seconds=uptime,
                    bytes_downloaded=down,bytes_uploaded=up,errors=9,active_connections=3,
                    tunnel=dict(connected=connected,reconnects=2,server='192.0.2.20'),
                    cache=dict(enabled=True,hits=3,misses=7,revalidated=2,legacy_hits=2,
                               saved_bytes=1000,entries=6,bytes=900,max_bytes=10000,errors=4),
                    stop_token='DO-NOT-EXPORT')

    def test_rate_uses_elapsed_time(self):
        self.m.update(self.source(),100)
        self.assertIsNone(self.m.snapshot(100)['down_bps'])
        self.m.update(self.source(down=500,up=100,uptime=12),102)
        state=self.m.snapshot(102)
        self.assertEqual(state['down_bps'],200)
        self.assertEqual(state['up_bps'],40)

    def test_restart_resets_baseline_without_negative_rates(self):
        self.m.update(self.source(down=2000,uptime=20),100)
        self.m.update(self.source(down=1,uptime=1),101)
        self.assertIsNone(self.m.snapshot(101)['down_bps'])
        self.assertTrue(any('重新启动' in x['message'] for x in self.m.snapshot(101)['events']))

    def test_offline_never_shows_stale_speed_or_connected_state(self):
        self.m.update(self.source(),100)
        self.m.update(None,101)
        state=self.m.snapshot(101)
        self.assertFalse(state['proxy_online'])
        self.assertFalse(state['connected'])
        self.assertIsNone(state['down_bps'])

    def test_arbitrary_source_fields_are_not_exported(self):
        self.m.update(self.source(),100)
        self.assertNotIn('DO-NOT-EXPORT',str(self.m.snapshot(100)))

    def test_replica_cache_counters_are_exported_without_extra_private_fields(self):
        source = self.source()
        expected = dict(memory_hits=4,memory_entries=2,memory_bytes=300,max_memory_bytes=67108864,
                        origin_opened=2,origin_reused=8,origin_retries=1,origin_idle=1)
        source['cache'].update(expected,private_key='NEVER-EXPORT')
        self.m.update(source,100)
        cache = self.m.snapshot(100)['cache']
        for name,value in expected.items():
            self.assertEqual(cache.get(name),value)
        self.assertNotIn('NEVER-EXPORT',str(cache))

    def test_ping_missing_reply_is_not_claimed_as_definite_packet_loss(self):
        self.m.ping(None,100)
        self.m.ping(None,110)
        state=self.m.snapshot(110)['ping']
        self.assertIsNone(state['loss_percent'])
        self.assertEqual(state['sent'],2)
        self.assertEqual(state['received'],0)

    def test_ping_window_is_rolling_and_independent_of_proxy_errors(self):
        self.m.ping(100,100)
        self.m.ping(None,110)
        self.assertEqual(self.m.snapshot(110)['ping']['loss_percent'],50)
        self.assertEqual(self.m.snapshot(800)['ping']['sent'],0)

    def test_history_is_bounded_and_time_gaps_have_no_average_speed(self):
        for i in range(400):
            self.m.update(self.source(down=i*100,uptime=i),i)
        self.assertLessEqual(len(self.m.snapshot(400)['history']),300)
        self.m.update(self.source(down=100000,uptime=500),500)
        self.assertIsNone(self.m.snapshot(500)['down_bps'])

    def test_connection_changes_create_events(self):
        self.m.update(self.source(),100)
        self.m.update(self.source(connected=False,uptime=11),101)
        self.assertTrue(any('断开' in x['message'] for x in self.m.snapshot(101)['events']))

    def test_snapshot_becomes_stale_without_new_samples(self):
        self.m.update(self.source(),100)
        self.assertFalse(self.m.snapshot(110)['connected'])

    def test_gbf_old_response_not_presented_as_current(self):
        self.m.gbf(123,200,100)
        self.assertEqual(self.m.snapshot(101)['gbf']['ms'],123)
        self.assertIsNone(self.m.snapshot(140)['gbf']['ms'])


@unittest.skipUnless(importlib.util.find_spec('monitor'),'Awaiting implementation')
class ServerTests(unittest.TestCase):
    def setUp(self):
        from monitor import Monitor, make_server
        self.app = Monitor(8123,'192.0.2.20',preview=True)
        self.server = make_server(self.app,0)
        self.thread = threading.Thread(target=self.server.serve_forever,daemon=True)
        self.thread.start()

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join()

    def request(self,path,headers=None,method='GET'):
        connection = http.client.HTTPConnection('127.0.0.1',self.server.server_port,timeout=3)
        connection.request(method,path,headers=headers or {})
        response = connection.getresponse()
        result = (response.status,dict(response.getheaders()),response.read())
        connection.close()
        return result

    def test_api_is_filtered_and_no_cache(self):
        status,headers,body=self.request('/api/status')
        self.assertEqual(status,200)
        self.assertEqual(headers['Cache-Control'],'no-store')
        self.assertIn(b'gbf-local-monitor',body)
        self.assertNotIn(b'stop_token',body)

    def test_static_allowlist_prevents_reading_config(self):
        self.assertEqual(self.request('/config.json')[0],404)
        self.assertEqual(self.request('/../config.json')[0],404)

    def test_rebinding_and_cross_origin_requests_rejected(self):
        self.assertEqual(self.request('/api/status',{'Host':'evil.example'})[0],403)
        self.assertEqual(self.request('/api/status',{'Origin':'https://evil.example'})[0],403)
        self.assertEqual(self.request('/api/status',{'Sec-Fetch-Site':'cross-site'})[0],403)

    def test_monitor_has_no_proxy_control_endpoint(self):
        self.assertEqual(self.request('/_control/stop',method='POST')[0],405)

    def test_health_does_not_activate_probes(self):
        self.request('/health')
        self.assertFalse(self.app.active())
        self.request('/api/status')
        self.assertTrue(self.app.active())

    def test_preview_does_not_report_isolated_icmp_as_user_latency(self):
        with patch('monitor.ping_node', return_value=0) as ping:
            self.app.sample('ping')
            ping.assert_not_called()
        self.assertEqual(self.app.snapshot()['ping']['sent'],0)

    def test_page_inactivity_expires_after_fifteen_seconds(self):
        with patch('monitor.time.monotonic',return_value=100):
            self.app.snapshot()
        with patch('monitor.time.monotonic',return_value=116):
            self.assertFalse(self.app.active())


if __name__=='__main__': unittest.main()
