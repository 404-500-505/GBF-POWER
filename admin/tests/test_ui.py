from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from admin_ui import AdminWindow,create_root

class UiTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.root=create_root()
        self.app=AdminWindow(self.root,Path(self.tmp.name),preview=True)
    def tearDown(self):self.app.busy=False;self.app.close();self.tmp.cleanup()
    def sample(self):
        return {'sampled_at':100,'server':{},'metering':{'enabled':True,'healthy':True},'events':[],
                'nodes':[{'id':'tokyo','label':'日本・东京','healthy':True,'draining':False,'utilization':.1,'upload_bps':1,'download_bps':2,'devices':1,'connections':2,'throttled_devices':0,'probe_latency_ms':60,'probe_failures':0,'auth_latency_ms':1,'auth_errors':0,'last_report_at':100},
                         {'id':'tokyo_cn2','label':'日本・东京 CN2','healthy':True,'draining':False,'utilization':.15,'upload_bps':2,'download_bps':3,'devices':0,'connections':0,'throttled_devices':0,'probe_latency_ms':42,'probe_failures':0,'auth_latency_ms':1,'auth_errors':0,'last_report_at':100},
                         {'id':'osaka','label':'日本・大阪','healthy':True,'draining':False,'utilization':.2,'upload_bps':3,'download_bps':4,'devices':0,'connections':0,'throttled_devices':0,'probe_latency_ms':61,'probe_failures':0,'auth_latency_ms':2,'auth_errors':0,'last_report_at':100}],
                'licenses':[{'id':'a'*24,'created':100,'disabled':False,'note':'张三','device_count':1,
                    'devices':[{'id':'b'*24,'created':100,'revoked':False,'note':'家里电脑','online_sessions':1,'active_connections':0,'upload_bytes':1024,'download_bytes':2048}]}]}
    def test_empty_window_has_no_fake_online_data(self):
        self.assertIn('尚未连接',self.app.status.cget('text'))
        self.assertEqual(self.app.licenses.get_children(),())
        self.assertEqual(self.app.settings.private_key,'')
    def test_bad_snapshot_preserves_previous_and_polling_continues(self):
        previous=self.sample();self.app.render(previous)
        self.root.after_cancel(self.app.timer)
        self.app.queue.put(('success','snapshot',{'licenses':[None],'server':{}}))
        self.app.drain()
        self.assertEqual(self.app.snapshot,previous)
        self.assertTrue(self.root.tk.call('after','info'))
        self.assertTrue(self.app.source_error)
        self.root.after_cancel(self.app.timer)
        following=self.sample();following['licenses'][0]['note']='更新'
        self.app.queue.put(('success','snapshot',following));self.app.drain()
        self.assertEqual(self.app.snapshot,following)
    def test_old_server_sample_and_busy_refresh_are_marked_stale(self):
        self.app.render(self.sample())
        self.assertIn('陈旧',self.app.status.cget('text'))
        self.app.busy=True;self.app.update_status()
        self.assertIn('陈旧',self.app.status.cget('text'))
    def test_missing_device_count_is_unknown(self):
        sample=self.sample();sample['licenses'][0].pop('device_count')
        self.app.render(sample)
        self.assertIn('—/2',self.app.licenses.item('a'*24,'values'))
    def test_render_keeps_selected_license_and_shows_server_bytes(self):
        self.app.render(self.sample());self.root.update()
        self.assertEqual(self.app.selected_license(),'a'*24)
        values=self.app.devices.item('b'*24,'values')
        self.assertIn('1.00 KiB',values);self.assertIn('家里电脑',values)
        self.app.render(self.sample());self.assertEqual(self.app.selected_license(),'a'*24)
    def test_render_separates_online_tunnels_from_forwarding_connections(self):
        self.app.render(self.sample());self.root.update()
        values=self.app.devices.item('b'*24,'values')
        self.assertEqual(values[1],'在线')
        self.assertEqual(values[5:7],('1','0'))
    def test_render_shows_both_nodes_without_server_addresses(self):
        self.app.render(self.sample());self.root.update()
        self.assertEqual(set(self.app.nodes.get_children()),{'tokyo','tokyo_cn2','osaka'})
        visible=' '.join(str(self.app.nodes.item(item,'values')) for item in self.app.nodes.get_children())
        self.assertIn('日本・东京',visible);self.assertIn('日本・东京 CN2',visible);self.assertIn('日本・大阪',visible)
        self.assertNotRegex(visible,r'\b(?:\d{1,3}\.){3}\d{1,3}\b|SSH')
    def test_revoke_requires_confirmation(self):
        self.app.render(self.sample());self.app.devices.selection_set('b'*24)
        with patch('admin_ui.messagebox.askyesno',return_value=False),patch.object(self.app,'run') as run:
            self.app.revoke_device()
        run.assert_not_called()
    def test_revoke_only_selected_device(self):
        self.app.render(self.sample());self.app.devices.selection_set('b'*24)
        with patch('admin_ui.messagebox.askyesno',return_value=True),patch.object(self.app,'run') as run:
            self.app.revoke_device()
        self.assertEqual(run.call_args.args[:2],('revoke-device','b'*24))

if __name__=='__main__':unittest.main()
