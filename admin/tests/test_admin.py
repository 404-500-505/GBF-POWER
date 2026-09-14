import base64
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from admin_transport import AdminClient,AdminError,Settings,remote_command,validate_snapshot
from admin_model import byte_count,rate,time_text,device_values,snapshot_summary,node_values

ID='a'*24

class TransportTests(unittest.TestCase):
    def test_note_is_one_base64_argument_and_id_cannot_inject(self):
        command=remote_command('note-device',ID,'测试备注; $(whoami)')
        self.assertEqual(base64.b64decode(command.split()[-1]).decode(),'测试备注; $(whoami)')
        with self.assertRaises(AdminError):remote_command('revoke-device',ID+';id')
        with self.assertRaises(AdminError):remote_command('shell')
        with self.assertRaises(AdminError):remote_command('note-license',ID,'字'*501)
    def test_argument_validation_prevents_host_option_injection(self):
        with self.assertRaises(AdminError):Settings(host='-oProxyCommand=bad').validate()
        with self.assertRaises(AdminError):Settings(username='root;id').validate()
    def test_settings_only_store_connection_paths_not_key_content(self):
        with tempfile.TemporaryDirectory() as temp:
            folder=Path(temp);key=folder/'private';key.write_text('SECRET-KEY')
            settings=Settings(private_key=str(key),known_hosts=str(folder/'known'))
            path=folder/'settings.json';settings.save(path)
            self.assertNotIn('SECRET-KEY',path.read_text())
            self.assertEqual(Settings.load(path).private_key,str(key))
    def test_ssh_has_strict_identity_and_no_interactive_password(self):
        with tempfile.TemporaryDirectory() as temp:
            key=Path(temp)/'key';known=Path(temp)/'known';key.write_text('dummy');known.write_text('public')
            client=AdminClient(Settings(private_key=str(key),known_hosts=str(known)))
            result=subprocess.CompletedProcess([],0,b'{"licenses":[],"server":{},"sampled_at":1}',b'')
            with patch('admin_transport.subprocess.run',return_value=result) as run:
                client.call('snapshot')
            args=run.call_args.args[0]
            self.assertIn('StrictHostKeyChecking=yes',args)
            self.assertIn('BatchMode=yes',args)
            self.assertIn('IdentityAgent=none',args)
            self.assertNotIn('shell',run.call_args.kwargs)
    def test_failed_create_never_returns_code_or_stderr_secrets(self):
        with tempfile.TemporaryDirectory() as temp:
            key=Path(temp)/'key';key.write_text('dummy')
            client=AdminClient(Settings(private_key=str(key),known_hosts=str(key)))
            code='GBF-'+'A'*32
            reply=subprocess.CompletedProcess([],255,code.encode(),b'Load key: Permission denied '+code.encode())
            with patch('admin_transport.subprocess.run',return_value=reply):
                with self.assertRaises(AdminError) as raised:client.call('create')
            self.assertNotIn(code,str(raised.exception))
            self.assertIn('权限',str(raised.exception))
    def test_connection_timeout_is_friendly(self):
        with tempfile.TemporaryDirectory() as temp:
            key=Path(temp)/'key';key.write_text('dummy')
            client=AdminClient(Settings(private_key=str(key),known_hosts=str(key)))
            with patch('admin_transport.subprocess.run',side_effect=subprocess.TimeoutExpired('ssh',20)):
                with self.assertRaises(AdminError) as error:client.call('snapshot')
            self.assertIn('超时',str(error.exception))

class ModelTests(unittest.TestCase):
    def test_unknown_not_zero(self):
        self.assertEqual(byte_count(None),'—');self.assertEqual(rate(None),'—');self.assertEqual(time_text(None),'—')
        self.assertEqual(byte_count(0),'0 B')
        self.assertEqual(device_values({'id':ID,'revoked':False})[1],'未知')
    def test_device_counts_have_server_direction(self):
        row=device_values({'id':ID,'upload_bytes':1024,'download_bytes':2048,'online_sessions':1,'active_connections':0,'revoked':False})
        self.assertIn('1.00 KiB',row);self.assertIn('2.00 KiB',row)
        self.assertEqual(row[1],'在线')
        self.assertEqual(row[5:7],('1','0'))
    def test_idle_authenticated_tunnel_is_online_and_old_server_falls_back(self):
        self.assertEqual(device_values({'id':ID,'online_sessions':1,'active_connections':0,'revoked':False})[1],'在线')
        self.assertEqual(device_values({'id':ID,'online_sessions':0,'active_connections':0,'revoked':False})[1],'离线')
        self.assertEqual(device_values({'id':ID,'active_connections':1,'revoked':False})[1],'在线')
    def test_missing_server_snapshot_not_reported_healthy(self):
        summary=snapshot_summary({'server':{},'metering':{}})
        self.assertIn('未启用',summary)
        self.assertIn('CPU —',summary)
    def test_node_values_show_health_load_and_bits_per_second(self):
        values=node_values({'id':'osaka','label':'日本・大阪','healthy':True,'draining':False,'utilization':.25,
                            'upload_bps':10_000_000,'download_bps':2_000_000,'devices':2,'connections':5,
                            'throttled_devices':1,'probe_latency_ms':61,'last_report_at':100})
        self.assertIn('正常',values);self.assertIn('25.0%',values);self.assertIn('10.00 Mbps',values);self.assertIn('1',values)
    def test_node_snapshot_schema_is_bounded_and_has_no_endpoint_fields(self):
        sample={'sampled_at':100,'server':{},'metering':{},'licenses':[],'events':[],
                'nodes':[{'id':'tokyo','label':'日本・东京','healthy':True,'draining':False,'utilization':.1,
                          'upload_bps':1,'download_bps':2,'devices':0,'connections':0,'throttled_devices':0,
                          'probe_latency_ms':60,'probe_failures':0,'auth_latency_ms':10,'auth_errors':0,'last_report_at':100}]}
        self.assertIs(validate_snapshot(sample),sample)
        sample['nodes'][0]['host']='secret.example'
        with self.assertRaises(AdminError):validate_snapshot(sample)
    def test_node_snapshot_accepts_tokyo_cn2_without_endpoint_fields(self):
        sample={'sampled_at':100,'server':{},'metering':{},'licenses':[],'events':[],
                'nodes':[{'id':'tokyo_cn2','label':'日本・东京 CN2','healthy':True,'draining':False,'utilization':.1,
                          'upload_bps':1,'download_bps':2,'devices':0,'connections':0,'throttled_devices':0,
                          'probe_latency_ms':60,'probe_failures':0,'auth_latency_ms':10,'auth_errors':0,'last_report_at':100}]}
        self.assertIs(validate_snapshot(sample),sample)

if __name__=='__main__':unittest.main()
