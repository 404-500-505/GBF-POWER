import copy
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'app'))
import client_runtime as r
import cache_certificate

class FakeManager:
    def __init__(self,root):
        self.root=root;self.active=True;self.starts=0;self.stops=0;self.fail_start=False
        (root/'runtime/cache-tls').mkdir(parents=True)
        (root/'runtime/cache-tls/ca.pem').write_text('OLD')
        r.save(root/'config.json',{'cache':{'enabled':False}})
    def owned_status(self):return {'running':True} if self.active else None
    def stop(self):self.active=False;self.stops+=1
    def start(self):
        self.starts+=1
        if self.fail_start and self.starts==1:raise RuntimeError('start failure')
        self.active=True
    def config(self):return r.load(self.root/'config.json')

class CertificateTransactions(unittest.TestCase):
    def test_rename_denied_restores_running_without_moving_original(self):
        with tempfile.TemporaryDirectory() as tmp:
            manager=FakeManager(Path(tmp))
            with patch.object(Path,'rename',side_effect=PermissionError('busy')) as rename:
                with self.assertRaises(PermissionError):r.renew_certificate(manager)
            self.assertTrue(manager.active)
            self.assertEqual(rename.call_count,1)
            self.assertEqual((manager.root/'runtime/cache-tls/ca.pem').read_text(),'OLD')
    def test_cache_failure_restores_running_state(self):
        with tempfile.TemporaryDirectory() as tmp:
            manager=FakeManager(Path(tmp));manager.fail_start=True
            info={'expires':'2099-01-01T00:00:00+00:00','thumbprint':'NEW'}
            with patch.object(cache_certificate,'prepare_certificate',return_value=info),patch.object(r,'trusted',return_value=True):
                with self.assertRaises(RuntimeError):r.set_cache(manager,True)
            self.assertTrue(manager.active,'失败后应恢复原先运行状态')
            self.assertFalse(manager.config()['cache']['enabled'])
    def test_renew_failure_stops_new_engine_before_restore(self):
        with tempfile.TemporaryDirectory() as tmp:
            manager=FakeManager(Path(tmp));trusted={'OLD'};events=[]
            original_stop=manager.stop
            def stop():events.append('stop');original_stop()
            manager.stop=stop
            def prepare(folder):
                folder.mkdir();(folder/'ca.pem').write_text('NEW')
                return {'thumbprint':'NEW'}
            def command(action,value):
                if action=='remove' and value=='OLD':raise RuntimeError('remove denied')
                if action=='remove':events.append('remove-new');trusted.discard(value)
                else:trusted.add(Path(value).read_text())
            with patch.object(cache_certificate,'prepare_certificate',side_effect=prepare),patch.object(r,'cert_status',return_value={'trusted':True,'thumbprint':'OLD'}),patch.object(r,'trusted',side_effect=lambda info:info['thumbprint'] in trusted),patch.object(r,'cert_command',side_effect=command):
                with self.assertRaises(RuntimeError):r.renew_certificate(manager)
            self.assertGreaterEqual(manager.stops,2)
            self.assertEqual((manager.root/'runtime/cache-tls/ca.pem').read_text(),'OLD')
            self.assertTrue(manager.active)
            self.assertEqual(trusted,{'OLD'})
            self.assertEqual(events[:2],['stop','stop'])
