import base64
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'app'))
import activation_client as a
import client_runtime as runtime

class ActivationTests(unittest.TestCase):
    def test_same_installation_reuses_private_key(self):
        with tempfile.TemporaryDirectory() as tmp:
            first=a.device_key(Path(tmp),create=True)
            second=a.device_key(Path(tmp),create=True)
            self.assertEqual(first.private_bytes_raw(),second.private_bytes_raw())
    def test_configuration_write_failure_restores_existing_host_key_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);runtime.initialize(root,Path(__file__).resolve().parents[1]/'proxy_core')
            folder=root/'runtime/device';folder.mkdir()
            (folder/'known_hosts').write_text('previous host key')
            previous=(root/'config.json').read_bytes()
            key=Ed25519PrivateKey.generate()
            public=key.public_key().public_bytes(serialization.Encoding.OpenSSH,serialization.PublicFormat.OpenSSH).decode()
            response={'active':True,'device_id':'abc','device_count':1,'device_limit':2,'node':{'host':'localhost','port':22,'username':'gbfdevice','host_key':public}}
            with patch.object(a,'save',side_effect=OSError('read-only')):
                with self.assertRaises(OSError):a.apply_registration(root,response)
            self.assertEqual((root/'config.json').read_bytes(),previous)
            self.assertEqual((folder/'known_hosts').read_text(),'previous host key')
    def test_signature_proves_device_key_and_binds_code(self):
        key=Ed25519PrivateKey.generate()
        request=a.signed_request(key,'activate','GBF-'+'A'*32)
        message='\n'.join(['GBF-ACTIVATE-V1',request['code'],request['public_key'],str(request['timestamp']),request['nonce']])
        key.public_key().verify(base64.b64decode(request['signature']),message.encode())
        self.assertNotIn('private',json.dumps(request))

    def test_v2_signature_binds_line_preference_and_quality(self):
        key=Ed25519PrivateKey.generate()
        quality={'tokyo':{'p95_ms':95,'consecutive_timeouts':0},'osaka':{'p95_ms':420,'consecutive_timeouts':2}}
        request=a.signed_request_v2(key,'status',None,'tokyo',quality)
        fields=['GBF-STATUS-V2','',request['public_key'],str(request['timestamp']),request['nonce'],'tokyo','95','0','420','2']
        key.public_key().verify(base64.b64decode(request['signature']),'\n'.join(fields).encode())
        tampered=dict(request);tampered['preference']='osaka'
        with self.assertRaises(Exception):
            key.public_key().verify(base64.b64decode(tampered['signature']),'\n'.join(fields[:5]+['osaka']+fields[6:]).encode())

    def test_v3_signature_binds_all_three_node_qualities(self):
        key=Ed25519PrivateKey.generate()
        quality={'tokyo':{'p95_ms':95,'consecutive_timeouts':0},
                 'tokyo_cn2':{'p95_ms':66,'consecutive_timeouts':0},
                 'osaka':{'p95_ms':420,'consecutive_timeouts':2}}
        request=a.signed_request_v3(key,'status',None,'tokyo_cn2',quality)
        fields=['GBF-STATUS-V3','',request['public_key'],str(request['timestamp']),request['nonce'],'tokyo_cn2','95','0','66','0','420','2']
        key.public_key().verify(base64.b64decode(request['signature']),'\n'.join(fields).encode())

    def test_v3_registration_persists_three_nodes_and_cn2_choice(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);runtime.initialize(root,Path(__file__).resolve().parents[1]/'proxy_core')
            pubs=[Ed25519PrivateKey.generate().public_key().public_bytes(serialization.Encoding.OpenSSH,serialization.PublicFormat.OpenSSH).decode() for _ in range(3)]
            nodes={
                'tokyo':{'host':'tokyo.example','port':2222,'username':'gbfdevice','host_key':pubs[0]},
                'tokyo_cn2':{'host':'cn2.example','port':2222,'username':'gbfdevice','host_key':pubs[1]},
                'osaka':{'host':'osaka.example','port':2222,'username':'gbfdevice','host_key':pubs[2]},
            }
            response={'active':True,'device_id':'a'*24,'device_count':1,'device_limit':2,
                      'node':nodes['tokyo_cn2'],'nodes':nodes,
                      'assigned_line':{'id':'tokyo_cn2','label':'日本・东京 CN2'},
                      'available_lines':[{'id':'auto','label':'自动选择'},{'id':'tokyo','label':'日本・东京'},
                                         {'id':'tokyo_cn2','label':'日本・东京 CN2'},{'id':'osaka','label':'日本・大阪'}]}
            a.apply_registration(root,response,preference='tokyo_cn2')
            config=runtime.load(root/'config.json')
            self.assertEqual(config['activation']['line_preference'],'tokyo_cn2')
            self.assertEqual(set(config['activation']['nodes']),{'tokyo','tokyo_cn2','osaka'})
            self.assertIn('[cn2.example]:2222 '+pubs[1],(root/'runtime/device/known_hosts').read_text())
    def test_pinned_transport_does_not_send_before_verification(self):
        class Socket:
            def getpeercert(self,binary_form=False):return b'wrong certificate'
        class Connection:
            sock=Socket();sent=False
            def connect(self):pass
            def request(self,*args,**kwargs):self.sent=True
            def close(self):pass
        connection=Connection()
        bootstrap={'host':'localhost','port':18444,'certificate_sha256':'0'*64}
        with patch.object(a.http.client,'HTTPSConnection',return_value=connection):
            with self.assertRaises(a.ActivationError):a.post(bootstrap,'/v1/activate',{'code':'SECRET'})
        self.assertFalse(connection.sent)
    def test_third_device_error_has_no_technical_secret(self):
        error=a.ActivationError('device_limit')
        self.assertIn('2',str(error));self.assertNotIn('SSH',str(error))
    def test_apply_requires_valid_node_and_preserves_config_on_failure(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);runtime.initialize(root,Path(__file__).resolve().parents[1]/'proxy_core')
            previous=(root/'config.json').read_bytes()
            with self.assertRaises(a.ActivationError):a.apply_registration(root,{'active':True,'node':{'host':'injected\n'}})
            self.assertEqual((root/'config.json').read_bytes(),previous)
    def test_apply_registration_keeps_private_key_local_and_no_code(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);runtime.initialize(root,Path(__file__).resolve().parents[1]/'proxy_core')
            key=Ed25519PrivateKey.generate()
            pub=key.public_key().public_bytes(serialization.Encoding.OpenSSH,serialization.PublicFormat.OpenSSH).decode()
            response={'active':True,'device_id':'abc','device_count':1,'device_limit':2,'node':{'host':'127.0.0.1','port':22,'username':'gbfdevice','host_key':pub}}
            a.apply_registration(root,response)
            config=runtime.load(root/'config.json')
            self.assertEqual(config['ssh']['username'],'gbfdevice')
            self.assertEqual(config['ssh']['private_key'],'runtime/device/id_ed25519')
            self.assertTrue(config['activation']['managed'])
            self.assertNotIn('code',json.dumps(config))
            self.assertIn(pub,(root/'runtime/device/known_hosts').read_text())

    def test_v2_registration_persists_safe_line_choice_and_all_pinned_nodes(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);runtime.initialize(root,Path(__file__).resolve().parents[1]/'proxy_core')
            pub1=Ed25519PrivateKey.generate().public_key().public_bytes(serialization.Encoding.OpenSSH,serialization.PublicFormat.OpenSSH).decode()
            pub2=Ed25519PrivateKey.generate().public_key().public_bytes(serialization.Encoding.OpenSSH,serialization.PublicFormat.OpenSSH).decode()
            response={'active':True,'device_id':'a'*24,'device_count':1,'device_limit':2,
                'node':{'host':'tokyo.example','port':2222,'username':'gbfdevice','host_key':pub1},
                'nodes':{
                    'tokyo':{'host':'tokyo.example','port':2222,'username':'gbfdevice','host_key':pub1},
                    'osaka':{'host':'osaka.example','port':2222,'username':'gbfdevice','host_key':pub2}},
                'assigned_line':{'id':'tokyo','label':'日本・东京'},
                'available_lines':[{'id':'auto','label':'自动选择'},{'id':'tokyo','label':'日本・东京'},{'id':'osaka','label':'日本・大阪'}]}
            a.apply_registration(root,response,preference='auto')
            config=runtime.load(root/'config.json')
            self.assertEqual(config['activation']['line_preference'],'auto')
            self.assertEqual(config['activation']['assigned_line'],{'id':'tokyo','label':'日本・东京'})
            self.assertEqual(set(config['activation']['nodes']),{'tokyo','osaka'})
            hosts=(root/'runtime/device/known_hosts').read_text()
            self.assertIn('[tokyo.example]:2222 '+pub1,hosts)
            self.assertIn('[osaka.example]:2222 '+pub2,hosts)
            self.assertNotIn('tokyo.example',config['activation']['assigned_line']['label'])

    def test_line_preference_rejects_unknown_values(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);runtime.initialize(root,Path(__file__).resolve().parents[1]/'proxy_core')
            with self.assertRaises(ValueError):a.set_line_preference(root,'fastest-secret-node')

    def test_line_preference_is_preserved_before_first_activation(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);runtime.initialize(root,Path(__file__).resolve().parents[1]/'proxy_core')
            a.set_line_preference(root,'osaka')
            self.assertEqual(a.line_preference(root),'osaka')

    def test_node_quality_update_is_bounded_and_does_not_change_assignment(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);runtime.initialize(root,Path(__file__).resolve().parents[1]/'proxy_core')
            config=runtime.load(root/'config.json');config['activation']={'managed':True,'device_id':'a'*24,'line_preference':'auto','assigned_line':{'id':'tokyo','label':'日本・东京'},'nodes':{'tokyo':{},'osaka':{}}};runtime.save(root/'config.json',config)
            a.set_node_quality(root,'osaka',{'p95_ms':801,'consecutive_timeouts':2})
            updated=runtime.load(root/'config.json')['activation']
            self.assertEqual(updated['node_quality']['osaka'],{'p95_ms':801,'consecutive_timeouts':2})
            self.assertEqual(updated['assigned_line']['id'],'tokyo')
            with self.assertRaises(ValueError):a.set_node_quality(root,'osaka',{'p95_ms':-1,'consecutive_timeouts':0})

if __name__=='__main__':unittest.main()
