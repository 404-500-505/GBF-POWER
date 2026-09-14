import json
import socket
import sys
import tempfile
import unittest
from unittest.mock import patch
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'app'))
try:
    import client_runtime as r
except ModuleNotFoundError:
    r=None

def unused():
    with socket.socket() as s:
        s.bind(('127.0.0.1',0));return s.getsockname()[1]

class RuntimeTests(unittest.TestCase):
    def setUp(self):
        self.assertIsNotNone(r,'客户端生命周期模块尚未实现')
        self.folder=tempfile.TemporaryDirectory()
        self.root=Path(self.folder.name)
        (self.root/'runtime').mkdir()
        self.port=unused()
        config={'port':self.port,'connect_timeout_seconds':2,'idle_timeout_seconds':5,'max_connections':8}
        (self.root/'config.json').write_text(json.dumps(config),encoding='utf-8')
        (self.root/'rules.json').write_text(json.dumps({'domain_suffixes':['granbluefantasy.jp'],'exact_hosts':[],'socks5_hosts':[]}),encoding='utf-8')
        self.manager=r.Manager(self.root, allow_direct=True)
    def tearDown(self):
        if hasattr(self,'manager'):self.manager.dispose()
        if hasattr(self,'folder'):self.folder.cleanup()
    def test_repeat_start_stop_releases_ports(self):
        for _ in range(2):
            self.manager.start()
            self.assertTrue(self.manager.owned_status())
            pid=self.manager.process.pid
            self.manager.start()
            self.assertEqual(self.manager.process.pid,pid)
            self.manager.stop()
            self.assertTrue(r.ports_free([self.port]))
    def test_foreign_port_never_killed(self):
        with socket.socket() as s:
            s.bind(('127.0.0.1',self.port));s.listen()
            with self.assertRaisesRegex(RuntimeError,'占用'):self.manager.start()
            self.assertIsNone(self.manager.process)
            self.assertFalse(r.ports_free([self.port]))
    def test_wrong_instance_is_not_owned(self):
        self.assertFalse(r.same_instance({'app':'gbf-local-proxy','instance':'x'}, {'instance':'y','port':self.port}, self.port))
    def test_default_profile_has_no_private_material(self):
        cfg=r.default_config()
        self.assertFalse(cfg['cache']['enabled'])
        self.assertTrue(cfg['game_channel']['enabled'])
        self.assertEqual(cfg['routing_profile_version'],2)
        self.assertNotIn('BEGIN',json.dumps(cfg))
        self.assertIsNone(cfg['ssh'])

    def test_acgp_cache_picker_accepts_common_directory_levels(self):
        root=self.root/'old-acgp/cache/gbf'
        (root/'https/assets').mkdir(parents=True)
        for selected in (root.parent.parent,root.parent,root,root/'https',root/'https/assets'):
            with self.subTest(selected=selected):
                self.assertEqual(r.normalize_acgp_cache_directory(selected),root.resolve())

    def test_acgp_cache_picker_rejects_unrelated_directory(self):
        unrelated=self.root/'downloads';unrelated.mkdir()
        with self.assertRaisesRegex(ValueError,'ACGP'):
            r.normalize_acgp_cache_directory(unrelated)
    def test_initialize_migrates_legacy_shared_profile_to_battle_priority(self):
        legacy={'port':8123,'game_channel':{'enabled':False,'socks_port':18125}}
        r.save(self.root/'config.json',legacy)
        r.initialize(self.root,self.root)
        current=r.load(self.root/'config.json')
        self.assertTrue(current['game_channel']['enabled'])
        self.assertEqual(current['game_channel']['socks_port'],18125)
        self.assertEqual(current['routing_profile_version'],2)
        current['game_channel']['enabled']=False
        r.save(self.root/'config.json',current)
        r.initialize(self.root,self.root)
        self.assertFalse(r.load(self.root/'config.json')['game_channel']['enabled'])
    def test_acceleration_ready_requires_enabled_battle_channel(self):
        shared={'mode':'ssh','tunnel':{'connected':True},
                'game_channel':{'enabled':False,'connected':False}}
        battle={'mode':'ssh','tunnel':{'connected':True},
                'game_channel':{'enabled':True,'connected':True}}
        waiting={'mode':'ssh','tunnel':{'connected':True},
                 'game_channel':{'enabled':True,'connected':False}}
        self.assertTrue(r.acceleration_ready(shared))
        self.assertTrue(r.acceleration_ready(battle))
        self.assertFalse(r.acceleration_ready(waiting))
    def test_external_port_does_not_prevent_exit(self):
        with socket.socket() as s:
            s.bind(('127.0.0.1',self.port));s.listen()
            self.manager.stop()
            self.assertFalse(r.ports_free([self.port]))

    def test_managed_start_adopts_verified_metering_node_before_launch(self):
        import activation_client as a
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        from cryptography.hazmat.primitives import serialization
        c=r.load(self.root/'config.json');c['activation']={'managed':True,'device_id':'a'*24};r.save(self.root/'config.json',c)
        public=Ed25519PrivateKey.generate().public_key().public_bytes(serialization.Encoding.OpenSSH,serialization.PublicFormat.OpenSSH).decode()
        response={'active':True,'device_id':'a'*24,'device_count':1,'device_limit':2,
                  'node':{'host':'example.com','port':2222,'username':'gbfdevice','host_key':public}}
        with patch.object(a,'check_device',return_value=response),patch.object(r,'ports_free',return_value=False):
            with self.assertRaisesRegex(RuntimeError,'占用'):self.manager.start()
        self.assertEqual(self.manager.config().get('ssh',{}).get('port'),2222)
        self.assertTrue((self.root/'runtime/device/known_hosts').read_text().startswith('[example.com]:2222 '))
        self.assertIsNone(self.manager.process)

    def test_failed_node_save_cannot_launch_worker(self):
        import activation_client as a
        c=r.load(self.root/'config.json');c['activation']={'managed':True,'device_id':'a'*24};r.save(self.root/'config.json',c)
        with patch.object(a,'check_device',return_value={'active':True}),patch.object(a,'apply_registration',side_effect=OSError('disk unavailable')):
            with self.assertRaisesRegex(OSError,'disk unavailable'):self.manager.start()
        self.assertIsNone(self.manager.process)

if __name__=='__main__':unittest.main()
