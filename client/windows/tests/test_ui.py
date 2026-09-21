import sys
from pathlib import Path
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'app'))
try:
    from desktop_ui import App,actual_line_label,create_root
except ModuleNotFoundError:
    App=None

class UiTests(unittest.TestCase):
    def test_running_route_uses_tunnel_server_instead_of_stale_assignment(self):
        enrolled={
            'assigned_line':{'id':'osaka','label':'日本・大阪'},
            'nodes':{
                'tokyo':{'host':'tokyo.example'},
                'osaka':{'host':'osaka.example'},
            },
        }
        status={
            'tunnel':{'connected':True,'server':'tokyo.example'},
            'game_channel':{'enabled':True,'connected':True,'server':'tokyo.example'},
        }
        self.assertEqual(actual_line_label(enrolled,status),'日本・东京')

    def test_running_route_reports_switching_when_channels_disagree(self):
        enrolled={'nodes':{
            'tokyo':{'host':'tokyo.example'},
            'osaka':{'host':'osaka.example'},
        }}
        status={
            'tunnel':{'connected':True,'server':'tokyo.example'},
            'game_channel':{'enabled':True,'connected':True,'server':'osaka.example'},
        }
        self.assertEqual(actual_line_label(enrolled,status),'线路切换中')

    def test_unknown_running_route_does_not_show_stale_assignment(self):
        enrolled={
            'assigned_line':{'id':'osaka','label':'日本・大阪'},
            'nodes':{'osaka':{'host':'osaka.example'}},
        }
        status={'tunnel':{'connected':True,'server':'unknown.example'}}
        self.assertEqual(actual_line_label(enrolled,status),'线路未知')

    def test_status_poll_synchronizes_preference_and_actual_route(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=create_root()
            try:
                app=App(root,Path(tmp),preview=True)
                app.line_value.set('优先大阪')
                app.actual_line.configure(text='日本・大阪')
                enrolled={
                    'assigned_line':{'id':'osaka','label':'日本・大阪'},
                    'nodes':{
                        'tokyo':{'host':'tokyo.example'},
                        'osaka':{'host':'osaka.example'},
                    },
                }
                status={
                    'tunnel':{'connected':True,'server':'tokyo.example'},
                    'game_channel':{'enabled':True,'connected':True,'server':'tokyo.example'},
                }
                app.queue.put(('status',(app.manager.root,status,None)))
                with patch('desktop_ui.registration',return_value=enrolled),patch('desktop_ui.line_preference',return_value='tokyo'):
                    app.drain()
                self.assertEqual(app.line_value.get(),'优先东京')
                self.assertEqual(app.actual_line.cget('text'),'日本・东京')
            finally:root.destroy()

    def test_authorization_deadline_stops_owned_engine_when_status_unavailable(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=create_root()
            try:
                app=App(root,Path(tmp),preview=True);app.auth_valid_until=0
                app.manager.process=SimpleNamespace(poll=lambda:None)
                with patch('desktop_ui.registration',return_value={'managed':True}),patch.object(app,'run') as run:
                    app.drain();self.assertEqual(run.call_args.args[0],'stopping')
            finally:root.destroy()
    def test_status_dialog_is_deferred_and_does_not_block_queue_drain(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=create_root()
            try:
                app=App(root,Path(tmp),preview=True)
                app.queue.put(('info','测试信息'))
                with patch('desktop_ui.messagebox.showinfo') as show:
                    app.drain();show.assert_not_called()
                    root.update();show.assert_called_once()
            finally:root.destroy()
    def test_authorization_deadline_does_not_wait_for_network_poll(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=create_root()
            try:
                app=App(root,Path(tmp),preview=True);app.online=True;app.auth_valid_until=0
                with patch('desktop_ui.registration',return_value={'managed':True}),patch.object(app,'run') as run:
                    app.drain()
                    self.assertEqual(run.call_args.args[0],'stopping')
            finally:root.destroy()
    def test_revocation_is_not_lost_while_operation_busy(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=create_root()
            try:
                app=App(root,Path(tmp),preview=True)
                app.gate.begin('starting')
                app.queue.put(('authorization_denied',(app.manager.root,'已撤销')))
                with patch.object(app,'run') as run:
                    app.drain();run.assert_not_called()
                    self.assertEqual(app.revocation_pending,'已撤销')
                    app.gate.finish('running');app.drain()
                    self.assertEqual(run.call_args.args[0],'stopping')
            finally:root.destroy()
    def test_public_menu_has_activation_not_ssh_setup(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=create_root()
            try:
                app=App(root,Path(tmp),preview=True)
                menu=app.build_menu()
                entries=[menu.entrycget(i,'label') for i in range(menu.index('end')+1) if menu.type(i)!='separator']
                self.assertIn('激活设备…',entries)
                self.assertFalse(any('密钥' in text or '公钥' in text or '配置' in text for text in entries))
            finally:root.destroy()
    def test_main_window_has_no_explicit_ip(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=create_root()
            try:
                App(root,Path(tmp),preview=True)
                def texts(widget):
                    result=[str(widget.cget('text'))] if 'text' in widget.keys() else []
                    for child in widget.winfo_children():result.extend(texts(child))
                    return result
                self.assertNotRegex('\n'.join(texts(root)),r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
            finally:root.destroy()

    def test_line_selector_matches_public_choices_and_hides_transport_details(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=create_root()
            try:
                app=App(root,Path(tmp),preview=True)
                self.assertEqual(tuple(app.line_select.cget('values')),('自动选择','优先东京','优先东京 CN2','优先大阪'))
                self.assertEqual(str(app.line_select.cget('state')),'readonly')
                self.assertNotRegex(app.actual_line.cget('text'),r'\b(?:\d{1,3}\.){3}\d{1,3}\b|SSH|:\d+')
            finally:root.destroy()

    def test_actual_route_identifies_tokyo_cn2_without_exposing_host(self):
        enrolled={'nodes':{'tokyo_cn2':{'host':'203.0.113.20'}}}
        status={'tunnel':{'connected':True,'server':'203.0.113.20'}}
        self.assertEqual(actual_line_label(enrolled,status),'日本・东京 CN2')
    def test_background_authorization_does_not_relabel_running_route(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=create_root()
            try:
                app=App(root,Path(tmp),preview=True)
                app.actual_line.configure(text='日本・东京')
                app.queue.put(('authorized',(app.manager.root,{
                    'device_count':1,
                    'assigned_line':{'id':'osaka','label':'日本・大阪'},
                },0.0)))
                app.drain()
                self.assertEqual(app.actual_line.cget('text'),'日本・东京')
            finally:root.destroy()
    def test_fixed_glass_layout_and_no_fake_features(self):
        self.assertIsNotNone(App,'原生窗口尚未实现')
        import tkinter as tk
        with tempfile.TemporaryDirectory() as tmp:
            root=create_root()
            try:
                app=App(root,Path(tmp),preview=True)
                root.update()
                self.assertEqual(root.resizable(),(0,0))
                self.assertEqual(root.cget('bg'),app.colors['bg'])
                self.assertIn('停止',app.toggle.cget('text'))
                self.assertEqual(app.network.get(),False)
                self.assertEqual(app.cache.get(),False)
                self.assertFalse(app.gate.busy)
                self.assertLessEqual(app.notice.winfo_y()+app.notice.winfo_height(),app.footer.winfo_height(),'底部说明不应被裁切')
                self.assertEqual(app.notice.winfo_height(),app.notice.winfo_reqheight(),'底部说明必须完整显示')
            finally:root.destroy()

if __name__=='__main__':unittest.main()
