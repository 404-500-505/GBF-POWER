import importlib.util
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]/'app'))
import client_model
from desktop_ui import App, create_root
from client_runtime import load


class RefreshTests(unittest.TestCase):
    def test_default_window_uses_compact_working_size(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=create_root()
            try:
                app=App(root,Path(tmp),preview=True);root.update()
                self.assertLessEqual(root.winfo_width(),500)
                self.assertLessEqual(root.winfo_height(),800)
                self.assertGreater(app.viewport.winfo_height(),300)
            finally:root.destroy()

    def test_high_dpi_does_not_double_scale_window_geometry(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=create_root()
            try:
                root.tk.call('tk','scaling',2.0)
                app=App(root,Path(tmp),preview=True);root.update()
                self.assertLessEqual(root.winfo_width(),650)
                self.assertLessEqual(root.winfo_height(),800)
                self.assertLessEqual(app.body.winfo_width(),app.viewport.winfo_width())
            finally:root.destroy()

    def test_short_screen_keeps_start_stop_visible(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = create_root()
            try:
                app = App(root, Path(tmp), preview=True)
                root.geometry('520x600');root.update()
                self.assertLessEqual(app.footer.winfo_y()+app.footer.winfo_height(),root.winfo_height())
                self.assertTrue(app.toggle.winfo_viewable())
                self.assertGreater(app.viewport.winfo_height(),200)
                self.assertEqual(app.notice.winfo_height(),app.notice.winfo_reqheight())
            finally:root.destroy()

    def test_old_route_probe_is_not_shown_after_switch(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=create_root()
            try:
                app=App(root,Path(tmp),preview=True)
                app.queue.put(('status',(app.manager.root,{'instance':'new',
                    'tunnel':{'connected':True,'server':'new.example'}},None)))
                app.queue.put(('ping',(app.manager.root,('old','old.example'),20)))
                app.drain()
                self.assertEqual(app.pings.view(__import__('time').time())['sent'],0)
                app.queue.put(('ping',(app.manager.root,('new','new.example'),60)))
                app.drain()
                self.assertEqual(app.pings.view(__import__('time').time())['latest'],60)
            finally:root.destroy()

    def test_follow_system_changes_theme_without_writing_preference(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=create_root()
            try:
                app=App(root,Path(tmp),preview=True)
                app.set_theme('system');app.last_theme_check=0
                with patch('desktop_ui.system_theme',return_value='dark'):
                    app.drain()
                self.assertEqual(app.theme_name,'dark')
                self.assertEqual(load(app.preferences)['theme'],'system')
            finally:root.destroy()

    def test_cache_counters_remain_distinct_and_unknown_is_not_zero(self):
        stats = client_model.display_stats({'cache': {
            'requests': 20, 'hits': 7, 'revalidated': 3, 'downloads': 8, 'saved_bytes': 1024}})
        self.assertEqual(stats.get('direct_hits'), 7)
        self.assertEqual(stats.get('validated_hits'), 3)
        self.assertEqual(stats.get('downloads'), 8)
        self.assertIsNone(client_model.display_stats({}).get('downloads'))

    def test_themes_have_explicit_fallback(self):
        spec = importlib.util.find_spec('client_theme')
        self.assertIsNotNone(spec, 'Theme module must exist')
        import client_theme as theme
        self.assertEqual(theme.resolve_theme('dark', 'light'), 'dark')
        self.assertEqual(theme.resolve_theme('system', 'dark'), 'dark')
        self.assertEqual(theme.resolve_theme('corrupt', 'light'), 'light')
        self.assertNotEqual(theme.PALETTES['light']['bg'], theme.PALETTES['dark']['bg'])

    def test_theme_switch_preserves_session_and_preferences(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = create_root()
            try:
                app = App(root, Path(tmp), preview=True)
                self.assertTrue(callable(getattr(app, 'set_theme', None)), 'Live theme switch is missing')
                manager = app.manager
                app.actual_line.configure(text='日本・东京 CN2')
                app.set_theme('dark')
                self.assertEqual(load(app.preferences)['theme'], 'dark')
                dark = root.cget('bg')
                app.set_theme('light')
                self.assertNotEqual(root.cget('bg'), dark)
                self.assertIs(app.manager, manager)
                self.assertEqual(app.actual_line.cget('text'), '日本・东京 CN2')
                self.assertIn('跟随系统', [app.theme_select.get()] + list(app.theme_select.cget('values')))
            finally:
                root.destroy()

    def test_busy_and_partial_connection_do_not_look_ready(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = create_root()
            try:
                app = App(root, Path(tmp), preview=True)
                self.assertTrue(hasattr(app, 'connection_state'), 'Connection state badge is missing')
                app.queue.put(('status', (app.manager.root, {'mode': 'ssh',
                    'tunnel': {'connected': True}, 'game_channel': {'enabled': True, 'connected': False}}, None)))
                app.drain()
                self.assertFalse(app.connected)
                self.assertIn('连接', app.connection_state.cget('text'))
                app.gate.begin('stopping')
                app.drain()
                self.assertIn('停止', app.connection_state.cget('text'))
            finally:
                root.destroy()

    def test_default_follow_system_and_restored_dark_theme(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = create_root()
            try:
                app = App(root, Path(tmp), preview=True)
                self.assertTrue(hasattr(app, 'theme_choice'), 'Theme choice is missing')
                self.assertEqual(app.theme_choice, 'system')
                app.set_theme('dark')
            finally:
                root.destroy()
            root = create_root()
            try:
                app = App(root, Path(tmp), preview=True)
                self.assertEqual(app.theme_choice, 'dark')
                self.assertEqual(app.theme_name, 'dark')
            finally:
                root.destroy()


if __name__ == '__main__':
    unittest.main()
