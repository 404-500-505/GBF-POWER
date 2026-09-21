"""Real Tk interaction tests; no live proxy or user profile is used."""
from pathlib import Path
import importlib.util
import ctypes
import sys
import tempfile
import time
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]/'app'))
from desktop_ui import App, create_root
import tkinter as tk


class ControlsTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = create_root()
        self.app = App(self.root, Path(self.tmp.name), preview=True)
        self.root.update()

    def tearDown(self):
        self.root.destroy()
        self.tmp.cleanup()

    def controls(self):
        self.assertIsNotNone(importlib.util.find_spec('client_controls'),
                             'Client needs custom drawn controls, not recolored native widgets')
        import client_controls
        return client_controls

    def pump(self, seconds=.25):
        until = time.monotonic()+seconds
        while time.monotonic() < until:
            self.root.update()
            time.sleep(.01)

    def test_main_controls_are_custom_drawn(self):
        c = self.controls()
        self.assertIsInstance(self.app.toggle, c.GlassButton)
        self.assertIsInstance(self.app.line_select, c.GlassSelect)
        self.assertIsInstance(self.app.theme_select, c.GlassSelect)
        self.assertIsInstance(self.app.toggle, tk.Canvas)
        def walk(widget):
            for child in widget.winfo_children():
                yield child
                yield from walk(child)
        classes = {w.winfo_class() for w in walk(self.root)}
        self.assertNotIn('Button', classes)
        self.assertNotIn('Checkbutton', classes)
        self.assertNotIn('TCombobox', classes)

    def test_click_release_outside_and_disabled_button(self):
        c = self.controls(); calls=[]
        b = c.GlassButton(self.root, text='Test', command=lambda: calls.append(1), palette=self.app.colors)
        b.pack(); self.root.update()
        b.event_generate('<ButtonPress-1>', x=10, y=10)
        b.event_generate('<ButtonRelease-1>', x=-1, y=10)
        self.assertEqual(calls, [])
        b.event_generate('<ButtonPress-1>', x=10, y=10)
        b.event_generate('<ButtonRelease-1>', x=10, y=10)
        self.assertEqual(calls, [1])
        b.configure(state='disabled'); b.invoke()
        self.assertEqual(calls, [1])

    def test_animation_finishes_and_destroy_cancels_callback(self):
        self.controls()
        b=self.app.confirm
        b.event_generate('<Enter>'); self.root.update()
        self.assertIsNotNone(b.animation_id)
        self.pump()
        self.assertIsNone(b.animation_id)
        b.event_generate('<Leave>'); self.root.update()
        pending=b.animation_id
        self.assertIsNotNone(pending)
        b.destroy()
        self.assertNotIn(pending, self.root.tk.call('after', 'info'))

    def test_checkbox_switch_and_radio_keep_variable_semantics(self):
        c=self.controls(); calls=[]
        value=tk.BooleanVar(self.root, False)
        for kind in ('check','switch'):
            b=c.GlassChoice(self.root,text='Option',variable=value,kind=kind,
                            command=lambda: calls.append(1),palette=self.app.colors)
            value.set(False); b.invoke(); self.assertTrue(value.get())
            b.invoke(); self.assertFalse(value.get())
            b.configure(state='disabled'); b.invoke(); self.assertFalse(value.get())
            b.destroy()
        selected=tk.StringVar(self.root,'a')
        a=c.GlassChoice(self.root,text='A',variable=selected,value='a',kind='radio',palette=self.app.colors)
        b=c.GlassChoice(self.root,text='B',variable=selected,value='b',kind='radio',palette=self.app.colors)
        b.invoke(); self.assertEqual(selected.get(),'b')
        b.invoke(); self.assertEqual(selected.get(),'b')
        a.invoke(); self.assertEqual(selected.get(),'a')
        self.assertEqual(len(calls),4)

    def test_select_popup_keyboard_commit_cancel_and_outside_click(self):
        self.controls(); s=self.app.theme_select
        s.open_popup(); self.root.update()
        self.assertIsNotNone(s.popup)
        self.assertEqual(s.popup.canvas.winfo_class(),'Canvas')
        s.popup.move(1); s.popup.commit(); self.root.update()
        self.assertEqual(self.app.theme_choice, 'light')
        self.assertIsNone(s.popup)
        s.open_popup(); self.root.update()
        s.popup.move(1); s.popup.canvas.event_generate('<Escape>'); self.root.update()
        self.assertEqual(self.app.theme_choice,'light')
        self.assertIsNone(s.popup)
        s.open_popup(); self.root.update()
        s.popup.canvas.event_generate('<ButtonPress-1>',x=-20,y=-20)
        self.root.update(); self.assertIsNone(s.popup)

    def test_popup_theme_change_and_disable_dismiss_without_changing_value(self):
        self.controls(); s=self.app.line_select
        original=s.get(); manager=self.app.manager
        s.open_popup(); self.root.update()
        self.app.set_theme('dark'); self.root.update()
        self.assertIsNone(s.popup)
        self.assertEqual(s.palette,self.app.colors)
        s.open_popup(); self.root.update()
        s.configure(state='disabled'); self.root.update()
        self.assertIsNone(s.popup)
        s.open_popup(); self.assertIsNone(s.popup)
        self.assertEqual(s.get(),original)
        self.assertIs(self.app.manager,manager)

    def test_variable_traces_are_removed_on_destroy(self):
        c=self.controls(); value=tk.BooleanVar(self.root,False)
        b=c.GlassChoice(self.root,text='Test',variable=value,palette=self.app.colors)
        self.assertTrue(value.trace_info()); b.destroy()
        self.assertEqual(value.trace_info(),[])

    def test_unchanged_status_does_not_redraw_idle_button(self):
        self.controls(); b=self.app.toggle
        image=b._surface_image
        b.configure(text=b.cget('text'),state=b.cget('state'))
        self.assertIs(b._surface_image,image)

    def test_menu_uses_same_custom_popup_and_dispatches_once(self):
        c=self.controls(); calls=[]
        menu=self.app.build_menu()
        self.assertIsInstance(menu,c.GlassMenu)
        menu.add_command(label='Test action',command=lambda: calls.append(1))
        menu.tk_popup(50,50); self.root.update()
        self.assertIsNotNone(menu.popup)
        menu.popup.index=len(menu.values)-1
        menu.popup.commit()
        self.assertEqual(calls,[1])
        self.assertIsNone(menu.popup)

    def test_stacking_configure_does_not_close_popup(self):
        self.controls(); s=self.app.line_select
        s.open_popup(); self.root.update()
        self.root.event_generate('<Configure>'); self.root.update()
        self.assertIsNotNone(s.popup)

    def test_outside_click_routed_to_grab_window_closes_popup(self):
        self.controls(); s=self.app.line_select
        s.open_popup(); self.root.update()
        s.popup.window.event_generate('<ButtonPress-1>',x=-20,y=-20)
        self.root.update()
        self.assertIsNone(s.popup)

    def test_unchanged_variable_values_do_not_schedule_or_redraw(self):
        c=self.controls(); value=tk.BooleanVar(self.root,False)
        choice=c.GlassChoice(self.root,text='Test',variable=value,palette=self.app.colors)
        value.set(False)
        self.assertIsNone(choice.animation_id)
        select=self.app.line_select; image=select._surface_image
        select.variable.set(select.get())
        self.assertIs(select._surface_image,image)

    def test_theme_change_snaps_to_latest_selected_value(self):
        c=self.controls(); value=tk.BooleanVar(self.root,False)
        choice=c.GlassChoice(self.root,text='Test',variable=value,palette=self.app.colors)
        choice.invoke()
        choice.set_palette(self.app.colors)
        self.assertEqual(choice.selection,1.)
        self.assertIsNone(choice.animation_id)

    def test_popup_position_respects_non_primary_monitor_work_area(self):
        c=self.controls()
        self.assertTrue(hasattr(c,'popup_position'))
        self.assertEqual(c.popup_position((-1800,100,220,40),(260,180),(-1920,0,0,1040)),(-1800,144))
        self.assertEqual(c.popup_position((2300,1000,220,40),(260,180),(1920,0,3840,1040)),(2300,816))

    def test_window_close_protocol_cleans_popup_and_allows_reopen(self):
        self.controls(); s=self.app.line_select
        s.open_popup(); self.root.update()
        self.root.tk.eval(s.popup.window.protocol('WM_DELETE_WINDOW'))
        self.root.update()
        self.assertIsNone(s.popup)
        s.open_popup(); self.root.update()
        self.assertIsNotNone(s.popup)

    @unittest.skipUnless(sys.platform=='win32','Windows z-order regression')
    def test_popup_is_above_always_on_top_owner(self):
        self.controls(); s=self.app.line_select
        self.root.attributes('-topmost',True)
        s.open_popup(); self.root.update()
        user=ctypes.windll.user32
        root_hwnd=user.GetParent(self.root.winfo_id())
        popup_hwnd=user.GetParent(s.popup.window.winfo_id())
        order=[]; hwnd=user.GetTopWindow(0)
        for _ in range(256):
            if not hwnd: break
            if hwnd in (root_hwnd,popup_hwnd): order.append(hwnd)
            hwnd=user.GetWindow(hwnd,2)
        self.assertEqual(order[:2],[popup_hwnd,root_hwnd])

    def test_destroyed_popup_cleans_owner_reference(self):
        self.controls(); s=self.app.line_select
        s.open_popup(); self.root.update()
        s.popup.window.destroy(); self.root.update()
        self.assertIsNone(s.popup)
        self.assertIsNone(self.root.grab_current())


if __name__=='__main__':
    unittest.main()
