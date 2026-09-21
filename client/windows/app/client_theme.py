"""Opaque, readable frosted surfaces: no desktop capture or whole-window alpha."""
import ctypes
import sys
import tkinter as tk

PALETTES = {
    'light': dict(bg='#e9eef5', card='#f8fafc', rim='#ffffff', shadow='#dce3ed',
                  text='#19283c', muted='#53647a', accent='#1764db', hover='#e2ebfa',
                  button='#e9eef6', line='#dde5ef', success='#167359', warning='#936018',
                  glow='#dcebf9', white='#ffffff'),
    'dark': dict(bg='#111924', card='#202d3e', rim='#3d4f65', shadow='#0c121d',
                 text='#edf3fb', muted='#adbed3', accent='#77b7ff', hover='#344b68',
                 button='#2a3a50', line='#3c4d63', success='#79d9b3', warning='#f5c478',
                 glow='#294967', white='#ffffff'),
}
THEME_LABELS = {'system': '跟随系统', 'light': '浅色', 'dark': '深色'}


def system_theme():
    try:
        import winreg
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER,
                r'Software\Microsoft\Windows\CurrentVersion\Themes\Personalize') as key:
            return 'light' if winreg.QueryValueEx(key, 'AppsUseLightTheme')[0] else 'dark'
    except (OSError, ImportError):
        return 'light'


def resolve_theme(choice, system):
    return choice if choice in PALETTES else system if system in PALETTES else 'light'


def titlebar_theme(root, dark):
    """Best-effort Windows titlebar only; unsupported systems keep native chrome."""
    if sys.platform != 'win32':
        return
    try:
        from ctypes import wintypes
        user = ctypes.windll.user32
        user.GetParent.argtypes = [wintypes.HWND]
        user.GetParent.restype = wintypes.HWND
        hwnd = user.GetParent(root.winfo_id())
        value = wintypes.BOOL(dark)
        fn = ctypes.windll.dwmapi.DwmSetWindowAttribute
        fn.argtypes = [wintypes.HWND, wintypes.DWORD, ctypes.c_void_p, wintypes.DWORD]
        fn(hwnd, 20, ctypes.byref(value), ctypes.sizeof(value))
    except (OSError, AttributeError):
        pass


class GlassCard(tk.Canvas):
    """Static frosted rim/shadow, with solid inner surface for legible native controls."""
    def __init__(self, parent, palette):
        super().__init__(parent, highlightthickness=0, bd=0, bg=palette['bg'])
        self.palette = palette
        self.inner = tk.Frame(self, bg=palette['card'])
        self.window = self.create_window(18, 12, window=self.inner, anchor='nw')
        self.inner.bind('<Configure>', self.measure)
        self.bind('<Configure>', self.render)
        self.image = None
        self.last_size = None

    def measure(self, _=None):
        wanted = self.inner.winfo_reqheight() + 26
        if self.cget('height') != str(wanted):
            self.configure(height=wanted)

    def set_palette(self, palette):
        self.palette = palette
        self.configure(bg=palette['bg'])
        self.inner.configure(bg=palette['card'])
        self.last_size = None
        self.render()

    def render(self, _=None):
        from PIL import Image, ImageDraw, ImageTk
        width, height = self.winfo_width(), self.winfo_height()
        if width < 40 or height < 40:
            return
        self.itemconfigure(self.window, width=width - 36)
        if self.last_size == (width, height):
            return
        self.last_size = (width, height)
        p = self.palette
        # Supersampling keeps the rounded edges smooth at fractional Windows DPI.
        scale = 2
        image = Image.new('RGB', (width*scale, height*scale), p['bg'])
        draw = ImageDraw.Draw(image)
        draw.rounded_rectangle((2, 6, (width-1)*scale, (height-1)*scale), 24*scale, fill=p['shadow'])
        draw.rounded_rectangle((1, 1, (width-2)*scale, (height-4)*scale), 22*scale,
                               fill=p['card'], outline=p['rim'], width=scale)
        # A subdued specular edge gives depth without animation or GPU dependency.
        draw.line((26*scale, 2*scale, (width-26)*scale, 2*scale), fill=p['glow'], width=scale)
        image = image.resize((width, height), Image.Resampling.LANCZOS)
        self.image = ImageTk.PhotoImage(image, master=self)
        self.delete('surface')
        self.create_image(0, 0, image=self.image, anchor='nw', tags='surface')
        self.tag_lower('surface')


def apply_roles(widget, palette):
    """Recolor in place; never rebuild controls or restart the running proxy."""
    roles = getattr(widget, '_theme_roles', {})
    if roles:
        widget.configure(**{option: palette[role] for option, role in roles.items()})
    if hasattr(widget, 'set_palette'):
        widget.set_palette(palette)
    for child in widget.winfo_children():
        if child.winfo_exists():
            apply_roles(child, palette)
