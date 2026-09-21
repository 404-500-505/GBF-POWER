"""Client-only glass layout, separated from lifecycle and authorization handling."""
import tkinter as tk
from tkinter import ttk
from client_theme import GlassCard, THEME_LABELS
from client_controls import GlassSelect


def compact_window_size(body_width, footer_height, screen_width, screen_height, scaling):
    """Return a readable compact size without applying Windows DPI twice."""
    scale=max(1.0,float(scaling)/(96/72))
    # Fonts and widgets already honor Tk scaling. Grow the shell more slowly,
    # then honor the actual minimum requested by its contents.
    base_width=round(480+min(scale-1,1)*240)
    width=min(max(480,base_width,body_width+24),max(400,screen_width-48))
    height=max(400,min(760,screen_height-72))
    # Keep enough work area above the fixed action footer on short displays.
    height=max(min(screen_height-48,footer_height+320),height)
    return width,height


def frame(app, parent, role='card', **kw):
    widget = tk.Frame(parent, bg=app.colors[role], **kw)
    widget._theme_roles = {'bg': role}
    return widget


def build(app, enrolled, preferences):
    root, p = app.root, app.colors
    footer = frame(app, root, 'bg')
    footer.pack(side='bottom', fill='x')
    app.footer = footer
    # Scroll only when the work area is too short (small screens or large fonts).
    viewport = tk.Canvas(root, bg=p['bg'], bd=0, highlightthickness=0)
    viewport._theme_roles = {'bg': 'bg'}
    viewport.pack(side='left', fill='both', expand=True)
    scroll = ttk.Scrollbar(root, orient='vertical', command=viewport.yview,style='Glass.Vertical.TScrollbar')
    viewport.configure(yscrollcommand=scroll.set)
    app.body = frame(app, viewport, 'bg')
    window = viewport.create_window(0, 0, anchor='nw', window=app.body)
    app.viewport = viewport
    def extent(_=None):
        viewport.configure(scrollregion=viewport.bbox('all'))
        if app.body.winfo_reqheight() > viewport.winfo_height() + 2:
            if not scroll.winfo_ismapped(): scroll.pack(side='right', fill='y')
        else:
            scroll.pack_forget()
            viewport.yview_moveto(0)
    def resize(event):
        viewport.itemconfigure(window, width=event.width)
        extent()
    viewport.bind('<Configure>', resize)
    app.body.bind('<Configure>', extent)
    def wheel(event):
        if event.widget.winfo_toplevel() == root and app.body.winfo_reqheight() > viewport.winfo_height():
            viewport.yview_scroll(-int(event.delta / 120), 'units')
    root.bind('<MouseWheel>', wheel)

    header = frame(app, app.body, 'bg')
    header.pack(fill='x', padx=24, pady=(14, 8))
    icon = tk.Label(header, image=app.header_icon, text='' if app.header_icon else 'GP',
                    font=('Segoe UI',18,'bold'),bg=p['bg'],fg=p['accent'])
    icon._theme_roles = {'bg': 'bg','fg':'accent'}
    icon.pack(side='left', padx=(0, 12))
    title = frame(app, header, 'bg'); title.pack(side='left')
    app.label(title, 'GBF POWER', font=('Segoe UI', 20, 'bold')).pack(anchor='w')
    app.label(title, '专注游戏，连接更轻盈。', 'muted', font=('Microsoft YaHei UI', 9)).pack(anchor='w')
    app.menu_button = app.button(header, '···', app.menu, width=3)
    app.menu_button.pack(side='right')

    appearance = frame(app, app.body, 'bg'); appearance.pack(fill='x', padx=26, pady=(0, 8))
    app.label(appearance, '外观', 'muted').pack(side='left')
    app.theme_value = tk.StringVar(value=THEME_LABELS[app.theme_choice])
    app.theme_select = GlassSelect(appearance, textvariable=app.theme_value,
        values=tuple(THEME_LABELS.values()), width=10, palette=p)
    app.theme_select.pack(side='right')
    app.theme_select.bind('<<ComboboxSelected>>', lambda _: app.set_theme(
        next(key for key, value in THEME_LABELS.items() if value == app.theme_value.get())))

    def card():
        outer = GlassCard(app.body, app.colors)
        outer.pack(fill='x', padx=18, pady=(0, 10))
        return outer.inner

    route = card()
    app.connection_state = app.label(route, '●  已停止', 'muted', font=('Microsoft YaHei UI', 10, 'bold'))
    app.connection_state.pack(anchor='w')
    app.actual_line = app.label(route, '未连接', font=('Microsoft YaHei UI', 20, 'bold'))
    app.actual_line.pack(anchor='w', pady=(5, 2))
    app.connection_hint = app.label(route, '选择偏好线路，准备好后开启加速。', 'muted', wraplength=420)
    app.connection_hint.pack(anchor='w', pady=(0, 8))
    app.line_value = tk.StringVar(value=preferences)
    app.line_select = GlassSelect(route, textvariable=app.line_value,
        values=('自动选择','优先东京','优先东京 CN2','优先大阪'), palette=p)
    app.line_select.pack(fill='x')
    app.line_select.bind('<<ComboboxSelected>>', app.line_changed)
    app.authorization = app.label(route,
        f"已激活 · {enrolled.get('device_count','—')} / 2 台" if enrolled else '未激活 · 从右上角菜单激活设备', 'muted')
    app.authorization.pack(anchor='w', pady=(10, 0))

    network = card()
    app.label(network, '连接概览', font=('Microsoft YaHei UI', 11, 'bold')).pack(anchor='w', pady=(0, 8))
    live = frame(app, network); live.pack(fill='x')
    for key, title, size in [('ping', '节点 TCP 延迟', 22), ('speed', '实时流量 ↓ / ↑', 13)]:
        cell = frame(app, live); cell.pack(side='left', fill='both', expand=True)
        app.label(cell, title, 'muted', font=('Microsoft YaHei UI', 9)).pack(anchor='w')
        app.metrics[key] = app.label(cell, '—', font=('Segoe UI', size, 'bold'))
        app.metrics[key].pack(anchor='w', pady=(2, 8))
    for key, title in [('loss', '探测未响应'), ('gbf', 'GBF 公开页'), ('tunnels', '累计加密连接')]:
        app.metrics[key] = app.row(title, '—', parent=network)
    app.label(network, '公开页响应不是战斗延迟；探测未响应不等于游戏丢包。', 'muted',
              font=('Microsoft YaHei UI', 9), wraplength=440).pack(anchor='w', pady=(6, 0))

    cache = card()
    heading = frame(app, cache); heading.pack(fill='x', pady=(0, 8))
    app.label(heading, '本地素材', font=('Microsoft YaHei UI', 11, 'bold')).pack(side='left')
    app.check(heading, '启用缓存', app.cache, app.cache_clicked).pack(side='right')
    counters = frame(app, cache); counters.pack(fill='x')
    for key, title in [('requests', '素材请求'), ('direct', '直接命中'), ('validated', '校验复用')]:
        cell = frame(app, counters); cell.pack(side='left', fill='x', expand=True)
        app.metrics[key] = app.label(cell, '—', font=('Segoe UI', 22, 'bold'))
        app.metrics[key].pack(anchor='w')
        app.label(cell, title, 'muted', font=('Microsoft YaHei UI', 9)).pack(anchor='w')
    app.cache_detail = app.label(cache, '网络下载 — · 节省传输 —', 'muted')
    app.cache_detail.pack(anchor='w', pady=(6, 2))
    app.cert_label = app.label(cache, '证书状态：未检查', 'muted', font=('Microsoft YaHei UI', 9), wraplength=440)
    app.cert_label.pack(anchor='w', pady=(3, 0))
    app.label(cache, '仅缓存 GBF 素材 · 登录与战斗保持加密透传', 'muted',
              font=('Microsoft YaHei UI', 9), wraplength=440).pack(anchor='w', pady=(3, 0))

    actions = frame(app, footer, 'bg'); actions.pack(fill='x', padx=22, pady=(10, 8))
    app.toggle = app.button(actions, '已停止，开启加速', app.toggle_clicked, primary=True)
    app.toggle.pack(side='left', fill='x', expand=True, ipady=9, padx=(0, 10))
    app.confirm = app.button(actions, '检查连接', app.confirm_clicked)
    app.confirm.pack(side='right', ipady=9, ipadx=8)
    bottom = frame(app, footer, 'bg'); bottom.pack(fill='x', padx=22)
    app.check(bottom, '窗口置顶', app.top, lambda: root.attributes('-topmost', app.top.get())).pack(side='left')
    app.button(bottom, '复制 PAC 地址', lambda: app.copy(
        f"http://127.0.0.1:{app.manager.config()['port']}/proxy.pac")).pack(side='right')
    app.notice = app.label(footer, '在 ZeroOmega 选择本机 PAC 情景；停止后切回直连。',
                           'muted', wraplength=460, font=('Microsoft YaHei UI', 9))
    app.notice.pack(fill='x', padx=26, pady=(8, 18))
    root.update_idletasks()
    width, height = compact_window_size(app.body.winfo_reqwidth(),footer.winfo_reqheight(),
        root.winfo_screenwidth(),root.winfo_screenheight(),root.tk.call('tk','scaling'))
    viewport.itemconfigure(window, width=width)
    root.update_idletasks()
    root.geometry(f'{width}x{height}+24+24')
