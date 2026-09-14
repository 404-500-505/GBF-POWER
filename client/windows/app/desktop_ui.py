"""Compact native window inspired by the supplied ACG POWER reference."""
import argparse
import ctypes
import ipaddress
import os
from pathlib import Path
import queue
import re
import socket
import sys
import threading
import time
_tcl_library=(Path(sys._MEIPASS)/'tcl86t.dll' if getattr(sys,'frozen',False)
              else Path(sys.base_prefix)/'DLLs/tcl86t.dll')
_tcl=ctypes.CDLL(str(_tcl_library))
_tcl.Tcl_FindExecutable.argtypes=[ctypes.c_char_p]
_tcl.Tcl_FindExecutable(sys.executable.encode('utf-8'))
_tcl.Tcl_SetSystemEncoding.argtypes=[ctypes.c_void_p,ctypes.c_char_p]
_tcl.Tcl_SetSystemEncoding.restype=ctypes.c_int
# Tcl's initial ANSI encoding may be unavailable before its scripts are loaded.
# UTF-8 is built in and avoids that bootstrap dependency on localized Windows.
if _tcl.Tcl_SetSystemEncoding(None,b'utf-8') != 0:
    raise RuntimeError('Cannot initialize the window runtime encoding')
import tkinter as tk
from tkinter import filedialog,messagebox,ttk

from client_model import OperationGate,display_stats,number,Rates,PingWindow
from client_runtime import (Manager,initialize,load,save,cert_status,set_cache,renew_certificate,
                            generate_key,uninstall_trust,acceleration_ready,BASE)
from monitor import ping_node,probe_gbf
from activation_client import (activate,registration,check_device,ActivationError,
                               set_line_preference,line_preference,set_node_quality,LINE_LABELS)

BG='#1c2420';HEAD='#18201c';FG='#dde2df';MUTED='#969e99';GREEN='#a5efd4';BUTTON='#575b59';LINE='#52665d'
FONT=('Microsoft YaHei UI',10)
PREFERENCE_LABELS={'auto':'自动选择','tokyo':'优先东京','tokyo_cn2':'优先东京 CN2','osaka':'优先大阪'}

def assets():
    p=BASE/'assets'
    return p if p.exists() else BASE.parent/'proxy_core'

def default_home():return Path(os.environ['LOCALAPPDATA'])/'GBFDesktop'

def actual_line_label(enrolled,status):
    """Return the route used by the running proxy without exposing its endpoint."""
    enrolled=enrolled if isinstance(enrolled,dict) else {}
    if not isinstance(status,dict):return '未连接'
    nodes=enrolled.get('nodes') if isinstance(enrolled.get('nodes'),dict) else {}
    hosts={node.get('host'):node_id for node_id,node in nodes.items()
           if node_id in ('tokyo','tokyo_cn2','osaka') and isinstance(node,dict) and isinstance(node.get('host'),str)}
    runtime_servers=[]
    for name in ('tunnel','game_channel'):
        channel=status.get(name)
        if isinstance(channel,dict) and channel.get('connected') and isinstance(channel.get('server'),str):
            runtime_servers.append(channel['server'])
    if not runtime_servers:return '连接中'
    routes=[hosts.get(server) for server in runtime_servers]
    if any(route is None for route in routes):return '线路未知'
    if len(set(routes))!=1:return '线路切换中'
    return LINE_LABELS[routes[0]]

class App:
    def __init__(self,root,home,preview=False,admin=False):
        self.root=root;self.home=Path(home);self.preview=preview;self.admin=admin
        self.home.mkdir(parents=True,exist_ok=True)
        self.preferences=self.home/'desktop.json'
        try:self.prefs=load(self.preferences)
        except (OSError,ValueError):self.prefs={}
        profile=Path(self.prefs.get('profile',str(self.home/'profile'))) if admin else self.home/'profile'
        if not (profile/'config.json').exists():profile=self.home/'profile'
        initialize(profile,assets())
        self.manager=Manager(profile);self.gate=OperationGate();self.queue=queue.Queue()
        self.quit_event=threading.Event();self.connected=False;self.online=False;self.current=None
        self.revocation_pending=None;self.auth_valid_until=time.monotonic()+300
        self.pings=PingWindow();self.down=Rates();self.up=Rates();self.exit_after=False
        self.node_pings={'tokyo':PingWindow(),'tokyo_cn2':PingWindow(),'osaka':PingWindow()}
        self.network=tk.BooleanVar(value=False);self.cache=tk.BooleanVar(value=False)
        self.top=tk.BooleanVar(value=True);self.metrics={};self.probe_due=0
        root.title('GBF POWER');root.configure(bg=BG)
        icon=assets()/'app.ico'
        if icon.is_file():root.iconbitmap(default=str(icon))
        header_icon=assets()/'app-header.png'
        self.header_icon=tk.PhotoImage(file=str(header_icon)) if header_icon.is_file() else None
        root.geometry('440x760');root.resizable(False,False);root.attributes('-topmost',True)
        root.protocol('WM_DELETE_WINDOW',self.close)
        root.option_add('*Font',FONT)
        header=tk.Frame(root,bg=HEAD,height=60)
        header.pack(fill='x');header.pack_propagate(False)
        if self.header_icon:
            tk.Label(header,image=self.header_icon,bg=HEAD).pack(side='left',padx=(16,0))
        else:
            tk.Label(header,text='G',font=('Segoe UI',18,'bold'),width=2,bg=BUTTON,fg=FG).pack(side='left',padx=(16,0))
        title=tk.Label(header,text='GBF POWER',font=('Segoe UI',22),bg=HEAD,fg=FG)
        title.pack(side='left',padx=10)
        menu=self.button(header,'⋮',self.menu,width=3);menu.pack(side='right',padx=12)
        self.body=tk.Frame(root,bg=BG);self.body.pack(fill='both',expand=True,padx=20,pady=12)
        line=tk.Frame(self.body,bg=BG);line.pack(fill='x',pady=2)
        self.label(line,'线路',MUTED,width=12).pack(side='left')
        self.line_value=tk.StringVar(value=PREFERENCE_LABELS[line_preference(self.manager.root)])
        style=ttk.Style(root);style.configure('Line.TCombobox',font=FONT,padding=2)
        self.line_select=ttk.Combobox(line,textvariable=self.line_value,state='readonly',width=17,
                                      values=('自动选择','优先东京','优先东京 CN2','优先大阪'),style='Line.TCombobox')
        self.line_select.pack(side='left',fill='x',expand=True)
        self.line_select.bind('<<ComboboxSelected>>',self.line_changed)
        enrolled=registration(self.manager.root)
        self.actual_line=self.row('实际线路','未连接')
        self.authorization=self.row('授权',f"已激活 · {enrolled.get('device_count','—')} / 2 台" if enrolled else '未激活')
        self.row('加速范围','GBF / GameWith / 梦宝谷 / DMM')
        self.row('本地入口','本机代理')
        self.separator()
        cert_line=tk.Frame(self.body,bg=BG);cert_line.pack(fill='x',pady=(3,0))
        self.check(cert_line,'自签证书 / 本地素材缓存',self.cache,self.cache_clicked).pack(side='left')
        self.cert_label=self.label(self.body,'证书状态：未检查',MUTED,wraplength=398)
        self.cert_label.pack(anchor='w',pady=(5,3))
        self.label(self.body,'只解密 GBF 素材 CDN，登录和战斗保持加密透传。',MUTED,wraplength=398).pack(anchor='w')
        self.separator()
        for name,text in [('requests','素材请求'),('hits','本地缓存命中'),('tunnels','加密连接'),('speed','实时流量'),('ping','线路延迟'),('loss','Ping 未响应率'),('gbf','GBF 公开页响应')]:
            self.metrics[name]=self.row(text,'—')
        self.label(self.body,'当前会话统计。加密连接 ≠ 请求数；Ping 不代表游戏丢包。',MUTED,wraplength=398).pack(anchor='w',pady=(5,8))
        self.toggle=self.button(self.body,'已停止，点击开启',self.toggle_clicked)
        self.toggle.pack(fill='x',ipady=6,pady=(2,9))
        self.confirm=self.button(self.body,'确认连接状态',self.confirm_clicked)
        self.confirm.pack(fill='x',ipady=4,pady=(0,9))
        bottom=tk.Frame(self.body,bg=BG);bottom.pack(fill='x')
        self.check(bottom,'网络加速',self.network,self.toggle_clicked).pack(side='left')
        self.check(bottom,'窗口置顶',self.top,lambda:root.attributes('-topmost',self.top.get())).pack(side='right')
        self.notice=self.label(self.body,'使用前在 ZeroOmega 选择本机 PAC 情景；停止后切回直连。',MUTED,wraplength=398)
        self.notice.pack(anchor='w',pady=(7,0))
        root.bind('<Map>',self.no_maximize)
        self.root.after(100,self.drain)
        if not preview:
            for target in (self.poll,self.ping_loop,self.gbf_loop,self.authorization_loop):
                threading.Thread(target=target,daemon=True).start()
            if not admin and not enrolled:self.root.after(300,self.activate_dialog)
    def label(self,parent,text,color=FG,**kw):return tk.Label(parent,text=text,bg=parent.cget('bg'),fg=color,anchor='w',justify='left',**kw)
    def button(self,parent,text,command,**kw):
        return tk.Button(parent,text=text,command=command,bg=BUTTON,fg=FG,activebackground='#686e6a',
                         activeforeground=FG,relief='flat',bd=0,cursor='hand2',**kw)
    def check(self,parent,text,variable,command):
        return tk.Checkbutton(parent,text=text,variable=variable,command=command,bg=BG,fg=FG,
            selectcolor='#344a40',activebackground=BG,activeforeground=GREEN,highlightthickness=0,bd=0)
    def row(self,name,value):
        line=tk.Frame(self.body,bg=BG);line.pack(fill='x',pady=2)
        self.label(line,name,MUTED,width=12).pack(side='left')
        v=self.label(line,value);v.pack(side='left',fill='x',expand=True);return v
    def separator(self):tk.Frame(self.body,bg=LINE,height=1).pack(fill='x',pady=10)
    def line_changed(self,_=None):
        labels={'自动选择':'auto','优先东京':'tokyo','优先东京 CN2':'tokyo_cn2','优先大阪':'osaka'}
        value=labels[self.line_value.get()]
        if self.online or self.gate.busy:
            current=PREFERENCE_LABELS[line_preference(self.manager.root)]
            self.line_value.set(current)
            messagebox.showinfo('先停止','切换线路前请先停止加速。',parent=self.root)
            return
        set_line_preference(self.manager.root,value)
        self.notice.configure(text='线路偏好已保存，下次启动时生效。',fg=MUTED)
    def no_maximize(self,_=None):
        if self.root.state()=='zoomed':self.root.state('normal')
        try:
            hwnd=ctypes.windll.user32.GetParent(self.root.winfo_id())
            style=ctypes.windll.user32.GetWindowLongW(hwnd,-16)
            ctypes.windll.user32.SetWindowLongW(hwnd,-16,style & ~0x10000 & ~0x40000)
        except OSError:pass
    def run(self,state,operation):
        if self.preview:return
        if not self.gate.begin(state):return
        self.toggle.configure(state='disabled',text={'starting':'正在启动…','stopping':'正在停止…','certificate':'正在处理证书…','activating':'正在激活…'}.get(state,'正在处理…'))
        def work():
            try:operation();self.queue.put(('done',None))
            except Exception as e:self.queue.put(('error',str(e)))
        threading.Thread(target=work,daemon=True).start()
    def toggle_clicked(self):
        self.network.set(self.online)
        if not self.online and not self.admin and not registration(self.manager.root):
            self.activate_dialog();return
        self.run('stopping' if self.online else 'starting',self.manager.stop if self.online else self.manager.start)
    def activate_dialog(self):
        if self.gate.busy or self.online:
            messagebox.showinfo('先停止','请先停止加速再激活设备。',parent=self.root);return
        dialog=tk.Toplevel(self.root);dialog.title('激活设备');dialog.configure(bg=BG)
        dialog.resizable(False,False);dialog.transient(self.root);dialog.grab_set()
        self.label(dialog,'输入激活码 · 一个码最多绑定 2 台设备',wraplength=380).pack(padx=18,pady=(18,8))
        entry=tk.Entry(dialog,width=38,bg=BUTTON,fg=FG,insertbackground=FG,relief='flat')
        entry.pack(padx=18,pady=8);entry.focus_set()
        self.label(dialog,'本机会自动生成独立设备凭据，无需配置密钥。\n重装后遗失凭据，请联系管理员解绑旧设备。',MUTED,wraplength=380).pack(padx=18,pady=8)
        def submit():
            code=entry.get();entry.delete(0,'end');dialog.destroy()
            def work():
                result=activate(self.manager.root,code)
                self.queue.put(('authorized',(self.manager.root,result,time.monotonic())))
            self.run('activating',work)
        self.button(dialog,'激活这台设备',submit).pack(fill='x',padx=18,pady=(8,18),ipady=5)
        entry.bind('<Return>',lambda _:submit())
    def authorization_loop(self):
        while not self.quit_event.is_set():
            manager=self.manager
            if registration(manager.root):
                try:
                    result=check_device(manager.root)
                    self.queue.put(('authorized',(manager.root,result,time.monotonic())))
                except ActivationError as error:
                    denied=error.code in ('revoked','not_activated','invalid_code','pin_mismatch')
                    if denied:
                        self.queue.put(('authorization_denied',(manager.root,str(error))))
                except (OSError,ValueError):
                    self.queue.put(('authorization_denied',(manager.root,'设备凭据不可读取，请联系管理员。')))
            self.quit_event.wait(60)
    def confirm_clicked(self):
        if self.preview:return
        if self.gate.busy:return
        def check():
            s=self.manager.owned_status()
            if not s:raise RuntimeError('本配置的代理未运行。若端口已占用，请先退出旧版。')
            ms,status=probe_gbf(self.manager.config()['port'])
            if ms is None:raise RuntimeError('本地代理在线，但 GBF 公开页探测失败，请检查节点状态。')
            self.queue.put(('info',f'本地代理在线，GBF 公开页 HTTP {status}，响应 {ms:.0f} ms。\n这不是账号首页或战斗接口延迟。'))
        self.run('checking',check)
    def cache_clicked(self):
        enabled=self.cache.get();self.cache.set(not enabled)
        if self.gate.busy:return
        text=('启用缓存需要在 Windows 当前用户证书库信任本机生成的证书。\n仅解密 13 个 GBF 素材 CDN；不处理登录／战斗。\n信任会影响使用此证书库的应用。CA 签名私钥不保存，素材私钥仅留在本机。\n\n允许安装证书并启用素材缓存吗？' if enabled else
              '将关闭本地素材缓存，移除这套缓存证书的信任，保留所有缓存文件。\n运行中的代理会短暂重启。继续吗？')
        if messagebox.askyesno('证书与素材缓存',text,parent=self.root):self.run('certificate',lambda:set_cache(self.manager,enabled))
    def close(self):
        if self.gate.busy:
            messagebox.showinfo('正在处理','请等待当前启动／停止操作完成后再退出。',parent=self.root);return
        if self.online and not messagebox.askyesno('停止并退出','退出将停止当前加速，请先结束游戏操作。\nZeroOmega 仍需切回“直接连接”。继续退出吗？',parent=self.root):return
        if self.preview:self.root.destroy();return
        self.exit_after=True;self.run('stopping',self.manager.stop)
    def poll(self):
        while not self.quit_event.is_set():
            manager=self.manager
            try:
                s=manager.owned_status();c=cert_status(manager.root)
                self.queue.put(('status',(manager.root,s,c)))
            except Exception:self.queue.put(('status',(manager.root,None,None)))
            self.quit_event.wait(1)
    def ping_loop(self):
        while not self.quit_event.is_set():
            manager=self.manager
            try:
                enrolled=registration(manager.root) or {};nodes=enrolled.get('nodes') or {}
                # Sandbox observations are never presented as the user's route.
                if nodes and 'sandbox' not in os.environ.get('USERNAME','').lower():
                    sampled=time.time()
                    for node_id,node in nodes.items():
                        started=time.monotonic()
                        try:
                            with socket.create_connection((node['host'],node['port']),timeout=2):pass
                            ms=(time.monotonic()-started)*1000
                        except OSError:ms=None
                        self.node_pings[node_id].add(ms,sampled)
                        set_node_quality(manager.root,node_id,self.node_pings[node_id].quality(sampled))
                    assigned=(enrolled.get('assigned_line') or {}).get('id')
                    ms=self.node_pings.get(assigned,PingWindow()).view(sampled)['latest']
                else:
                    node=manager.config().get('ssh',{}).get('host')
                    ms=None if 'sandbox' in os.environ.get('USERNAME','').lower() else ping_node(node)
                self.queue.put(('ping',(manager.root,ms)))
            except Exception:pass
            self.quit_event.wait(10)
    def gbf_loop(self):
        while not self.quit_event.wait(15):
            manager=self.manager
            if self.connected:
                ms,status=probe_gbf(manager.config()['port'])
                self.queue.put(('gbf',(manager.root,ms,status)))
    def drain(self):
        try:
            while True:
                kind,value=self.queue.get_nowait()
                if kind in ('done','error'):
                    self.gate.finish('running' if self.online else 'stopped')
                    self.toggle.configure(state='normal')
                    if kind=='error':
                        self.exit_after=False;self.notice.configure(text=value,fg='#e2bc9c')
                        self.root.after(0,lambda message=value:messagebox.showerror('操作未完成',message,parent=self.root))
                    elif self.exit_after:
                        self.quit_event.set();self.manager.dispose();self.root.destroy();return
                elif kind=='info':self.root.after(0,lambda message=value:messagebox.showinfo('连接状态',message,parent=self.root))
                elif kind=='authorized':
                    folder,result,checked_at=value
                    if folder==self.manager.root:
                        self.authorization.configure(text=f"已激活 · {result.get('device_count','—')} / 2 台")
                        self.auth_valid_until=checked_at+300;self.revocation_pending=None
                elif kind=='authorization_denied':
                    folder,reason=value
                    if folder==self.manager.root:
                        self.authorization.configure(text='授权不可用')
                        self.notice.configure(text=reason,fg='#e2bc9c')
                        self.revocation_pending=reason
                elif kind=='status':
                    folder,s,c=value
                    if folder!=self.manager.root:continue
                    self.current=s;self.online=bool(s);self.connected=acceleration_ready(s)
                    enrolled=registration(self.manager.root) or {}
                    self.line_value.set(PREFERENCE_LABELS[line_preference(self.manager.root)])
                    self.actual_line.configure(text=actual_line_label(enrolled,s))
                    if not self.connected:self.metrics['gbf'].configure(text='—')
                    self.network.set(self.online)
                    self.cache.set(bool(s.get('cache',{}).get('enabled')) if s else bool(self.manager.config().get('cache',{}).get('enabled')))
                    if c:self.cert_label.configure(text=f"证书：{'已信任' if c['trusted'] else '未信任'}　有效期至 {c['expires'][:10]}")
                    else:self.cert_label.configure(text='证书：未安装 / 不可读取')
                    d=display_stats(s)
                    for key,source in [('requests','asset_requests'),('hits','cache_hits'),('tunnels','tunnels')]:self.metrics[key].configure(text=number(d[source]))
                    now=time.monotonic();s=s or {}
                    down=self.down.update(s.get('instance'),s.get('bytes_downloaded'),now)
                    up=self.up.update(s.get('instance'),s.get('bytes_uploaded'),now)
                    self.metrics['speed'].configure(text=f'↓ {speed(down)}　↑ {speed(up)}')
                    if not self.gate.busy:self.toggle.configure(text='加速中，点击停止' if self.connected else '连接中 / 重连中，点击停止' if self.online else '已停止，点击开启')
                elif kind=='ping':
                    folder,ms=value
                    if folder==self.manager.root:self.pings.add(ms,time.time())
                elif kind=='gbf':
                    folder,ms,status=value
                    if folder==self.manager.root:self.metrics['gbf'].configure(text=f'{ms:.0f} ms · HTTP {status}' if ms is not None else '不可测')
        except queue.Empty:pass
        self.auth_valid_until=max(self.auth_valid_until,self.manager.auth_checked_at+300)
        owned_alive=self.manager.process is not None and self.manager.process.poll() is None
        if (self.online or owned_alive) and registration(self.manager.root) and time.monotonic()>=self.auth_valid_until:
            self.revocation_pending='已超过 5 分钟无法确认授权，暂停加速；网络恢复后可重新开启。'
        if self.revocation_pending and not self.gate.busy:
            self.notice.configure(text=self.revocation_pending,fg='#e2bc9c')
            self.revocation_pending=None;self.run('stopping',self.manager.stop)
        p=self.pings.view(time.time())
        self.metrics['ping'].configure(text=f"{p['latest']:.0f} ms" if p['latest'] is not None else '—')
        self.metrics['loss'].configure(text=(f"{p['loss']:.1f}%（{p['sent']} 次探测）" if p['loss'] is not None else '不可测 / 尚无有效回包'))
        self.root.after(100,self.drain)
    def build_menu(self):
        m=tk.Menu(self.root,tearoff=False,bg=BG,fg=FG)
        m.add_command(label='激活设备…',command=self.activate_dialog)
        if self.admin:
            m.add_command(label='节点与配置…',command=self.settings)
            m.add_command(label='使用已有配置目录…',command=self.use_existing)
        m.add_command(label='复制 PAC 地址',command=lambda:self.copy(f"http://127.0.0.1:{self.manager.config()['port']}/proxy.pac"))
        if self.admin:
            m.add_command(label='生成本机 SSH 密钥',command=self.key_clicked)
            m.add_command(label='复制本机 SSH 公钥',command=self.copy_key)
        m.add_command(label='更新证书…',command=self.renew_clicked)
        m.add_command(label='打开数据目录',command=lambda:os.startfile(self.manager.root))
        m.add_separator();m.add_command(label='停止并退出',command=self.close)
        return m
    def menu(self):
        m=self.build_menu()
        m.tk_popup(self.root.winfo_rootx()+250,self.root.winfo_rooty()+55)
    def copy(self,text):self.root.clipboard_clear();self.root.clipboard_append(text)
    def copy_key(self):
        try:self.copy((self.manager.root/'runtime/ssh/id_ed25519.pub').read_text())
        except OSError:messagebox.showinfo('尚无公钥','请先生成本机 SSH 密钥。',parent=self.root)
    def key_clicked(self):
        if self.gate.busy:return
        def make():
            generate_key(self.manager.root)
            self.queue.put(('info','本机密钥已生成。请从菜单复制公钥，将它添加到服务器对应用户的 authorized_keys。\n安装包不会包含任何人的私钥。'))
        self.run('key',make)
    def renew_clicked(self):
        if self.gate.busy:return
        if messagebox.askyesno('更新证书','重新生成本机素材证书并安装当前用户信任，移除旧证书信任。\n仅限素材 CDN；保留旧证书文件备份和所有缓存。运行中的代理会重启。\n继续吗？',parent=self.root):self.run('certificate',lambda:renew_certificate(self.manager))
    def use_existing(self):
        if self.gate.busy or self.online:
            messagebox.showinfo('先停止','请先停止当前加速再切换配置目录。',parent=self.root);return
        folder=filedialog.askdirectory(title='选择包含 config.json 和 rules.json 的代理配置目录',parent=self.root)
        if not folder:return
        p=Path(folder)
        try:
            c=load(p/'config.json');load(p/'rules.json')
            if not isinstance(c.get('port'),int):raise ValueError()
            self.manager.dispose();self.manager=Manager(p);self.pings=PingWindow()
            self.metrics['gbf'].configure(text='—');self.down=Rates();self.up=Rates()
            self.prefs['profile']=str(p);save(self.preferences,self.prefs)
            self.notice.configure(text='已接入现有配置。已有实例可正常停止；再次开启后由客户端管理。',fg=MUTED)
        except (OSError,ValueError):messagebox.showerror('配置无效','目录中需要有效的 config.json 和 rules.json。',parent=self.root)
    def settings(self):
        if self.gate.busy or self.online:
            messagebox.showinfo('先停止','修改节点前请先停止加速。',parent=self.root);return
        dialog=tk.Toplevel(self.root);dialog.title('节点与配置');dialog.configure(bg=BG);dialog.resizable(False,False)
        dialog.transient(self.root);dialog.grab_set()
        c=self.manager.config();ssh=c.get('ssh',{});fields={}
        labels=[('host','服务器',ssh.get('host','')),('username','SSH 用户',ssh.get('username','')),
                ('port','SSH 端口',str(ssh.get('port',22))),('private_key','私钥文件',ssh.get('private_key','')),
                ('known_hosts','服务器公钥文件',ssh.get('known_hosts',''))]
        for i,(key,label,value) in enumerate(labels):
            self.label(dialog,label,MUTED).grid(row=i,column=0,padx=12,pady=8,sticky='w')
            entry=tk.Entry(dialog,width=30,bg=BUTTON,fg=FG,insertbackground=FG,relief='flat')
            entry.insert(0,value);entry.grid(row=i,column=1,padx=12,pady=8);fields[key]=entry
            if key in ('private_key','known_hosts'):
                def browse(e=entry):
                    file=filedialog.askopenfilename(parent=dialog)
                    if file:e.delete(0,'end');e.insert(0,file)
                self.button(dialog,'…',browse).grid(row=i,column=2,padx=6)
        self.label(dialog,'服务器公钥须经可信渠道核对；不自动接受陌生主机。\n同一台电脑可用菜单“使用已有配置目录”接入旧配置。',MUTED,wraplength=420).grid(row=5,column=0,columnspan=3,padx=12,pady=12)
        def commit():
            values={key:e.get().strip() for key,e in fields.items()}
            try:
                if not re.fullmatch(r'[a-zA-Z0-9.-]+',values['host']) or not re.fullmatch(r'[a-zA-Z0-9_-]+',values['username']):raise ValueError()
                values['port']=int(values['port'])
                if not 1<=values['port']<=65535:raise ValueError()
                if not values['private_key'] or not values['known_hosts']:raise ValueError()
                values['socks_port']=ssh.get('socks_port',18124);c['ssh']=values;save(self.manager.root/'config.json',c)
                self.pings=PingWindow();dialog.destroy()
            except ValueError:messagebox.showerror('参数无效','请检查服务器、用户名、端口和文件路径。',parent=dialog)
        self.button(dialog,'保存',commit).grid(row=6,column=0,columnspan=3,padx=12,pady=12,sticky='ew')

def speed(value):
    if value is None:return '—'
    return f'{value/1024:.1f} KB/s' if value<1024**2 else f'{value/1024**2:.1f} MB/s'

def create_root():
    try:return tk.Tk()
    except tk.TclError as error:
        _tcl.Tcl_CreateInterp.restype=ctypes.c_void_p
        interp=_tcl.Tcl_CreateInterp()
        _tcl.Tcl_Eval.argtypes=[ctypes.c_void_p,ctypes.c_char_p]
        _tcl.Tcl_GetStringResult.argtypes=[ctypes.c_void_p]
        _tcl.Tcl_GetStringResult.restype=ctypes.c_char_p
        diagnostics=[]
        for expression in ('pwd','encoding system','set env(TCL_LIBRARY)',
                           'file exists [file join $env(TCL_LIBRARY) init.tcl]',
                           'set tcl_library $env(TCL_LIBRARY); source [file join $env(TCL_LIBRARY) init.tcl]'):
            code=_tcl.Tcl_Eval(interp,expression.encode())
            diagnostics.append((expression,code,_tcl.Tcl_GetStringResult(interp)))
        _tcl.Tcl_DeleteInterp.argtypes=[ctypes.c_void_p]
        _tcl.Tcl_DeleteInterp(interp)
        # On Windows the first Tcl filesystem lookup may precede encoding/path
        # initialization. The explicit interpreter bootstrap above completes it.
        try:return tk.Tk()
        except tk.TclError:
            raise RuntimeError(str(error)+'\nRuntime diagnostics: '+repr(diagnostics)) from error

def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--home',type=Path)
    parser.add_argument('--preview',action='store_true')
    parser.add_argument('--screenshot',type=Path)
    parser.add_argument('--uninstall',action='store_true')
    parser.add_argument('--admin',action='store_true',help='Show legacy maintenance settings (does not grant server privileges)')
    args=parser.parse_args();home=args.home or default_home()
    if args.uninstall:
        profiles=[home/'profile']
        try:profiles.append(Path(load(home/'desktop.json')['profile']))
        except (OSError,ValueError,KeyError):pass
        for profile in set(profiles):uninstall_trust(profile)
        return
    mutex=None
    if not args.preview and not args.home:
        from ctypes import wintypes
        api=ctypes.WinDLL('kernel32',use_last_error=True)
        api.CreateMutexW.argtypes=[ctypes.c_void_p,wintypes.BOOL,wintypes.LPCWSTR]
        api.CreateMutexW.restype=wintypes.HANDLE
        api.CloseHandle.argtypes=[wintypes.HANDLE]
        mutex=api.CreateMutexW(None,False,'Local\\GBFPowerDesktopApp')
        if not mutex:raise ctypes.WinError(ctypes.get_last_error())
        if ctypes.get_last_error()==183:
            api.CloseHandle(mutex)
            ctypes.windll.user32.MessageBoxW(None,'客户端已打开，请使用现有窗口。','GBF POWER',0x40)
            return
    root=create_root();app=App(root,home,preview=args.preview,admin=args.admin)
    if args.screenshot:
        def shot():
            from PIL import ImageGrab
            try:
                root.update()
                hwnd=ctypes.windll.user32.GetParent(root.winfo_id())
                ImageGrab.grab(window=hwnd).save(args.screenshot)
            finally:root.destroy()
        root.after(1200,shot)
    try:root.mainloop()
    finally:
        app.quit_event.set();app.manager.dispose()
        if mutex:api.CloseHandle(mutex)
