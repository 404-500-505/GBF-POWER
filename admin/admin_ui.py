"""Owner operations window. No client-reported traffic or embedded credentials."""
import ctypes
import os
from pathlib import Path
import queue
import sys
import threading
import time

BASE=Path(__file__).resolve().parent
_tcl=ctypes.CDLL(str(Path(sys._MEIPASS)/'tcl86t.dll' if getattr(sys,'frozen',False) else Path(sys.base_prefix)/'DLLs/tcl86t.dll'))
_tcl.Tcl_FindExecutable.argtypes=[ctypes.c_char_p];_tcl.Tcl_FindExecutable(sys.executable.encode('utf-8'))
_tcl.Tcl_SetSystemEncoding.argtypes=[ctypes.c_void_p,ctypes.c_char_p]
if _tcl.Tcl_SetSystemEncoding(None,b'utf-8')!=0:raise RuntimeError('Cannot initialize Tcl encoding')
import tkinter as tk
from tkinter import ttk,filedialog,messagebox
from admin_transport import Settings,AdminClient,AdminError,validate_snapshot
from admin_model import device_values,snapshot_summary,time_text,numeric,node_values

BG='#1c2420';HEAD='#18201c';FG='#dde2df';MUTED='#a0aaa3';BUTTON='#575b59';GREEN='#a5efd4';WARN='#e2bc9c'

def create_root():
    try:return tk.Tk()
    except tk.TclError:
        _tcl.Tcl_CreateInterp.restype=ctypes.c_void_p;interp=_tcl.Tcl_CreateInterp()
        _tcl.Tcl_Eval.argtypes=[ctypes.c_void_p,ctypes.c_char_p]
        for text in ('pwd','encoding system','set tcl_library $env(TCL_LIBRARY); source [file join $env(TCL_LIBRARY) init.tcl]'):
            _tcl.Tcl_Eval(interp,text.encode())
        _tcl.Tcl_DeleteInterp.argtypes=[ctypes.c_void_p];_tcl.Tcl_DeleteInterp(interp)
        return tk.Tk()

class AdminWindow:
    def __init__(self,root,home,preview=False):
        self.root=root;self.home=Path(home);self.preview=preview;self.home.mkdir(parents=True,exist_ok=True)
        self.settings_path=self.home/'connection.json';self.busy=False;self.closed=False;self.queue=queue.Queue()
        self.snapshot=None;self.received_at=0;self.next_refresh=0;self.controls=[];self.source_error=''
        try:self.settings=Settings.load(self.settings_path)
        except AdminError:
            self.settings=Settings(known_hosts=str(BASE/'assets/known_hosts'))
        root.title('GBF POWER · 管理');root.geometry('1180x830');root.minsize(980,700);root.configure(bg=BG)
        root.option_add('*Font',('Microsoft YaHei UI',10));root.protocol('WM_DELETE_WINDOW',self.close)
        style=ttk.Style(root);style.theme_use('clam')
        style.configure('Treeview',background=BG,foreground=FG,fieldbackground=BG,rowheight=29,borderwidth=0)
        style.configure('Treeview.Heading',background=BUTTON,foreground=FG,relief='flat')
        style.map('Treeview',background=[('selected','#375448')],foreground=[('selected',FG)])
        header=tk.Frame(root,bg=HEAD);header.pack(fill='x')
        self.label(header,'GBF POWER  管理',font=('Segoe UI',20)).pack(side='left',padx=16,pady=12)
        self.label(header,'仅管理员使用 · 服务端计量',fg=MUTED).pack(side='right',padx=18)
        toolbar=tk.Frame(root,bg=BG);toolbar.pack(fill='x',padx=14,pady=8)
        for title,callback in [('刷新',lambda:self.run('snapshot')),('创建激活码',self.create_code),('连接设置',self.connection_dialog)]:
            self.button(toolbar,title,callback).pack(side='left',padx=(0,8),ipadx=10,ipady=3)
        self.status=self.label(toolbar,'尚未连接：请先检查连接设置',fg=WARN);self.status.pack(side='left',padx=12)
        self.summary=self.label(root,'CPU —    内存 —    磁盘 —    上下行 —',fg=MUTED)
        self.summary.pack(fill='x',padx=16,pady=(2,9))
        nodes_frame=tk.Frame(root,bg=BG,height=128);nodes_frame.pack(fill='x',padx=14,pady=(0,8));nodes_frame.pack_propagate(False)
        self.label(nodes_frame,'节点状态',fg=GREEN).pack(anchor='w',pady=(0,4))
        node_columns=[('label','线路',105),('state','状态',65),('load','负载',70),('up','上行',100),('down','下行',100),
                      ('devices','在线设备',70),('connections','转发',55),('throttled','限流设备',75),('probe','公开探测',90),('updated','最后上报',165)]
        self.nodes=self.table(nodes_frame,node_columns)
        panes=tk.PanedWindow(root,orient='horizontal',bg=BG,sashwidth=7,bd=0,height=350);panes.pack(fill='both',expand=True,padx=14)
        left=tk.Frame(panes,bg=BG);right=tk.Frame(panes,bg=BG);panes.add(left,minsize=350,width=390);panes.add(right,minsize=540)
        self.label(left,'激活码 / 用户',fg=GREEN).pack(anchor='w',pady=4)
        self.search=tk.StringVar();entry=tk.Entry(left,textvariable=self.search,bg=BUTTON,fg=FG,insertbackground=FG,relief='flat')
        entry.pack(fill='x',pady=(0,7));entry.bind('<KeyRelease>',lambda _:self.render_licenses())
        self.licenses=self.table(left,[('id','激活码 ID',155),('note','用户 / 备注',145),('state','状态',70),('count','绑定',50),('created','创建时间',160)])
        self.licenses.configure(displaycolumns=('note','state','count','created','id'))
        self.licenses.bind('<<TreeviewSelect>>',lambda _:self.render_devices())
        code_actions=tk.Frame(left,bg=BG);code_actions.pack(fill='x',pady=7)
        self.button(code_actions,'修改备注',lambda:self.edit_note('license')).pack(side='left',padx=(0,6),ipadx=8,ipady=3)
        self.button(code_actions,'停用此码',self.disable_code).pack(side='left',ipadx=8,ipady=3)
        self.label(left,'历史激活码不能还原；新建时显示一次。\n一码两个设备凭据，默认不过期。',fg=MUTED).pack(anchor='w',pady=(0,8))
        self.device_title=self.label(right,'绑定设备 · 请选择左侧激活码',fg=GREEN);self.device_title.pack(anchor='w',pady=4)
        device_actions=tk.Frame(right,bg=BG);device_actions.pack(fill='x',pady=(0,7))
        self.button(device_actions,'修改设备备注',lambda:self.edit_note('device')).pack(side='left',padx=(0,7),ipady=3,ipadx=8)
        self.button(device_actions,'解绑所选设备',self.revoke_device).pack(side='left',ipady=3,ipadx=8)
        cols=[('id','设备 ID',165),('state','状态',65),('note','备注',140),('created','绑定时间',165),('seen','最近连接',165),
              ('sessions','隧道',55),('active','转发',55),('up','上传速度',110),('down','下载速度',110),('tu','今日上传',100),('td','今日下载',100),
              ('totalu','累计上传',100),('totald','累计下载',100),('fingerprint','设备公钥指纹',410)]
        self.devices=self.table(right,cols);self.devices.bind('<<TreeviewSelect>>',lambda _:self.render_details())
        self.devices.configure(displaycolumns=('state','note','up','down','sessions','active','tu','td','totalu','totald','created','seen','id','fingerprint'))
        self.details=self.label(right,'在线按已认证客户端隧道判断；转发是当前 GBF 请求连接。上下行来自服务器实际转发字节。',fg=MUTED,wraplength=690)
        self.details.pack(fill='x',pady=7)
        self.label(root,'最近管理操作（服务器时间）',fg=MUTED).pack(anchor='w',padx=16,pady=(8,2))
        self.events=tk.Text(root,height=4,bg=HEAD,fg=MUTED,relief='flat',wrap='none',state='disabled')
        self.events.pack(fill='x',padx=14,pady=(0,6))
        self.label(root,'不采集游戏内容或设备私钥。今日按北京时间；不含 SSH/TCP 外层开销，异常退出可能损失最近 5 秒未落盘计量。',fg=MUTED).pack(anchor='w',padx=16,pady=(0,8))
        self.timer=root.after(150,self.drain)
        if not preview:root.after(300,lambda:self.run('snapshot'))

    def label(self,parent,text,**kw):return tk.Label(parent,text=text,bg=parent.cget('bg'),fg=kw.pop('fg',FG),anchor='w',justify='left',**kw)
    def button(self,parent,text,command):
        button=tk.Button(parent,text=text,command=command,bg=BUTTON,fg=FG,activebackground='#68726b',activeforeground=FG,relief='flat',bd=0)
        self.controls.append(button);return button
    def table(self,parent,columns):
        frame=tk.Frame(parent,bg=BG);frame.pack(fill='both',expand=True)
        tree=ttk.Treeview(frame,columns=[c[0] for c in columns],show='headings',selectmode='browse',height=5)
        for key,title,width in columns:tree.heading(key,text=title);tree.column(key,width=width,minwidth=45,stretch=False)
        vertical=ttk.Scrollbar(frame,orient='vertical',command=tree.yview);horizontal=ttk.Scrollbar(frame,orient='horizontal',command=tree.xview)
        tree.configure(yscrollcommand=vertical.set,xscrollcommand=horizontal.set)
        tree.grid(row=0,column=0,sticky='nsew');vertical.grid(row=0,column=1,sticky='ns');horizontal.grid(row=1,column=0,sticky='ew')
        frame.rowconfigure(0,weight=1);frame.columnconfigure(0,weight=1);return tree
    def selected_license(self):
        values=self.licenses.selection();return values[0] if values else None
    def selected_device(self):
        values=self.devices.selection();return values[0] if values else None
    def license_row(self):return next((row for row in (self.snapshot or {}).get('licenses',[]) if row.get('id')==self.selected_license()),None)
    def device_row(self):return next((row for row in (self.license_row() or {}).get('devices',[]) if row.get('id')==self.selected_device()),None)
    def sync_rows(self,tree,rows):
        desired={identifier for identifier,_ in rows}
        for old in tree.get_children():
            if old not in desired:tree.delete(old)
        for identifier,values in rows:
            if tree.exists(identifier):tree.item(identifier,values=values)
            else:tree.insert('',tk.END,iid=identifier,values=values)
    def render(self,data):
        validate_snapshot(data)
        self.snapshot=data;self.received_at=time.monotonic();self.source_error=''
        self.summary.configure(text=snapshot_summary(data));self.render_nodes();self.render_licenses()
        actions={'create':'创建激活码','revoke-device':'解绑设备','disable-code':'停用激活码','note-license':'修改码备注','note-device':'修改设备备注'}
        lines=[f'{time_text(event.get("time"))}  {actions.get(event.get("action"),event.get("action",""))}  {event.get("target","")}' for event in data.get('events',[])[-30:]]
        self.events.configure(state='normal');self.events.delete('1.0',tk.END);self.events.insert('1.0','\n'.join(reversed(lines)) or '暂无管理记录');self.events.configure(state='disabled')
        self.update_status()
    def render_nodes(self):
        rows=[(node['id'],node_values(node)) for node in (self.snapshot or {}).get('nodes',[])]
        self.sync_rows(self.nodes,rows)
    def render_licenses(self):
        if self.snapshot is None:return
        query=self.search.get().strip().lower();rows=[]
        for item in self.snapshot.get('licenses',[]):
            if query and query not in (item.get('id','')+' '+item.get('note','')).lower():continue
            count=item.get('device_count');count=str(count) if type(count) is int and 0<=count<=2 else '—'
            rows.append((item['id'],(item['id'],item.get('note',''),'已停用' if item.get('disabled') else '启用',count+'/2',time_text(item.get('created')))))
        self.sync_rows(self.licenses,rows)
        if not self.licenses.selection() and rows:self.licenses.selection_set(rows[0][0])
        self.render_devices()
    def render_devices(self):
        row=self.license_row();self.sync_rows(self.devices,[(d['id'],device_values(d)) for d in (row or {}).get('devices',[])])
        self.device_title.configure(text='绑定设备 · '+(row.get('note') or row['id']) if row else '绑定设备 · 请选择左侧激活码')
        self.render_details()
    def render_details(self):
        row=self.device_row()
        self.details.configure(text=(f'设备：{row["id"]}\n公钥指纹：{row.get("fingerprint","—")}\n备注：{row.get("note","")}' if row else '上下行按设备视角；数值来自服务器实际转发字节。'))
    def update_status(self):
        sampled=(self.snapshot or {}).get('sampled_at')
        stale=self.snapshot is not None and (time.monotonic()-self.received_at>15 or not numeric(sampled) or not -5<=time.time()-sampled<=15)
        if self.busy:
            if stale:self.status.configure(text='正在操作 · 表格采样陈旧，请勿当作实时状态',fg=WARN)
            return
        if self.source_error:text=self.source_error+'（表格保留旧数据）' if self.snapshot else self.source_error;color=WARN
        elif stale:text='采样陈旧或时钟不一致，请检查连接和时间';color=WARN
        elif self.snapshot:
            text='已连接 · 采样 '+time_text(self.snapshot.get('sampled_at'));color=GREEN
        else:text='尚未连接：请先检查连接设置';color=WARN
        self.status.configure(text=text,fg=color)
    def run(self,action,identifier=None,note=None):
        if self.busy or self.preview or self.closed:return
        self.busy=True;self.status.configure(text='正在读取…' if action=='snapshot' else '正在执行，请勿重复操作…',fg=MUTED)
        self.set_controls(False);client=AdminClient(self.settings)
        def worker():
            try:self.queue.put(('success',action,client.call(action,identifier,note)))
            except AdminError as error:self.queue.put(('failure',action,str(error)))
            except Exception:self.queue.put(('failure',action,'管理响应处理失败，请先刷新确认服务器状态。'))
        threading.Thread(target=worker,daemon=True).start()
    def set_controls(self,enabled):
        for button in self.controls:
            if button.winfo_exists():button.configure(state='normal' if enabled else 'disabled')
    def drain(self):
        if self.closed:return
        previous=self.snapshot;previous_received=self.received_at
        try:
            while True:
                kind,action,value=self.queue.get_nowait();self.busy=False;self.set_controls(True)
                self.next_refresh=time.monotonic()+5
                if kind=='failure':
                    self.source_error=value;self.update_status()
                    if action!='snapshot':self.root.after(0,lambda v=value:messagebox.showerror('操作未确认',v,parent=self.root))
                elif action=='snapshot':self.render(value)
                else:
                    if action=='create':self.root.after(0,lambda v=value:self.show_created(v))
                    self.source_error='';self.next_refresh=0
        except queue.Empty:pass
        except Exception:
            self.snapshot=previous;self.received_at=previous_received
            if previous is not None:
                try:self.summary.configure(text=snapshot_summary(previous));self.render_licenses()
                except Exception:pass
            self.busy=False;self.set_controls(True)
            self.source_error='运营数据处理失败，请刷新重试。'
        finally:
            if not self.closed:self.timer=self.root.after(150,self.drain)
        if not self.busy and not self.preview and time.monotonic()>=self.next_refresh:self.run('snapshot')
        self.update_status()
    def create_code(self):
        if messagebox.askyesno('创建激活码','创建一个新的激活码，允许绑定 2 台设备、默认不过期。继续吗？',parent=self.root):self.run('create')
    def show_created(self,result):
        dialog=tk.Toplevel(self.root);dialog.title('激活码已创建');dialog.configure(bg=BG);dialog.resizable(False,False);dialog.transient(self.root)
        self.label(dialog,'新激活码（仅此处显示，不自动保存）',fg=GREEN).pack(padx=20,pady=(18,8))
        value=tk.StringVar(value=result['code']);entry=tk.Entry(dialog,textvariable=value,width=43,readonlybackground=BUTTON,fg=FG,state='readonly',relief='flat');entry.pack(padx=20,pady=8)
        self.label(dialog,'码 ID：'+result['license_id']+'\n请妥善保存后关闭；丢失不能从服务器还原。',fg=MUTED).pack(padx=20,pady=8)
        def copy():self.root.clipboard_clear();self.root.clipboard_append(value.get())
        self.button(dialog,'复制激活码',copy).pack(fill='x',padx=20,pady=(5,18),ipady=5)
        def close():value.set('');dialog.destroy()
        dialog.protocol('WM_DELETE_WINDOW',close)
    def disable_code(self):
        row=self.license_row()
        if not row:return
        if row.get('disabled'):messagebox.showinfo('已停用','此激活码已停用。',parent=self.root);return
        if messagebox.askyesno('停用激活码',f'停用 {row["id"]}？\n备注：{row.get("note","")}\n该码所有设备将失去权限，计量入口的连接会被关闭。此版本不支持恢复停用码。',parent=self.root):self.run('disable-code',row['id'])
    def revoke_device(self):
        row=self.device_row()
        if not row:return
        if row.get('revoked'):messagebox.showinfo('已解绑','该设备已解绑。',parent=self.root);return
        if messagebox.askyesno('解绑设备',f'解绑设备 {row["id"]}？\n备注：{row.get("note","")}\n会关闭该设备的计量连接并释放一个名额。旧凭据不可再激活。',parent=self.root):self.run('revoke-device',row['id'])
    def edit_note(self,kind):
        row=self.license_row() if kind=='license' else self.device_row()
        if not row:return
        dialog=tk.Toplevel(self.root);dialog.title('修改备注');dialog.configure(bg=BG);dialog.transient(self.root);dialog.resizable(False,False)
        self.label(dialog,row['id']+' · 最多 500 字').pack(padx=15,pady=12)
        editor=tk.Text(dialog,height=5,width=48,bg=BUTTON,fg=FG,insertbackground=FG,relief='flat');editor.pack(padx=15);editor.insert('1.0',row.get('note',''))
        def save():
            note=editor.get('1.0','end-1c')
            if len(note)>500:messagebox.showerror('备注过长','最多 500 个字符。',parent=dialog);return
            if self.busy:return
            self.run('note-'+kind,row['id'],note);dialog.destroy()
        self.button(dialog,'保存到服务器',save).pack(fill='x',padx=15,pady=12,ipady=5)
    def connection_dialog(self):
        dialog=tk.Toplevel(self.root);dialog.title('管理员连接设置');dialog.configure(bg=BG);dialog.transient(self.root);dialog.resizable(False,False)
        fields={}
        for index,(key,title) in enumerate((('host','服务器'),('port','管理 SSH 端口'),('username','管理用户名'),('private_key','管理员私钥'),('known_hosts','服务器公钥文件'))):
            self.label(dialog,title).grid(row=index,column=0,padx=12,pady=8,sticky='w')
            entry=tk.Entry(dialog,width=55,bg=BUTTON,fg=FG,insertbackground=FG,relief='flat');entry.insert(0,str(getattr(self.settings,key)));entry.grid(row=index,column=1,padx=8,pady=8);fields[key]=entry
            if key in ('private_key','known_hosts'):
                def browse(target=entry):
                    file=filedialog.askopenfilename(parent=dialog)
                    if file:target.delete(0,tk.END);target.insert(0,file)
                self.button(dialog,'选择',browse).grid(row=index,column=2,padx=8)
        self.label(dialog,'只保存文件路径，不复制或修改私钥。服务器公钥必须事先通过可信渠道核对。',fg=MUTED).grid(row=5,column=0,columnspan=3,padx=12,pady=10)
        def save():
            try:
                values={key:entry.get().strip() for key,entry in fields.items()};values['port']=int(values['port'])
                settings=Settings(**values).validate();settings.save(self.settings_path);self.settings=settings
            except (ValueError,OSError,AdminError) as error:messagebox.showerror('设置未保存',str(error),parent=dialog);return
            dialog.destroy();self.next_refresh=0
        self.button(dialog,'保存并连接',save).grid(row=6,column=0,columnspan=3,padx=12,pady=12,sticky='ew')
    def close(self):
        if self.busy and not messagebox.askyesno('管理操作进行中','关闭窗口不会撤销已发出的操作。确定退出吗？下次打开请先刷新确认结果。',parent=self.root):return
        self.closed=True;self.root.after_cancel(self.timer);self.root.destroy()
