"""Desktop controller. Private data stays in the explicitly selected profile."""
import ctypes
import hashlib
import json
import msvcrt
import os
from pathlib import Path
import socket
import subprocess
import sys
import threading
import time
import uuid
import urllib.request

BASE=Path(__file__).resolve().parent
if not getattr(sys,'frozen',False):sys.path.insert(0,str(BASE.parent/'proxy_core'))
from win_job import Job
from monitor import read_status

def default_config():
    return dict(port=8123,connect_timeout_seconds=15,idle_timeout_seconds=300,max_connections=256,
        routing_profile_version=2,
        ssh=None,
        cache=dict(enabled=False,legacy_directory=None,max_bytes=5*1024**3,max_item_bytes=16*1024**2),
        game_channel=dict(enabled=True,socks_port=18125))

def normalize_acgp_cache_directory(folder):
    """Resolve a user-selected ACGP cache/cache-gbf/https/assets level."""
    selected=Path(folder).resolve()
    if selected.name.casefold()=='assets' and selected.parent.name.casefold()=='https':
        return selected.parent.parent.resolve()
    candidates=[selected,selected/'gbf',selected/'cache/gbf']
    if selected.name.casefold()=='https':candidates.append(selected.parent)
    for candidate in candidates:
        if (candidate/'https/assets').is_dir():return candidate.resolve()
    checked='；'.join(str(candidate/'https/assets') for candidate in candidates)
    raise ValueError(f'所选目录中没有可识别的 ACGP cache/gbf/https/assets 结构。\n'
                     f'实际选择：{selected}\n已检查：{checked}')

def load(path):
    return json.loads(Path(path).read_text(encoding='utf-8-sig'))

def save(path,value):
    path=Path(path);pending=path.with_suffix(path.suffix+'.pending')
    pending.write_text(json.dumps(value,ensure_ascii=False,indent=2),encoding='utf-8')
    os.replace(pending,path)

def same_instance(status,state,port):
    return bool(status and state and status.get('app')=='gbf-local-proxy' and
                status.get('instance') and state.get('instance')==status['instance'] and
                state.get('port')==port and state.get('app')=='gbf-local-proxy')

def acceleration_ready(status):
    if not status:return False
    if status.get('mode')!='ssh':return True
    if not (status.get('tunnel') or {}).get('connected'):return False
    battle=status.get('game_channel') or {}
    return not battle.get('enabled') or bool(battle.get('connected'))

def ports_free(ports):
    probes=[]
    try:
        for port in set(ports):
            s=socket.socket();probes.append(s)
            s.setsockopt(socket.SOL_SOCKET,socket.SO_EXCLUSIVEADDRUSE,1)
            s.bind(('127.0.0.1',port))
        return True
    except OSError:return False
    finally:
        for s in probes:s.close()

def entry_command():
    return [sys.executable] if getattr(sys,'frozen',False) else [sys.executable,str(BASE/'app.py')]

class Manager:
    def __init__(self,root,allow_direct=False):
        self.root=Path(root).resolve();self.allow_direct=allow_direct
        self.process=None;self.job=None;self.log=None;self.lock=None
        self.auth_checked_at=0
        self.operation=threading.Lock()
    def config(self):return load(self.root/'config.json')
    def ports(self):
        c=self.config();p=[c['port']]
        if c.get('ssh'):p.append(c['ssh']['socks_port'])
        if c.get('game_channel',{}).get('enabled'):p.append(c['game_channel']['socks_port'])
        return p
    def state(self):
        try:return load(self.root/'runtime/state.json')
        except (OSError,ValueError):return None
    def owned_status(self):
        port=self.config()['port'];s=read_status(port)
        return s if same_instance(s,self.state(),port) else None
    def acquire(self):
        if self.lock:return
        (self.root/'runtime').mkdir(exist_ok=True)
        f=(self.root/'runtime/desktop.lock').open('a+b')
        try:
            if f.tell()==0:f.write(b'0');f.flush()
            f.seek(0);msvcrt.locking(f.fileno(),msvcrt.LK_NBLCK,1)
        except OSError:
            f.close();raise RuntimeError('另一客户端正在使用此配置，请回到已打开的窗口。')
        self.lock=f
    def start(self):
        with self.operation:
            self.acquire()
            c=self.config();s=self.owned_status()
            if s:
                if not acceleration_ready(s):
                    raise RuntimeError('加速通道正在重连，请等待或先停止；未启动重复进程。')
                return
            if c.get('activation',{}).get('managed'):
                from activation_client import check_device,apply_registration
                response=check_device(self.root)
                apply_registration(self.root,response)
                c=self.config()
                self.auth_checked_at=time.monotonic()
            if not ports_free(self.ports()):raise RuntimeError('代理或 SSH 端口被占用。请先关闭旧版或 ACG POWER；不会终止其他程序。')
            if not c.get('ssh') and not self.allow_direct:raise RuntimeError('尚未配置日本节点。')
            if c.get('ssh'):
                for field in ('private_key','known_hosts'):
                    if not (self.root/c['ssh'][field]).is_file():
                        raise RuntimeError('尚未配置 SSH 密钥／服务器公钥，请打开“设置”。')
            self._close_handles()
            self.job=Job()
            self.log=(self.root/'runtime/desktop-engine.log').open('w',encoding='utf-8')
            gate=self.root/'runtime'/('start-'+uuid.uuid4().hex+'.gate')
            try:
                self.process=subprocess.Popen(entry_command()+['--engine',str(self.root),'--gate',gate.name],
                    stdin=subprocess.DEVNULL,stdout=self.log,stderr=self.log,
                    creationflags=subprocess.CREATE_NO_WINDOW,cwd=str(self.root))
                try:self.job.assign(self.process)
                except BaseException:
                    self.process.terminate();self.process.wait(timeout=5);raise
                gate.touch(exist_ok=False)
                due=time.monotonic()+30
                while time.monotonic()<due:
                    if self.process.poll() is not None:raise RuntimeError('启动失败，详细信息在 runtime/desktop-engine.log。请检查 SSH 授权和证书。')
                    s=self.owned_status()
                    if acceleration_ready(s):return
                    time.sleep(.12)
                raise RuntimeError('启动超过 30 秒，已回收本次进程。请检查节点连接和 SSH 授权。')
            except BaseException:
                self._close_handles();raise
            finally:gate.unlink(missing_ok=True)
    def _close_handles(self):
        if self.job:self.job.close();self.job=None
        if self.process:
            try:self.process.wait(timeout=5)
            except subprocess.TimeoutExpired:raise RuntimeError('自有进程尚未退出，请稍后再试。')
            self.process=None
        if self.log:self.log.close();self.log=None
    def stop(self):
        with self.operation:
            s=self.owned_status();state=self.state()
            if not s and self.process is None:
                # A foreign listener must not prevent closing an idle client.
                return
            if s and state:
                req=urllib.request.Request(f"http://127.0.0.1:{self.config()['port']}/_control/stop",data=b'',
                      headers={'X-Stop-Token':state['stop_token']},method='POST')
                opener=urllib.request.build_opener(urllib.request.ProxyHandler({}))
                try:
                    with opener.open(req,timeout=3) as response:response.read(1024)
                except OSError:pass
                due=time.monotonic()+15
                while time.monotonic()<due and not ports_free(self.ports()):time.sleep(.1)
            self._close_handles()
            due=time.monotonic()+3
            while time.monotonic()<due and not ports_free(self.ports()):time.sleep(.1)
            if not ports_free(self.ports()):
                raise RuntimeError('端口仍被其他或旧版进程占用。没有强制终止不属于本客户端的进程。')
            if state and self.state()==state:
                (self.root/'runtime/state.json').unlink(missing_ok=True)
    def dispose(self):
        self._close_handles()
        if self.lock:self.lock.close();self.lock=None

def trusted(info):
    import ssl
    return any(hashlib.sha1(cert).hexdigest().upper()==info['thumbprint']
               for cert,encoding,_ in ssl.enum_certificates('ROOT') if encoding=='x509_asn')

def cert_status(root):
    from cache_certificate import certificate_info
    try:
        info=certificate_info(Path(root)/'runtime/cache-tls');info['trusted']=trusted(info);return info
    except (OSError,ValueError):return None

def cert_command(action,value):
    args=['certutil.exe','-user']+(['-addstore','Root',str(value)] if action=='add' else ['-delstore','Root',str(value)])
    p=subprocess.run(args,capture_output=True,timeout=30,creationflags=subprocess.CREATE_NO_WINDOW)
    if p.returncode:raise RuntimeError('Windows 证书操作未完成，未确认生效。')

def set_cache(manager,enabled):
    from datetime import datetime,timezone
    from cache_certificate import prepare_certificate
    # The UI must obtain consent before calling this function.
    was_running=bool(manager.owned_status())
    previous=manager.config();info=None;added=False
    old=cert_status(manager.root)
    record=manager.root/'runtime/desktop-trust.json'
    old_record=record.read_bytes() if record.exists() else None
    manager.stop()
    try:
        if enabled:
            info=prepare_certificate(manager.root/'runtime/cache-tls')
            if datetime.fromisoformat(info['expires'])<=datetime.now(timezone.utc):
                raise RuntimeError('证书已过期，请用“更新证书”重新生成。')
            if not trusted(info):
                cert_command('add',manager.root/'runtime/cache-tls/ca.pem');added=True
                save(manager.root/'runtime/desktop-trust.json',{'thumbprint':info['thumbprint']})
            if not trusted(info):raise RuntimeError('证书信任未生效。')
        c=json.loads(json.dumps(previous));c['cache']['enabled']=enabled;save(manager.root/'config.json',c)
        if was_running:manager.start()
        if not enabled:
            info=cert_status(manager.root)
            if info and info['trusted']:cert_command('remove',info['thumbprint'])
    except BaseException:
        manager.stop()
        save(manager.root/'config.json',previous)
        if added and info:cert_command('remove',info['thumbprint'])
        if old and old['trusted'] and not trusted(old):cert_command('add',manager.root/'runtime/cache-tls/ca.pem')
        if old_record is None:record.unlink(missing_ok=True)
        else:record.write_bytes(old_record)
        if was_running:manager.start()
        raise

def initialize(root,assets):
    root=Path(root);root.mkdir(parents=True,exist_ok=True)
    config_path=root/'config.json'
    if not config_path.exists():
        save(config_path,default_config())
    else:
        config=load(config_path)
        if config.get('routing_profile_version',0)<2:
            channel=config.setdefault('game_channel',{})
            channel['enabled']=True
            channel.setdefault('socks_port',18125)
            config['routing_profile_version']=2
            save(config_path,config)
    if not (root/'rules.json').exists():
        rules_source=Path(assets)/'rules.json'
        if not rules_source.is_file() and not getattr(sys,'frozen',False):
            rules_source=BASE.parent/'proxy_core'/'rules.json'
        (root/'rules.json').write_bytes(rules_source.read_bytes())
    (root/'runtime').mkdir(exist_ok=True)

def generate_key(root):
    from cache_certificate import protect_directory
    folder=Path(root)/'runtime/ssh';protect_directory(folder)
    key=folder/'id_ed25519'
    if key.exists():raise RuntimeError('密钥已存在，不会覆盖。可复制现有公钥。')
    p=subprocess.run(['ssh-keygen.exe','-q','-t','ed25519','-N','','-C','gbf-desktop-device','-f',str(key)],
                     capture_output=True,timeout=15,creationflags=subprocess.CREATE_NO_WINDOW)
    if p.returncode:raise RuntimeError('生成密钥失败，请检查 Windows OpenSSH 客户端。')
    return key.with_suffix('.pub').read_text().strip()

def renew_certificate(manager):
    from cache_certificate import prepare_certificate
    running=bool(manager.owned_status())
    old=cert_status(manager.root);directory=manager.root/'runtime/cache-tls'
    backup=manager.root/'runtime'/('cache-tls-backup-'+uuid.uuid4().hex)
    previous=manager.config()
    record=manager.root/'runtime/desktop-trust.json'
    old_record=record.read_bytes() if record.exists() else None
    new=None;backup_moved=False;preparing=False
    manager.stop()
    try:
        if directory.exists():directory.rename(backup);backup_moved=True
        preparing=True
        new=prepare_certificate(directory)
        cert_command('add',directory/'ca.pem')
        if not trusted(new):raise RuntimeError('新证书信任未生效。')
        c=json.loads(json.dumps(previous));c['cache']['enabled']=True;save(manager.root/'config.json',c)
        if running:manager.start()
        if old and old['trusted']:cert_command('remove',old['thumbprint'])
        save(manager.root/'runtime/desktop-trust.json',{'thumbprint':new['thumbprint']})
    except BaseException:
        manager.stop()
        if new and trusted(new):cert_command('remove',new['thumbprint'])
        if preparing and directory.exists():directory.rename(manager.root/'runtime'/('certificate-failed-'+uuid.uuid4().hex))
        if backup_moved:backup.rename(directory)
        save(manager.root/'config.json',previous)
        if old and old['trusted'] and not trusted(old):cert_command('add',directory/'ca.pem')
        if old_record is None:record.unlink(missing_ok=True)
        else:record.write_bytes(old_record)
        if running:manager.start()
        raise

def uninstall_trust(root):
    root=Path(root);record=root/'runtime/desktop-trust.json'
    if not record.is_file():return
    info=cert_status(root)
    if info and info['thumbprint']==load(record).get('thumbprint') and info['trusted']:
        cert_command('remove',info['thumbprint'])
    record.unlink(missing_ok=True)
