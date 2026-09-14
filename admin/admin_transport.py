"""Owner-only SSH transport. Never bundles, copies or changes a private key."""
import base64
from dataclasses import asdict,dataclass
import json
import os
from pathlib import Path
import re
import subprocess
import math

class AdminError(RuntimeError):pass

def validate_snapshot(data):
    def fail():raise AdminError('运营数据结构无效，保留上次有效数据。')
    def fields(row,strings=(),booleans=(),numbers=()):
        if not isinstance(row,dict):fail()
        for key in strings:
            if key in row and (not isinstance(row[key],str) or '\x00' in row[key]):fail()
        for key in booleans:
            if key in row and type(row[key]) is not bool:fail()
        for key in numbers:
            value=row.get(key)
            if value is not None and (type(value) not in (int,float) or not math.isfinite(value) or value<0):fail()
    fields(data,numbers=('sampled_at',))
    if not isinstance(data.get('server'),dict) or not isinstance(data.get('licenses'),list):fail()
    fields(data['server'],numbers=('cpu_percent','memory_used_bytes','memory_total_bytes','disk_free_bytes','disk_total_bytes','uptime_seconds','service_uptime_seconds','network_rx_bytes','network_tx_bytes'))
    fields(data.get('metering',{}),booleans=('healthy','enabled'),numbers=('last_persisted_at',))
    seen=set();devices=set()
    def identifier(row,known):
        value=row.get('id')
        if not isinstance(value,str) or not re.fullmatch('[a-f0-9]{24}',value) or value in known:fail()
        known.add(value)
    for row in data['licenses']:
        fields(row,strings=('note',),booleans=('disabled',),numbers=('created','device_count'))
        identifier(row,seen)
        if not isinstance(row.get('devices',[]),list):fail()
        for device in row.get('devices',[]):
            fields(device,strings=('note','fingerprint'),booleans=('revoked',),numbers=('created','last_seen','online_sessions','active_connections','upload_bytes','download_bytes','today_upload_bytes','today_download_bytes','upload_bps','download_bps'))
            identifier(device,devices)
    if not isinstance(data.get('events',[]),list):fail()
    for event in data.get('events',[]):fields(event,strings=('action','target'),numbers=('time',))
    nodes=data.get('nodes',[])
    if not isinstance(nodes,list) or len(nodes)>8:fail()
    node_ids=set();allowed={'id','label','healthy','draining','utilization','upload_bps','download_bps','devices','connections','throttled_devices','probe_latency_ms','probe_failures','auth_latency_ms','auth_errors','last_report_at'}
    for node in nodes:
        if not isinstance(node,dict) or set(node)-allowed:fail()
        fields(node,strings=('id','label'),booleans=('healthy','draining'),numbers=('utilization','upload_bps','download_bps','devices','connections','throttled_devices','probe_latency_ms','probe_failures','auth_latency_ms','auth_errors','last_report_at'))
        node_id=node.get('id')
        if node_id not in ('tokyo','tokyo_cn2','osaka') or node_id in node_ids:fail()
        node_ids.add(node_id)
        if node.get('label') != {'tokyo':'日本・东京','tokyo_cn2':'日本・东京 CN2','osaka':'日本・大阪'}[node_id]:fail()
        if node.get('utilization',0)>1 or node.get('throttled_devices',0)>node.get('devices',0):fail()
    return data

def remote_command(action,identifier=None,note=None):
    if action not in ('snapshot','create','list','revoke-device','disable-code','note-license','note-device'):
        raise AdminError('不支持的管理操作。')
    args=['/opt/gbf-activation/gbf-activation','--admin','/var/lib/gbf-activation/admin.sock',action]
    if action in ('revoke-device','disable-code','note-license','note-device'):
        if not isinstance(identifier,str) or not re.fullmatch('[0-9a-f]{24}',identifier):raise AdminError('设备或激活码 ID 无效。')
        args.append(identifier)
    elif identifier is not None:raise AdminError('此操作不接受 ID。')
    if action.startswith('note-'):
        if not isinstance(note,str) or len(note)>500 or '\x00' in note:raise AdminError('备注最多 500 个字符，不能包含空字符。')
        # Empty text must survive the remote shell as an empty CLI argument.
        args.append(base64.b64encode(note.encode('utf-8')).decode('ascii') or "''")
    elif note is not None:raise AdminError('此操作不接受备注。')
    return ' '.join(args)

@dataclass
class Settings:
    host:str='control.example.com'
    port:int=22
    username:str='deploy'
    private_key:str=''
    known_hosts:str=''

    def validate(self):
        if not re.fullmatch(r'[a-zA-Z0-9][a-zA-Z0-9.-]{0,252}',self.host):raise AdminError('管理服务器地址无效。')
        if not re.fullmatch(r'[a-zA-Z0-9_][a-zA-Z0-9_-]{0,31}',self.username):raise AdminError('SSH 管理用户名无效。')
        if type(self.port) is not int or not 1<=self.port<=65535:raise AdminError('SSH 端口无效。')
        for value in (self.private_key,self.known_hosts):
            if not isinstance(value,str) or any(c in value for c in ('\r','\n','\x00','"')):raise AdminError('文件路径无效。')
        return self
    def save(self,path):
        self.validate();path=Path(path);path.parent.mkdir(parents=True,exist_ok=True)
        pending=path.with_suffix('.pending')
        pending.write_text(json.dumps(asdict(self),ensure_ascii=False,indent=2),encoding='utf-8')
        os.replace(pending,path)
    @classmethod
    def load(cls,path):
        try:return cls(**json.loads(Path(path).read_text(encoding='utf-8'))).validate()
        except (OSError,ValueError,TypeError):raise AdminError('无法读取管理连接设置，请重新选择文件。') from None

class AdminClient:
    def __init__(self,settings):self.settings=settings.validate()
    def call(self,action,identifier=None,note=None):
        remote=remote_command(action,identifier,note);s=self.settings
        if not s.private_key or not s.known_hosts:raise AdminError('请在“连接设置”中选择管理员私钥和服务器公钥文件。')
        try:
            for file in (s.private_key,s.known_hosts):
                with open(file,'rb') as stream:stream.read(1)
        except OSError:raise AdminError('无法读取管理员密钥或服务器公钥文件，请检查当前 Windows 账户权限。不要重新生成或公开私钥。') from None
        executable=str(Path(os.environ.get('WINDIR',r'C:\Windows'))/'System32/OpenSSH/ssh.exe')
        args=[executable,'-F','none','-T','-i',s.private_key,'-p',str(s.port),
              '-o','BatchMode=yes','-o','IdentitiesOnly=yes','-o','IdentityAgent=none',
              '-o','StrictHostKeyChecking=yes','-o',f'UserKnownHostsFile="{Path(s.known_hosts).as_posix()}"',
              '-o','ConnectTimeout=8','-o','ServerAliveInterval=5','-o','ServerAliveCountMax=2',
              s.username+'@'+s.host,remote]
        try:
            result=subprocess.run(args,capture_output=True,timeout=25,creationflags=getattr(subprocess,'CREATE_NO_WINDOW',0))
        except subprocess.TimeoutExpired:raise AdminError('连接或管理操作超时。请先刷新列表确认结果，不要重复创建激活码。') from None
        except OSError:raise AdminError('无法启动 Windows OpenSSH 客户端，请检查系统可选功能。') from None
        if result.returncode:
            error=result.stderr.decode('utf-8',errors='replace').lower()
            if 'load key' in error or 'unprotected private key' in error:
                message='管理员私钥无法加载，请检查文件所有者和访问权限。'
            elif 'host key verification failed' in error or 'identification has changed' in error:
                message='服务器身份校验失败，已拒绝连接。请通过可信渠道核对服务器公钥。'
            elif 'permission denied' in error:
                message='服务器拒绝管理员身份，请检查用户名和已授权的私钥。'
            elif 'unknown admin command' in error:
                message='服务器尚未升级运营服务，请先运行部署工具。'
            else:message='管理操作未确认成功，请检查服务状态；创建失败或超时后先刷新列表，避免重复发码。'
            raise AdminError(message)
        if len(result.stdout)>8*1024*1024:raise AdminError('服务器响应过大，已停止加载。')
        try:data=json.loads(result.stdout)
        except (ValueError,UnicodeError):raise AdminError('服务器返回的管理数据格式无效。') from None
        if action=='create':
            if not isinstance(data,dict) or not re.fullmatch('GBF-[A-F0-9]{32}',data.get('code','')) or not re.fullmatch('[a-f0-9]{24}',data.get('license_id','')):
                raise AdminError('服务器未返回可验证的激活码。请先刷新列表确认创建结果。')
        elif action=='snapshot':
            validate_snapshot(data)
        elif action!='list' and (not isinstance(data,dict) or data.get('ok') is not True):raise AdminError('服务器未确认此次修改。')
        return data
