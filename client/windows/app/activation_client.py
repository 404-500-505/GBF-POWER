"""Device-owned credentials and certificate-pinned enrollment; no shared secret."""
import base64
import hashlib
import hmac
import http.client
import json
import os
from pathlib import Path
import re
import secrets
import ssl
import time
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey,Ed25519PublicKey
from client_runtime import BASE,load,save

MESSAGES={
    'device_limit':'这个激活码已绑定 2 台设备，请联系管理员解绑旧设备。',
    'invalid_code':'激活码无效，请检查后重试。',
    'revoked':'此设备或激活码已停用，请联系管理员。',
    'invalid_request':'验证未通过，请检查电脑日期和时间后重试。',
    'rate_limited':'操作过于频繁，请稍后再试。',
    'unavailable':'暂时无法连接激活服务，请稍后重试。',
    'pin_mismatch':'无法确认激活服务身份，已停止连接，请联系管理员更新客户端。',
    'not_activated':'请先输入激活码激活这台设备。',
    'invalid_response':'激活服务返回的配置无效，原配置未更改。',
    'local_storage':'无法保存或读取本机设备凭据，请检查数据目录权限后重试。',
}
class ActivationError(RuntimeError):
    def __init__(self,code):
        self.code=code if code in MESSAGES else 'unavailable'
        super().__init__(MESSAGES[self.code])

def bootstrap():
    try:
        result=load(BASE/'assets/activation.local.json')
        if not re.fullmatch(r'[a-zA-Z0-9.-]+',result['host']):raise ValueError()
        if not 1<=int(result['port'])<=65535:raise ValueError()
        if not re.fullmatch(r'[0-9a-fA-F]{64}',result['certificate_sha256']):raise ValueError()
        return result
    except (OSError,ValueError,KeyError,TypeError):raise ActivationError('unavailable') from None

def signed_request(key,operation,code=None):
    public=key.public_key().public_bytes(serialization.Encoding.OpenSSH,serialization.PublicFormat.OpenSSH).decode('ascii')
    request={'public_key':public,'timestamp':int(time.time()),'nonce':secrets.token_urlsafe(24)}
    fields=['GBF-'+operation.upper()+'-V1']
    if operation=='activate':request['code']=code;fields.append(code)
    fields.extend([public,str(request['timestamp']),request['nonce']])
    request['signature']=base64.b64encode(key.sign('\n'.join(fields).encode('ascii'))).decode('ascii')
    return request

LEGACY_NODE_IDS=('tokyo','osaka')
NODE_IDS=('tokyo','tokyo_cn2','osaka')
V2_LINE_LABELS={'auto':'自动选择','tokyo':'日本・东京','osaka':'日本・大阪'}
LINE_LABELS={'auto':'自动选择','tokyo':'日本・东京','tokyo_cn2':'日本・东京 CN2','osaka':'日本・大阪'}

def normalize_quality(value,node_ids=NODE_IDS):
    result={}
    value=value if isinstance(value,dict) else {}
    for node_id in node_ids:
        item=value.get(node_id,{}) if isinstance(value.get(node_id,{}),dict) else {}
        p95=item.get('p95_ms',0);timeouts=item.get('consecutive_timeouts',0)
        if type(p95) is not int or not 0<=p95<=60000:p95=0
        if type(timeouts) is not int or not 0<=timeouts<=100:timeouts=0
        result[node_id]={'p95_ms':p95,'consecutive_timeouts':timeouts}
    return result

def signed_request_v2(key,operation,code=None,preference='auto',quality=None):
    if preference not in V2_LINE_LABELS:raise ValueError('invalid line preference')
    quality=normalize_quality(quality,LEGACY_NODE_IDS)
    public=key.public_key().public_bytes(serialization.Encoding.OpenSSH,serialization.PublicFormat.OpenSSH).decode('ascii')
    request={'public_key':public,'timestamp':int(time.time()),'nonce':secrets.token_urlsafe(24),
             'preference':preference,'quality':quality}
    fields=['GBF-'+operation.upper()+'-V2',code or '',public,str(request['timestamp']),request['nonce'],preference]
    for node_id in LEGACY_NODE_IDS:
        fields.extend([str(quality[node_id]['p95_ms']),str(quality[node_id]['consecutive_timeouts'])])
    if operation=='activate':request['code']=code
    request['signature']=base64.b64encode(key.sign('\n'.join(fields).encode('ascii'))).decode('ascii')
    return request

def signed_request_v3(key,operation,code=None,preference='auto',quality=None):
    if preference not in LINE_LABELS:raise ValueError('invalid line preference')
    quality=normalize_quality(quality)
    public=key.public_key().public_bytes(serialization.Encoding.OpenSSH,serialization.PublicFormat.OpenSSH).decode('ascii')
    request={'public_key':public,'timestamp':int(time.time()),'nonce':secrets.token_urlsafe(24),
             'preference':preference,'quality':quality}
    fields=['GBF-'+operation.upper()+'-V3',code or '',public,str(request['timestamp']),request['nonce'],preference]
    for node_id in NODE_IDS:
        fields.extend([str(quality[node_id]['p95_ms']),str(quality[node_id]['consecutive_timeouts'])])
    if operation=='activate':request['code']=code
    request['signature']=base64.b64encode(key.sign('\n'.join(fields).encode('ascii'))).decode('ascii')
    return request

def post(service,path,request):
    # Pin authentication replaces public-PKI authentication for this private
    # service. Never transmit a request until the connected certificate matches.
    context=ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname=False;context.verify_mode=ssl.CERT_NONE
    context.minimum_version=ssl.TLSVersion.TLSv1_2
    connection=http.client.HTTPSConnection(service['host'],service['port'],context=context,timeout=12)
    try:
        connection.connect()
        digest=hashlib.sha256(connection.sock.getpeercert(binary_form=True)).hexdigest()
        if not hmac.compare_digest(digest,service['certificate_sha256'].lower()):raise ActivationError('pin_mismatch')
        connection.request('POST',path,json.dumps(request),{'Content-Type':'application/json','Connection':'close'})
        response=connection.getresponse();raw=response.read(8193)
        if len(raw)>8192:raise ActivationError('invalid_response')
        data=json.loads(raw)
        if not isinstance(data,dict):raise ActivationError('invalid_response')
        if response.status!=200:raise ActivationError(data.get('error','unavailable'))
        return data
    except ActivationError:raise
    except (OSError,ValueError,http.client.HTTPException):raise ActivationError('unavailable') from None
    finally:connection.close()

def device_key(root,create=False):
    folder=Path(root)/'runtime/device';path=folder/'id_ed25519'
    if not path.exists():
        if not create:raise ActivationError('not_activated')
        from cache_certificate import protect_directory
        protect_directory(folder)
        key=Ed25519PrivateKey.generate()
        with path.open('xb') as output:
            output.write(key.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.OpenSSH,serialization.NoEncryption()))
            output.flush();os.fsync(output.fileno())
    key=serialization.load_ssh_private_key(path.read_bytes(),password=None)
    if not isinstance(key,Ed25519PrivateKey):raise ActivationError('not_activated')
    return key

def registration(root):
    try:
        value=load(Path(root)/'config.json').get('activation',{})
        return value if value.get('managed') and value.get('device_id') else None
    except (OSError,ValueError):return None

def line_preference(root):
    try:value=load(Path(root)/'config.json').get('activation',{}).get('line_preference','auto')
    except (OSError,ValueError,TypeError):value='auto'
    return value if value in LINE_LABELS else 'auto'

def set_line_preference(root,value):
    if value not in LINE_LABELS:raise ValueError('invalid line preference')
    root=Path(root);config=load(root/'config.json')
    activation=config.setdefault('activation',{})
    activation['line_preference']=value
    save(root/'config.json',config)

def set_node_quality(root,node_id,quality):
    if node_id not in NODE_IDS or not isinstance(quality,dict):raise ValueError('invalid node quality')
    p95=quality.get('p95_ms');timeouts=quality.get('consecutive_timeouts')
    if type(p95) is not int or not 0<=p95<=60000 or type(timeouts) is not int or not 0<=timeouts<=100:raise ValueError('invalid node quality')
    root=Path(root);config=load(root/'config.json');activation=config.get('activation')
    if not isinstance(activation,dict) or not activation.get('managed') or node_id not in activation.get('nodes',{}):raise ValueError('node not enrolled')
    current=normalize_quality(activation.get('node_quality'));current[node_id]={'p95_ms':p95,'consecutive_timeouts':timeouts}
    activation['node_quality']=current;save(root/'config.json',config)

def validate_node(node):
    if not isinstance(node,dict):raise ValueError()
    if not re.fullmatch(r'[a-zA-Z0-9.-]{1,253}',node['host']):raise ValueError()
    if not re.fullmatch(r'[a-zA-Z0-9_-]{1,32}',node['username']):raise ValueError()
    if type(node['port']) is not int or not 1<=node['port']<=65535:raise ValueError()
    host_key=node['host_key']
    public=serialization.load_ssh_public_key(host_key.encode('ascii'))
    if not isinstance(public,Ed25519PublicKey):raise ValueError()
    if public.public_bytes(serialization.Encoding.OpenSSH,serialization.PublicFormat.OpenSSH).decode()!=host_key:raise ValueError()
    return dict(host=node['host'],port=node['port'],username=node['username'],host_key=host_key)

def apply_registration(root,response,preference=None):
    try:
        node=response['node'];device_id=response['device_id'];count=response['device_count']
        if response.get('active') is not True or response['device_limit']!=2:raise ValueError()
        if not isinstance(count,int) or not 1<=count<=2:raise ValueError()
        if not re.fullmatch(r'[a-zA-Z0-9_-]{1,128}',device_id):raise ValueError()
        node=validate_node(node)
        multi='nodes' in response or 'assigned_line' in response or 'available_lines' in response
        if multi:
            node_ids=set(response['nodes'])
            if node_ids==set(LEGACY_NODE_IDS):expected_labels=V2_LINE_LABELS
            elif node_ids==set(NODE_IDS):expected_labels=LINE_LABELS
            else:raise ValueError()
            nodes={node_id:validate_node(value) for node_id,value in response['nodes'].items()}
            assigned=response['assigned_line'];line_id=assigned['id'];label=assigned['label']
            if line_id not in nodes or label!=expected_labels[line_id] or nodes[line_id]!=node:raise ValueError()
            available=response['available_lines']
            if not isinstance(available,list) or [(v.get('id'),v.get('label')) for v in available] != list(expected_labels.items()):raise ValueError()
        else:
            nodes=None;assigned=None
    except (ValueError,TypeError,KeyError,UnicodeError):raise ActivationError('invalid_response') from None
    root=Path(root);config=load(root/'config.json')
    folder=root/'runtime/device';folder.mkdir(parents=True,exist_ok=True)
    hosts=folder/'known_hosts';old_hosts=hosts.read_bytes() if hosts.exists() else None
    pinned=nodes.values() if nodes else (node,)
    host_lines=[]
    for pinned_node in pinned:
        host=pinned_node['host'] if pinned_node['port']==22 else f"[{pinned_node['host']}]:{pinned_node['port']}"
        host_lines.append(host+' '+pinned_node['host_key'])
    try:
        hosts.write_text('\n'.join(sorted(set(host_lines)))+'\n',encoding='ascii')
        current_ssh=config.get('ssh') or {}
        config['ssh']={'host':node['host'],'port':node['port'],'username':node['username'],
                       'socks_port':current_ssh.get('socks_port',18124),
                       'private_key':'runtime/device/id_ed25519','known_hosts':'runtime/device/known_hosts'}
        previous=config.get('activation',{})
        activation={'managed':True,'device_id':device_id,'device_count':count,'device_limit':2}
        if multi:
            selected_preference=preference if preference is not None else previous.get('line_preference','auto')
            if selected_preference not in LINE_LABELS:raise ValueError('invalid line preference')
            activation.update(line_preference=selected_preference,assigned_line=assigned,
                              available_lines=response['available_lines'],nodes=nodes,
                              node_quality=normalize_quality(previous.get('node_quality'),tuple(expected_labels)[1:]))
        config['activation']=activation
        save(root/'config.json',config)
    except BaseException:
        if old_hosts is None:hosts.unlink(missing_ok=True)
        else:hosts.write_bytes(old_hosts)
        raise
    return config['activation']

def activate(root,code):
    code=code.strip().upper()
    if not re.fullmatch(r'GBF-[0-9A-F]{32}',code):raise ActivationError('invalid_code')
    try:
        service=bootstrap();key=device_key(root,create=True);preference=line_preference(root)
        quality=normalize_quality((registration(root) or {}).get('node_quality'))
        response=post(service,'/v3/activate',signed_request_v3(key,'activate',code,preference,quality))
        return apply_registration(root,response,preference)
    except ActivationError:raise
    except (OSError,ValueError):raise ActivationError('local_storage') from None

def check_device(root):
    if not registration(root):raise ActivationError('not_activated')
    enrolled=registration(root);preference=line_preference(root)
    response=post(bootstrap(),'/v3/status',signed_request_v3(device_key(root),'status',None,preference,enrolled.get('node_quality')))
    if response.get('active') is not True:raise ActivationError('revoked')
    return response
