"""Presentation for server-owned metrics; unavailable is never zero."""
from datetime import datetime,timezone,timedelta
import math

def numeric(value):return isinstance(value,(int,float)) and not isinstance(value,bool) and math.isfinite(value) and value>=0
def byte_count(value):
    if not numeric(value):return '—'
    for unit in ('B','KiB','MiB','GiB','TiB'):
        if value<1024 or unit=='TiB':return f'{int(value)} B' if unit=='B' else f'{value:.2f} {unit}'
        value/=1024
def rate(value):return '—' if not numeric(value) else byte_count(value)+'/s'
def bitrate(value):
    if not numeric(value):return '—'
    for unit,scale in (('Gbps',1_000_000_000),('Mbps',1_000_000),('Kbps',1_000)):
        if value>=scale:return f'{value/scale:.2f} {unit}'
    return f'{int(value)} bps'
def time_text(value):
    if not numeric(value) or value==0:return '—'
    try:return datetime.fromtimestamp(value,timezone(timedelta(hours=8))).strftime('%Y-%m-%d %H:%M:%S')
    except (ValueError,OSError,OverflowError):return '—'
def duration(value):
    if not numeric(value):return '—'
    minutes=int(value)//60
    return f'{minutes//1440}天 {minutes//60%24}时 {minutes%60}分'
def device_values(d):
    sessions=d.get('online_sessions');active=d.get('active_connections');revoked=d.get('revoked') is True
    known=numeric(sessions) or numeric(active);online=(numeric(sessions) and sessions>0) or (numeric(active) and active>0)
    status='已解绑' if revoked else ('未知' if not known else ('在线' if online else '离线'))
    return (d.get('id',''),status,d.get('note',''),time_text(d.get('created')),time_text(d.get('last_seen')),
            str(sessions) if numeric(sessions) else '—',str(active) if numeric(active) else '—',rate(d.get('upload_bps')),rate(d.get('download_bps')),
            byte_count(d.get('today_upload_bytes')),byte_count(d.get('today_download_bytes')),
            byte_count(d.get('upload_bytes')),byte_count(d.get('download_bytes')),d.get('fingerprint','—'))
def snapshot_summary(data):
    server=data.get('server') or {};meter=data.get('metering') or {}
    state=('正常' if meter.get('healthy') is True else '异常') if meter.get('enabled') else '未启用'
    cpu=server.get('cpu_percent');cpu=f'{cpu:.1f}%' if numeric(cpu) else '—'
    return (f'计量入口 {state}    CPU {cpu}    内存 {byte_count(server.get("memory_used_bytes"))} / {byte_count(server.get("memory_total_bytes"))}\n'
            f'磁盘剩余 {byte_count(server.get("disk_free_bytes"))} / {byte_count(server.get("disk_total_bytes"))}    系统运行 {duration(server.get("uptime_seconds"))}    服务运行 {duration(server.get("service_uptime_seconds"))}\n'
            f'网卡累计收 {byte_count(server.get("network_rx_bytes"))} / 发 {byte_count(server.get("network_tx_bytes"))}    计量落盘 {time_text(meter.get("last_persisted_at"))}')

def node_values(node):
    healthy=node.get('healthy');draining=node.get('draining') is True
    state='维护' if draining else ('正常' if healthy is True else '异常')
    utilization=node.get('utilization');load=f'{utilization*100:.1f}%' if numeric(utilization) else '—'
    latency=node.get('probe_latency_ms');latency=f'{latency:.0f} ms' if numeric(latency) else '—'
    return (node.get('label',''),state,load,bitrate(node.get('upload_bps')),bitrate(node.get('download_bps')),
            str(node.get('devices')) if numeric(node.get('devices')) else '—',str(node.get('connections')) if numeric(node.get('connections')) else '—',
            str(node.get('throttled_devices')) if numeric(node.get('throttled_devices')) else '—',latency,time_text(node.get('last_report_at')))
