"""Loopback-only HTTP CONNECT / SOCKS5 proxy and GBF PAC service.

Direct egress or an authenticated SSH Japan exit, with optional GBF CDN asset cache.
Python 3.11+. Optional cache uses h11 and cryptography.
"""
from __future__ import annotations

import argparse
import asyncio
import hashlib
import ipaddress
import json
import logging
from logging.handlers import RotatingFileHandler
import os
from pathlib import Path
import re
import secrets
import socket
import struct
import time
from html import escape
from urllib.parse import urlsplit

from ssh_tunnel import SshTunnel, open_socks
from game_channel import GAME_HOSTS, game_channel_config, is_battle_target

ROOT = Path(__file__).resolve().parent
APP = 'gbf-local-proxy'
VERSION = '0.4.5'
HEADER_LIMIT = 65536
LOG = logging.getLogger(APP)
REASONS = {200: 'OK', 400: 'Bad Request', 403: 'Forbidden', 404: 'Not Found',
           405: 'Method Not Allowed', 408: 'Request Timeout',
           431: 'Request Header Fields Too Large', 502: 'Bad Gateway', 503: 'Service Unavailable'}


async def start_tunnels(*tunnels):
    tasks = [asyncio.create_task(tunnel.start()) for tunnel in tunnels if tunnel]
    try:
        await asyncio.gather(*tasks)
    except BaseException:
        for task in tasks:
            if not task.done():
                task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        raise


async def close_resources(*resources):
    active = [resource for resource in resources if resource]
    results = await asyncio.gather(*(resource.close() for resource in active), return_exceptions=True)
    for result in results:
        if isinstance(result, BaseException):
            LOG.error('Resource cleanup failed', exc_info=(type(result), result, result.__traceback__))


class HTTPError(Exception):
    def __init__(self, status, message):
        self.status, self.message = status, message


def load_rules(path=ROOT / 'rules.json'):
    rules = json.loads(Path(path).read_text(encoding='utf-8-sig'))
    for key in ('domain_suffixes', 'exact_hosts', 'socks5_hosts'):
        if not isinstance(rules.get(key), list):
            raise ValueError(f'{key} must be a list')
        clean = []
        for host in rules[key]:
            if not isinstance(host, str) or not re.fullmatch(r'[a-zA-Z0-9.-]+', host):
                raise ValueError(f'Invalid host in {key}')
            host = host.lower().rstrip('.')
            if not host or any(not label for label in host.split('.')):
                raise ValueError(f'Invalid host in {key}')
            if host not in clean:
                clean.append(host)
        rules[key] = clean
    return rules


def generate_pac(rules, port=8123):
    """ES5-compatible; hostname comparisons never use unescaped regexes."""
    return '''// GBF Local Proxy: selected sites use the local proxy; all others DIRECT.
var suffixes = %s;
var exactHosts = %s;
var socksHosts = %s;
function contains(items, value) {
  for (var i = 0; i < items.length; i++) if (items[i] === value) return true;
  return false;
}
function FindProxyForURL(url, host) {
  host = String(host).toLowerCase().replace(/\\.$/, "");
  if (contains(socksHosts, host)) return "SOCKS5 127.0.0.1:%d";
  if (contains(exactHosts, host)) return "PROXY 127.0.0.1:%d";
  for (var i = 0; i < suffixes.length; i++) {
    var domain = suffixes[i];
    if (host === domain || host.slice(-(domain.length + 1)) === "." + domain)
      return "PROXY 127.0.0.1:%d";
  }
  return "DIRECT";
}
''' % (json.dumps(rules['domain_suffixes']), json.dumps(rules['exact_hosts']),
       json.dumps(rules['socks5_hosts']), port, port, port)


def authority(value, default_port=None):
    try:
        if any(c.isspace() for c in value) or any(c in value for c in '/?#@\\'):
            raise ValueError()
        parsed = urlsplit('//' + value)
        host = parsed.hostname
        port = parsed.port if parsed.port is not None else default_port
        if not host or port is None or not 1 <= port <= 65535:
            raise ValueError()
        return host, port
    except ValueError:
        raise HTTPError(400, 'Invalid destination authority') from None


class ProxyServer:
    def __init__(self, port=8123, runtime_dir=ROOT / 'runtime', rules=None,
                 connect_timeout=15, idle_timeout=300, max_connections=256,
                 upstream_port=None, ssh_tunnel=None, asset_gateway=None, game_tunnel=None):
        self.port = port
        self.runtime_dir = Path(runtime_dir)
        self.rules = rules if rules is not None else load_rules()
        self.connect_timeout = connect_timeout
        self.idle_timeout = idle_timeout
        self.max_connections = max_connections
        self.upstream_port = upstream_port
        self.ssh_tunnel = ssh_tunnel
        self.game_tunnel = game_tunnel
        self.game_connections = 0
        self.asset_gateway = asset_gateway
        self.stop_event = asyncio.Event()
        self.server = None
        self.tasks = set()
        self.writers = set()
        self.token = secrets.token_urlsafe(32)
        self.started = time.time()
        self.instance = hashlib.sha256(str(ROOT).encode()).hexdigest()[:16]
        self.stats = dict(http_requests=0, connect_tunnels=0, socks5_tunnels=0,
                          errors=0, bytes_uploaded=0, bytes_downloaded=0)

    async def start(self):
        self.server = await asyncio.start_server(self.handle, '127.0.0.1', self.port,
                                                 limit=HEADER_LIMIT)
        self.port = self.server.sockets[0].getsockname()[1]
        self.pac = generate_pac(self.rules, self.port).encode('utf-8')
        self.runtime_dir.mkdir(parents=True, exist_ok=True)
        state = dict(app=APP, pid=os.getpid(), port=self.port, stop_token=self.token,
                     instance=self.instance, started_at=self.started)
        pending = self.runtime_dir / 'state.pending'
        pending.write_text(json.dumps(state), encoding='utf-8')
        pending.replace(self.runtime_dir / 'state.json')
        LOG.info('Listening on 127.0.0.1:%s; egress=%s', self.port,
                 'Japan SSH' if self.upstream_port else 'DIRECT')

    async def close(self):
        if self.server:
            self.server.close()
        current = asyncio.current_task()
        tasks = [t for t in self.tasks if t is not current]
        for writer in tuple(self.writers):
            writer.close()
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        # Python 3.12+ also waits for accepted connections. Close them BEFORE
        # waiting for the listener, otherwise live browser tunnels block shutdown.
        if self.server:
            await self.server.wait_closed()
        state_path = self.runtime_dir / 'state.json'
        try:
            if json.loads(state_path.read_text())['stop_token'] == self.token:
                state_path.unlink()
        except (OSError, ValueError, KeyError):
            pass

    async def respond(self, writer, status, body=b'', content_type='text/plain; charset=utf-8', head=False):
        if isinstance(body, str):
            body = body.encode('utf-8')
        headers = (f'HTTP/1.1 {status} {REASONS[status]}\r\n'
                   f'Content-Type: {content_type}\r\nContent-Length: {len(body)}\r\n'
                   'Cache-Control: no-store\r\nConnection: close\r\n'
                   'X-Content-Type-Options: nosniff\r\n'
                   "Content-Security-Policy: default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'none'\r\n\r\n")
        writer.write(headers.encode('ascii') + (b'' if head else body))
        await writer.drain()

    async def handle(self, reader, writer):
        task = asyncio.current_task()
        if len(self.tasks) >= self.max_connections:
            writer.close()
            return
        self.tasks.add(task)
        self.writers.add(writer)
        protocol = None
        try:
            first = await asyncio.wait_for(reader.readexactly(1), 15)
            protocol = 'socks' if first == b'\x05' else 'http'
            if protocol == 'socks':
                await self.handle_socks(reader, writer)
            else:
                await self.handle_http(first, reader, writer)
        except HTTPError as error:
            self.stats['errors'] += 1
            if protocol == 'http':
                try:
                    await self.respond(writer, error.status, error.message)
                except OSError:
                    pass
        except (OSError, asyncio.IncompleteReadError, TimeoutError, ValueError) as error:
            self.stats['errors'] += 1
            # Never log URLs, request headers, credentials, or TLS payloads.
            LOG.debug('Connection ended: %s', type(error).__name__)
        finally:
            self.writers.discard(writer)
            writer.close()
            try:
                await writer.wait_closed()
            except OSError:
                pass
            self.tasks.discard(task)

    async def open_remote(self, host, port):
        if self.game_tunnel and is_battle_target(host, port):
            if not self.game_tunnel.ready:
                raise OSError('Game tunnel is not connected; fallback disabled')
            connection = await open_socks(self.game_tunnel.config['socks_port'], host, port,
                                          self.connect_timeout)
            self.game_connections += 1
            return connection
        if self.upstream_port is not None:
            if self.ssh_tunnel and not self.ssh_tunnel.ready:
                raise OSError('Japan tunnel is not connected; direct fallback disabled')
            return await open_socks(self.upstream_port, host, port, self.connect_timeout)
        async def connect():
            loop = asyncio.get_running_loop()
            addresses = await loop.getaddrinfo(host, port, type=socket.SOCK_STREAM)
            last_error = OSError('No usable address')
            # Validate and use the SAME resolved IP to prevent recursive self-proxying.
            for family, _, _, _, addr in addresses:
                if port == self.port and ipaddress.ip_address(addr[0]).is_loopback:
                    raise HTTPError(403, 'Cannot proxy back into this listener')
            for family, _, _, _, addr in addresses:
                try:
                    return await asyncio.open_connection(addr[0], port, family=family)
                except OSError as error:
                    last_error = error
            raise last_error
        return await asyncio.wait_for(connect(), self.connect_timeout)

    async def tunnel(self, client_reader, client_writer, remote_reader, remote_writer):
        self.writers.add(remote_writer)
        async def pump(reader, writer, counter):
            while True:
                data = await asyncio.wait_for(reader.read(65536), self.idle_timeout)
                if not data:
                    if writer.can_write_eof():
                        writer.write_eof()
                        await writer.drain()
                    return
                writer.write(data)
                await writer.drain()
                self.stats[counter] += len(data)
        pumps = [asyncio.create_task(pump(client_reader, remote_writer, 'bytes_uploaded')),
                 asyncio.create_task(pump(remote_reader, client_writer, 'bytes_downloaded'))]
        try:
            await asyncio.gather(*pumps)
        finally:
            for task in pumps:
                task.cancel()
            await asyncio.gather(*pumps, return_exceptions=True)
            self.writers.discard(remote_writer)
            remote_writer.close()
            try:
                await remote_writer.wait_closed()
            except OSError:
                pass

    async def handle_socks(self, reader, writer):
        async def exact(size):
            return await asyncio.wait_for(reader.readexactly(size), 15)
        count = (await exact(1))[0]
        methods = await exact(count)
        if 0 not in methods:
            writer.write(b'\x05\xff')
            await writer.drain()
            return
        writer.write(b'\x05\x00')
        await writer.drain()
        version, command, reserved, atyp = await exact(4)
        async def reject(code):
            writer.write(bytes([5, code, 0, 1]) + b'\x00' * 6)
            await writer.drain()
        if version != 5 or reserved != 0:
            await reject(1)
            return
        if command != 1:
            await reject(7)  # No BIND or UDP ASSOCIATE in this browser-only phase.
            return
        if atyp == 1:
            host = socket.inet_ntop(socket.AF_INET, await exact(4))
        elif atyp == 4:
            host = socket.inet_ntop(socket.AF_INET6, await exact(16))
        elif atyp == 3:
            host = (await exact((await exact(1))[0])).decode('ascii')
            if not host or any(c in host for c in '/\\\x00'):
                await reject(4)
                return
        else:
            await reject(8)
            return
        port = struct.unpack('!H', await exact(2))[0]
        if port == 0:
            await reject(1)
            return
        try:
            remote_reader, remote_writer = await self.open_remote(host, port)
        except (OSError, TimeoutError, HTTPError, ValueError) as error:
            self.stats['errors'] += 1
            await reject(2 if isinstance(error, HTTPError) else 5)
            return
        self.stats['socks5_tunnels'] += 1
        writer.write(b'\x05\x00\x00\x01' + b'\x00' * 6)
        await writer.drain()
        await self.tunnel(reader, writer, remote_reader, remote_writer)

    async def handle_http(self, first, reader, writer):
        try:
            raw = first + await asyncio.wait_for(reader.readuntil(b'\r\n\r\n'), 15)
        except asyncio.LimitOverrunError:
            raise HTTPError(431, 'Request headers exceed 64 KiB') from None
        except TimeoutError:
            raise HTTPError(408, 'Request headers timed out') from None
        if len(raw) > HEADER_LIMIT:
            raise HTTPError(431, 'Request headers exceed 64 KiB')
        lines = raw[:-4].decode('iso-8859-1').split('\r\n')
        try:
            method, target, version = lines[0].split(' ')
        except ValueError:
            raise HTTPError(400, 'Invalid request line') from None
        if version not in ('HTTP/1.0', 'HTTP/1.1') or not re.fullmatch(r'[A-Z]+', method):
            raise HTTPError(400, 'Unsupported request line')
        headers = []
        for line in lines[1:]:
            name, separator, value = line.partition(':')
            if not separator or not re.fullmatch(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+", name):
                raise HTTPError(400, 'Invalid header')
            if any(ord(c) < 32 and c != '\t' or ord(c) == 127 for c in value):
                raise HTTPError(400, 'Invalid header value')
            headers.append((name, value.strip()))
        mapped = {}
        for name, value in headers:
            mapped.setdefault(name.lower(), []).append(value)
        if any(len(mapped.get(key, [])) > 1 for key in ('host', 'content-length', 'transfer-encoding')):
            raise HTTPError(400, 'Duplicate framing header')
        if 'content-length' in mapped and 'transfer-encoding' in mapped:
            raise HTTPError(400, 'Ambiguous request framing')
        if 'content-length' in mapped and not re.fullmatch(r'[0-9]+', mapped['content-length'][0]):
            raise HTTPError(400, 'Invalid Content-Length')
        if 'transfer-encoding' in mapped and mapped['transfer-encoding'][0].lower() != 'chunked':
            raise HTTPError(400, 'Unsupported Transfer-Encoding')
        if target.startswith('/'):
            await self.local_request(method, target, mapped, writer)
            return
        if method == 'CONNECT':
            host, port = authority(target)
        else:
            try:
                parsed = urlsplit(target)
                if parsed.scheme not in ('http', 'ws') or parsed.username is not None or parsed.fragment:
                    raise ValueError()
                host, port = authority(parsed.netloc, 80)
            except ValueError:
                raise HTTPError(400, 'Use an absolute http:// URL or CONNECT for TLS') from None
        try:
            if method == 'CONNECT' and self.asset_gateway and self.asset_gateway.handles(host, port):
                remote_reader, remote_writer = await self.asset_gateway.open(host)
            else:
                remote_reader, remote_writer = await self.open_remote(host, port)
        except (OSError, TimeoutError):
            raise HTTPError(502, 'Destination or upstream connection failed; check local status') from None
        if method == 'CONNECT':
            self.stats['connect_tunnels'] += 1
            writer.write(b'HTTP/1.1 200 Connection Established\r\n\r\n')
            await writer.drain()
        else:
            self.stats['http_requests'] += 1
            # One ordinary HTTP request per connection. HTTPS and WebSocket tunnels
            # stay persistent; their encrypted application framing is untouched.
            upgrade = 'upgrade' in mapped and 'upgrade' in ','.join(mapped.get('connection', [])).lower()
            request_path = parsed.path or '/'
            if parsed.query:
                request_path += '?' + parsed.query
            request = f'{method} {request_path} {version}\r\nHost: {parsed.netloc}\r\n'
            removed = {'host', 'proxy-authorization', 'proxy-connection', 'connection', 'keep-alive'}
            for name, value in headers:
                if name.lower() not in removed:
                    request += f'{name}: {value}\r\n'
            request += 'Connection: ' + ('Upgrade' if upgrade else 'close') + '\r\n\r\n'
            remote_writer.write(request.encode('iso-8859-1'))
            await remote_writer.drain()
        await self.tunnel(reader, writer, remote_reader, remote_writer)

    async def local_request(self, method, target, headers, writer):
        host, port = authority(headers.get('host', [''])[0], 80)
        if host.lower() not in ('127.0.0.1', 'localhost') or port != self.port:
            raise HTTPError(403, 'Local endpoint requires a loopback Host header')
        if target == '/_control/stop':
            supplied = headers.get('x-stop-token', [''])[0]
            if method != 'POST' or not secrets.compare_digest(supplied, self.token):
                raise HTTPError(403, 'Stop requires the local launcher token')
            await self.respond(writer, 200, 'Stopping')
            self.stop_event.set()
            return
        if method not in ('GET', 'HEAD'):
            raise HTTPError(405, 'Only GET and HEAD are supported here')
        if target == '/proxy.pac':
            await self.respond(writer, 200, self.pac, 'application/x-ns-proxy-autoconfig', method == 'HEAD')
        elif target == '/status.json':
            mode = 'ssh' if self.ssh_tunnel else ('socks5' if self.upstream_port else 'direct')
            connected = self.ssh_tunnel.ready if self.ssh_tunnel else bool(self.upstream_port)
            status = dict(app=APP, version=VERSION, instance=self.instance, mode=mode,
                          acceleration_enabled=connected, listen=f'127.0.0.1:{self.port}',
                          uptime_seconds=int(time.time() - self.started),
                          active_connections=max(0, len(self.tasks) - 1), **self.stats)
            if self.ssh_tunnel:
                status['tunnel'] = self.ssh_tunnel.status()
            status['cache'] = self.asset_gateway.status() if self.asset_gateway else {'enabled': False}
            status['game_channel'] = dict(enabled=bool(self.game_tunnel), connected=False,
                                          hosts=list(GAME_HOSTS), connections=self.game_connections, ssh_pid=None)
            if self.game_tunnel:
                status['game_channel'].update(self.game_tunnel.status())
            await self.respond(writer, 200, json.dumps(status), 'application/json', method == 'HEAD')
        elif target == '/':
            await self.respond(writer, 200, self.homepage(), 'text/html; charset=utf-8', method == 'HEAD')
        else:
            raise HTTPError(404, 'Not found')

    def homepage(self):
        if self.game_tunnel:
            game_state = '已连接' if self.game_tunnel.ready else '正在连接或重连'
            game_note = (f'B 模式 · 战斗优先通道：{game_state}。GBF 主接口、房间实时连接与'
                         '原 PAC 指定的实时节点使用第二条 SSH 通道；素材流量使用原通道。'
                         '战斗流量保持加密透传，断线时不回落。')
        else:
            game_note = 'A 模式 · 共享通道：游戏与素材沿用原出口，战斗优先通道未启用。'
        if self.ssh_tunnel:
            state = '已连接' if self.ssh_tunnel.ready else '正在连接或重连'
            note = (f'日本加密通道：{state}。名单内流量经日本出口；'
                    '断线时不会自动改为直连。实际延迟改善需实测。')
        else:
            note = '当前使用本机网络直连，尚未接入日本节点。'
        if self.asset_gateway:
            cache = self.asset_gateway.status()
            cache_note = (f'GBF 素材缓存已启用：本地命中 {cache["hits"]} 次，源站校验复用 {cache["revalidated"]} 次'
                          f'（旧缓存 {cache["legacy_hits"]} 次），节省下载 {cache["saved_bytes"]/1024/1024:.2f} MB。'
                          f'新缓存 {cache["entries"]} 个文件，{cache["bytes"]/1024/1024:.2f} MB / {cache["max_bytes"]/1024**3:g} GB。'
                          '刷新此页面查看最新统计。只有独立 GBF 素材 CDN 使用本机证书；登录和战斗域名仍加密透传。')
        else:
            cache_note = 'GBF 素材缓存未启用。运行 Enable-Cache.cmd，阅读证书提示并确认后启用；无需修改 PAC。'
        return f'''<!doctype html><html lang="zh-CN"><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>GBF 本地代理</title>
<style>body{{max-width:760px;margin:60px auto;padding:0 24px;font:17px/1.8 system-ui;color:#24354a;background:#f6f8fa}}code{{background:#e6ecf2;padding:3px 6px;border-radius:5px}}a{{color:#1764a5}}.note{{padding:16px 20px;background:#fff3cf;border-left:4px solid #b68b26}}</style>
<h1>GBF 本地代理 · v{VERSION}</h1><p>服务已启动：<code>127.0.0.1:{self.port}</code></p>
<p class="note">{note}</p>
<p class="note">{game_note}</p>
<p>ZeroOmega 的 PAC 地址：<a href="/proxy.pac">http://127.0.0.1:{self.port}/proxy.pac</a></p>
<p>在原有 gbf 情景模式中点击“立即更新情景模式”，然后选择 gbf。</p>
<p>范围：GBF、GameWith、梦宝谷、DMM，以及列入规则的公共素材域名；其他网站直连。</p>
<p class="note">{cache_note}</p>
<p>HTTP、HTTPS CONNECT 和 SOCKS5 共用同一端口。关闭缓存：运行 Disable-Cache.cmd，恢复加密透传并移除本程序证书信任，保留缓存文件。</p>
<p><a href="/status.json">查看连接和流量统计</a> · 修改 rules.json 后重启生效。</p>
<p>停止服务：双击 Stop.cmd。停止后请将 ZeroOmega 切回“直接连接”，以免名单内网站仍指向已关闭的代理。</p></html>'''


async def run(config):
    game_config = game_channel_config(config)
    runtime = ROOT / 'runtime'
    runtime.mkdir(exist_ok=True)
    handler = RotatingFileHandler(runtime / 'proxy.log', maxBytes=1024 * 1024,
                                  backupCount=2, encoding='utf-8')
    handler.setFormatter(logging.Formatter('%(asctime)s %(levelname)s %(message)s'))
    LOG.setLevel(logging.INFO)
    LOG.addHandler(handler)
    tunnel = game_tunnel = server = None
    cache = None
    gateway = None
    try:
        ssh_config = config.get('ssh')
        tunnel = SshTunnel(ssh_config, ROOT, runtime) if ssh_config else None
        game_tunnel = SshTunnel(game_config, ROOT, runtime) if game_config else None
        server = ProxyServer(port=config['port'], runtime_dir=runtime,
                             connect_timeout=config['connect_timeout_seconds'],
                             idle_timeout=config['idle_timeout_seconds'], max_connections=config['max_connections'],
                             upstream_port=ssh_config['socks_port'] if ssh_config else None,
                             ssh_tunnel=tunnel, game_tunnel=game_tunnel)
        if cache_config := config.get('cache'):
            if cache_config.get('enabled'):
                from asset_cache import AssetCache
                from asset_gateway import AssetGateway
                from cache_certificate import certificate_info
                import ssl
                cert_dir = runtime/'cache-tls'
                certificate_info(cert_dir)
                if os.name == 'nt':
                    expected = ssl.PEM_cert_to_DER_cert((cert_dir/'ca.pem').read_text())
                    if not any(cert == expected for cert, encoding, trust in ssl.enum_certificates('ROOT')):
                        raise OSError('Cache CA is not trusted. Use Enable-Cache.cmd, or disable cache in config.json.')
                cache = AssetCache(runtime/'asset-cache',cache_config.get('legacy_directory'),
                                   cache_config.get('max_bytes',5*1024**3),cache_config.get('max_item_bytes',16*1024**2))
                gateway = AssetGateway(cache,cert_dir,server.open_remote)
                await gateway.start()
                server.asset_gateway = gateway
        await server.start()
        await start_tunnels(tunnel, game_tunnel)
        print(f'GBF Local Proxy v{VERSION}: http://127.0.0.1:{server.port}/', flush=True)
        print('Egress: Japan SSH tunnel.' if tunnel else 'Egress: DIRECT.', flush=True)
        await server.stop_event.wait()
    finally:
        try:
            if server:
                try:
                    await server.close()
                except Exception:
                    LOG.exception('Proxy listener cleanup failed')
            await close_resources(gateway, game_tunnel, tunnel)
            if cache:
                cache.close()
        finally:
            LOG.removeHandler(handler)
            handler.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--export-pac', type=Path, help='Generate a static PAC and exit')
    args = parser.parse_args()
    config = json.loads((ROOT / 'config.json').read_text(encoding='utf-8-sig'))
    for key, low, high in [('port', 1, 65535), ('connect_timeout_seconds', 1, 120),
                           ('idle_timeout_seconds', 1, 3600), ('max_connections', 1, 4096)]:
        if type(config.get(key)) is not int or not low <= config[key] <= high:
            raise ValueError(f'Invalid configuration: {key}')
    if ssh := config.get('ssh'):
        for key in ('host', 'username', 'private_key', 'known_hosts'):
            if not isinstance(ssh.get(key), str) or not ssh[key]:
                raise ValueError(f'Missing SSH configuration: {key}')
        if not re.fullmatch(r'[a-zA-Z0-9.-]+', ssh['host']) or not re.fullmatch(r'[a-zA-Z0-9_-]+', ssh['username']):
            raise ValueError('Invalid SSH host or username')
        for key in ('port', 'socks_port'):
            if type(ssh.get(key)) is not int or not 1 <= ssh[key] <= 65535:
                raise ValueError(f'Invalid SSH {key}')
        if ssh['socks_port'] == config['port']:
            raise ValueError('SSH SOCKS port must differ from the PAC/proxy port')
    if cache := config.get('cache'):
        if type(cache.get('enabled')) is not bool:
            raise ValueError('cache.enabled must be boolean')
        for key,low,high in [('max_bytes',1024**2,100*1024**3),('max_item_bytes',1024,64*1024**2)]:
            if type(cache.get(key)) is not int or not low <= cache[key] <= high:
                raise ValueError(f'Invalid cache {key}')
    game_channel_config(config)
    if args.export_pac:
        args.export_pac.write_text(generate_pac(load_rules(), config['port']), encoding='utf-8')
        return 0
    try:
        asyncio.run(run(config))
    except KeyboardInterrupt:
        return 0
    except OSError as error:
        print(f'Cannot start local proxy: {error}', flush=True)
        return 1
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
