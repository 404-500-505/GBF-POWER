"""Independent loopback-only GBF monitor. Never changes the proxy or its trust."""
import argparse
import http.client
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import ipaddress
import json
import os
from pathlib import Path
import ssl
import subprocess
import threading
import time
import urllib.request

from monitor_metrics import Metrics

ROOT = Path(__file__).resolve().parent
APP = 'gbf-local-monitor'


def read_status(port):
    # Bypass system/environment proxies for the loopback management endpoint.
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    try:
        with opener.open(f'http://127.0.0.1:{port}/status.json', timeout=0.8) as response:
            body = response.read(65537)
        if len(body) > 65536:
            return None
        value = json.loads(body)
        return value if isinstance(value, dict) and value.get('app') == 'gbf-local-proxy' else None
    except (OSError, ValueError):
        return None


def ping_node(host):
    host = str(ipaddress.IPv4Address(host))
    command = (
        "$ErrorActionPreference='Stop'; $probe=New-Object System.Net.NetworkInformation.Ping; "
        f"try {{$reply=$probe.Send('{host}',1500); "
        "if ($reply.Status -eq 'Success') { Write-Output $reply.RoundtripTime }} "
        "finally {$probe.Dispose()}"
    )
    try:
        result = subprocess.run(
            ['powershell.exe', '-NoLogo', '-NoProfile', '-NonInteractive', '-Command', command],
            capture_output=True, text=True, timeout=5,
            creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
        return float(result.stdout.strip()) if result.returncode == 0 and result.stdout.strip() else None
    except (OSError, ValueError, subprocess.TimeoutExpired):
        return None


def probe_gbf(port):
    started = time.monotonic()
    connection = http.client.HTTPSConnection('127.0.0.1', port, timeout=6,
                                              context=ssl.create_default_context())
    connection.set_tunnel('game.granbluefantasy.jp', 443)
    try:
        # No cookies, account endpoints or redirects. Certificate verification stays enabled.
        connection.request('HEAD', '/', headers={'User-Agent': 'GBF-Local-Monitor/1.0',
                                                 'Connection': 'close'})
        response = connection.getresponse()
        return round((time.monotonic() - started) * 1000, 1), response.status
    except (OSError, http.client.HTTPException):
        return None, None
    finally:
        connection.close()


class Monitor:
    def __init__(self, proxy_port, node, preview=False):
        self.proxy_port = proxy_port
        self.node = str(ipaddress.IPv4Address(node))
        self.preview = preview or 'sandbox' in os.environ.get('USERNAME', '').lower()
        self.metrics = Metrics()
        self.last_view = -float('inf')
        self.stop = threading.Event()

    def active(self):
        return time.monotonic() - self.last_view < 15

    def snapshot(self):
        self.last_view = time.monotonic()
        data = self.metrics.snapshot(time.time())
        data.update(app=APP, version='1.0.0', sampling_context='preview' if self.preview else 'user',
                    node=self.node, proxy_port=self.proxy_port, sampled_at=time.time())
        return data

    def worker(self, kind, interval):
        due = 0
        while not self.stop.wait(0.2):
            if not self.active() or time.monotonic() < due:
                continue
            due = time.monotonic() + interval
            try:
                self.sample(kind)
            except Exception:
                # Keep independent samplers alive; do not expose raw network errors or URLs.
                if kind == 'status':
                    self.metrics.update(None, time.time())

    def sample(self, kind):
        if kind == 'status':
            self.metrics.update(read_status(self.proxy_port), time.time())
        elif kind == 'ping':
            # A sandbox can synthesize ICMP replies; never present them as user-route data.
            if not self.preview:
                self.metrics.ping(ping_node(self.node), time.time())
        elif self.metrics.snapshot(time.time()).get('connected'):
            ms, status = probe_gbf(self.proxy_port)
            self.metrics.gbf(ms, status, time.time())
        else:
            self.metrics.gbf(None, None, time.time())

    def start(self):
        for kind, interval in (('status', 1), ('ping', 10), ('gbf', 15)):
            threading.Thread(target=self.worker, args=(kind, interval), daemon=True).start()


class Handler(BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'

    def setup(self):
        super().setup()
        self.connection.settimeout(5)

    def log_message(self, *args):
        pass

    def respond(self, code, body, content_type='application/json; charset=utf-8'):
        self.send_response(code)
        self.send_header('Content-Type', content_type)
        self.send_header('Content-Length', str(len(body)))
        self.send_header('Cache-Control', 'no-store')
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('Referrer-Policy', 'no-referrer')
        self.send_header('Content-Security-Policy', "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self' data:; frame-ancestors 'none'; base-uri 'none'; form-action 'none'")
        self.send_header('Connection', 'close')
        self.end_headers()
        self.wfile.write(body)
        self.close_connection = True

    def do_GET(self):
        port = self.server.server_port
        hosts = (f'127.0.0.1:{port}', f'localhost:{port}')
        host = self.headers.get('Host')
        origin = self.headers.get('Origin')
        if (host not in hosts or
                (origin is not None and origin != f'http://{host}') or
                self.headers.get('Sec-Fetch-Site') == 'cross-site'):
            return self.respond(403, b'{"error":"local same-origin access only"}')
        path = self.path.split('?', 1)[0]
        if path == '/api/status':
            return self.respond(200, json.dumps(self.server.app.snapshot(), ensure_ascii=False).encode('utf-8'))
        if path == '/health':
            return self.respond(200, json.dumps({'app': APP, 'pid': os.getpid(),
                'preview': self.server.app.preview, 'proxy_port': self.server.app.proxy_port}).encode())
        files = {'/': ('index.html', 'text/html; charset=utf-8'),
                 '/style.css': ('style.css', 'text/css; charset=utf-8'),
                 '/app.js': ('app.js', 'text/javascript; charset=utf-8')}
        if path not in files:
            return self.respond(404, b'{"error":"not found"}')
        name, mime = files[path]
        try:
            self.respond(200, (ROOT / 'monitor' / name).read_bytes(), mime)
        except FileNotFoundError:
            self.respond(404, b'{"error":"not found"}')

    def do_POST(self):
        self.respond(405, b'{"error":"read only"}')


def make_server(app, port):
    server = ThreadingHTTPServer(('127.0.0.1', port), Handler)
    server.daemon_threads = True
    server.app = app
    return server


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--port', type=int, default=18127)
    parser.add_argument('--preview', action='store_true')
    args = parser.parse_args()
    config = json.loads((ROOT / 'config.json').read_text(encoding='utf-8-sig'))
    app = Monitor(int(config['port']), config['ssh']['host'], args.preview)
    server = make_server(app, args.port)
    app.start()
    print(f'GBF monitor: http://127.0.0.1:{server.server_port}/', flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        app.stop.set()
        server.server_close()


if __name__ == '__main__':
    main()
