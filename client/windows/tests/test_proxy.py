import asyncio
import importlib.util
import json
import socket
import ssl
import struct
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

ROOT = Path(__file__).resolve().parents[1]/'proxy_core'
sys.path.insert(0, str(ROOT))


def create_localhost_certificate(folder):
    """Create an ephemeral origin certificate without storing a test private key in Git."""
    folder.mkdir(parents=True, exist_ok=True)
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'localhost')])
    now = datetime.now(timezone.utc)
    certificate = (x509.CertificateBuilder()
                   .subject_name(subject).issuer_name(subject).public_key(key.public_key())
                   .serial_number(x509.random_serial_number())
                   .not_valid_before(now-timedelta(minutes=1))
                   .not_valid_after(now+timedelta(minutes=5))
                   .add_extension(x509.SubjectAlternativeName([x509.DNSName('localhost')]), critical=False)
                   .sign(key, hashes.SHA256()))
    certificate_path = folder/'localhost.pem'
    key_path = folder/'localhost-key.pem'
    certificate_path.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(key.private_bytes(serialization.Encoding.PEM,
                                           serialization.PrivateFormat.PKCS8,
                                           serialization.NoEncryption()))
    return certificate_path, key_path


class ImplementationTests(unittest.TestCase):
    def test_proxy_module_exists(self):
        self.assertIsNotNone(importlib.util.find_spec('gbf_proxy'), 'Local proxy has not been implemented')


@unittest.skipUnless(importlib.util.find_spec('gbf_proxy'), 'Awaiting proxy implementation')
class ProxyTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        import gbf_proxy
        self.temp = tempfile.TemporaryDirectory()
        self.proxy = gbf_proxy.ProxyServer(port=0, runtime_dir=Path(self.temp.name), idle_timeout=1)
        await self.proxy.start()
        self.port = self.proxy.port
        self.backends = []

    async def asyncTearDown(self):
        await self.proxy.close()
        for server in self.backends:
            server.close()
            await server.wait_closed()
        self.temp.cleanup()

    async def backend(self, callback):
        server = await asyncio.start_server(callback, '127.0.0.1', 0)
        self.backends.append(server)
        return server.sockets[0].getsockname()[1]

    async def connect(self):
        reader, writer = await asyncio.open_connection('127.0.0.1', self.port)
        self.addAsyncCleanup(self.close_writer, writer)
        return reader, writer

    async def close_writer(self, writer):
        writer.close()
        try:
            await writer.wait_closed()
        except OSError:
            pass

    async def echo(self, reader, writer):
        try:
            while data := await reader.read(65536):
                writer.write(data)
                await writer.drain()
        finally:
            await self.close_writer(writer)

    async def request(self, path, method='GET', headers=''):
        reader, writer = await self.connect()
        writer.write(f'{method} {path} HTTP/1.1\r\nHost: 127.0.0.1:{self.port}\r\n{headers}\r\n'.encode())
        await writer.drain()
        return await asyncio.wait_for(reader.read(), 3)

    async def test_pac_is_served_on_same_port(self):
        response = await self.request('/proxy.pac')
        self.assertIn(b'200 OK', response)
        self.assertIn(b'application/x-ns-proxy-autoconfig', response)
        self.assertIn(b'FindProxyForURL', response)
        self.assertIn(f'PROXY 127.0.0.1:{self.port}'.encode(), response)
        self.assertIn(f'SOCKS5 127.0.0.1:{self.port}'.encode(), response)

    async def test_status_reports_direct_mode_and_no_upstream(self):
        response = await self.request('/status.json')
        status = json.loads(response.split(b'\r\n\r\n', 1)[1])
        self.assertEqual(status['app'], 'gbf-local-proxy')
        self.assertEqual(status['mode'], 'direct')
        self.assertFalse(status['acceleration_enabled'])
        self.assertNotIn('stop_token', status)

    async def test_homepage_explains_phase_one(self):
        response = await self.request('/')
        self.assertIn('尚未接入日本节点'.encode(), response)

    async def test_http_forwarding_strips_proxy_credentials_and_rewrites_target(self):
        received = asyncio.get_running_loop().create_future()
        async def handler(reader, writer):
            head = await reader.readuntil(b'\r\n\r\n')
            received.set_result(head)
            writer.write(b'HTTP/1.1 200 OK\r\nContent-Length: 4\r\nConnection: close\r\n\r\nGBF!')
            await writer.drain()
            await self.close_writer(writer)
        port = await self.backend(handler)
        reader, writer = await self.connect()
        writer.write((f'GET http://127.0.0.1:{port}/asset?x=1 HTTP/1.1\r\n'
                      'Host: wrong.example\r\nProxy-Authorization: secret\r\n'
                      'Proxy-Connection: keep-alive\r\nAuthorization: Bearer keep\r\n\r\n').encode())
        await writer.drain()
        response = await asyncio.wait_for(reader.read(), 3)
        self.assertTrue(response.endswith(b'GBF!'))
        head = await received
        self.assertTrue(head.startswith(b'GET /asset?x=1 HTTP/1.1'))
        self.assertIn(f'Host: 127.0.0.1:{port}'.encode(), head)
        self.assertNotIn(b'secret', head)
        self.assertNotIn(b'Proxy-Connection', head)
        self.assertIn(b'Authorization: Bearer keep', head)

    async def test_http_post_preserves_body(self):
        async def handler(reader, writer):
            await reader.readuntil(b'\r\n\r\n')
            body = await reader.readexactly(5)
            writer.write(b'HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\n' + body)
            await writer.drain()
            await self.close_writer(writer)
        port = await self.backend(handler)
        reader, writer = await self.connect()
        writer.write(f'POST http://127.0.0.1:{port}/ HTTP/1.1\r\nHost: localhost\r\nContent-Length: 5\r\n\r\nhello'.encode())
        self.assertTrue((await asyncio.wait_for(reader.read(), 3)).endswith(b'hello'))

    async def test_connect_preserves_coalesced_bytes(self):
        port = await self.backend(self.echo)
        reader, writer = await self.connect()
        writer.write(f'CONNECT 127.0.0.1:{port} HTTP/1.1\r\nHost: localhost\r\n\r\n'.encode() + b'early TLS bytes')
        self.assertIn(b'200 Connection Established', await reader.readuntil(b'\r\n\r\n'))
        self.assertEqual(await reader.readexactly(15), b'early TLS bytes')

    async def test_connect_half_close_allows_response(self):
        async def handler(reader, writer):
            body = await reader.read()
            writer.write(body[::-1])
            await writer.drain()
            await self.close_writer(writer)
        port = await self.backend(handler)
        reader, writer = await self.connect()
        writer.write(f'CONNECT 127.0.0.1:{port} HTTP/1.1\r\nHost: localhost\r\n\r\n'.encode())
        await reader.readuntil(b'\r\n\r\n')
        writer.write(b'abcdef')
        writer.write_eof()
        self.assertEqual(await asyncio.wait_for(reader.read(), 3), b'fedcba')

    async def test_tls_certificate_is_end_to_end_through_connect(self):
        fixture = Path(self.temp.name)/'origin-fixture'
        certificate_path, key_path = create_localhost_certificate(fixture)
        server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        server_context.load_cert_chain(certificate_path, key_path)
        server = await asyncio.start_server(self.echo, '127.0.0.1', 0, ssl=server_context)
        self.backends.append(server)
        port = server.sockets[0].getsockname()[1]
        reader, writer = await self.connect()
        writer.write(f'CONNECT 127.0.0.1:{port} HTTP/1.1\r\nHost: localhost\r\n\r\n'.encode())
        await reader.readuntil(b'\r\n\r\n')
        client_context = ssl.create_default_context(cafile=str(certificate_path))
        await writer.start_tls(client_context, server_hostname='localhost')
        peer = writer.get_extra_info('ssl_object').getpeercert(binary_form=True)
        expected = ssl.PEM_cert_to_DER_cert(certificate_path.read_text())
        self.assertEqual(peer, expected, 'Proxy must expose the origin TLS certificate unchanged')
        writer.write(b'private-login-data')
        self.assertEqual(await reader.readexactly(18), b'private-login-data')

    async def test_socks5_ipv6_destination(self):
        try:
            server = await asyncio.start_server(self.echo, '::1', 0)
        except OSError:
            self.skipTest('IPv6 loopback unavailable')
        self.backends.append(server)
        port = server.sockets[0].getsockname()[1]
        await self.socks(4, socket.inet_pton(socket.AF_INET6, '::1'), port)

    async def test_websocket_upgrade_preserves_stream(self):
        async def handler(reader, writer):
            head = await reader.readuntil(b'\r\n\r\n')
            self.assertIn(b'Connection: Upgrade', head)
            writer.write(b'HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n')
            await writer.drain()
            await self.echo(reader, writer)
        port = await self.backend(handler)
        reader, writer = await self.connect()
        writer.write(f'GET http://127.0.0.1:{port}/socket HTTP/1.1\r\nHost: localhost\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n'.encode())
        self.assertIn(b'101 Switching Protocols', await reader.readuntil(b'\r\n\r\n'))
        writer.write(b'\x82\x05hello')
        self.assertEqual(await reader.readexactly(7), b'\x82\x05hello')

    async def test_plain_http_explicit_port_zero_is_rejected(self):
        reader, writer = await self.connect()
        writer.write(b'GET http://localhost:0/ HTTP/1.1\r\nHost: localhost\r\n\r\n')
        self.assertIn(b'400 Bad Request', await asyncio.wait_for(reader.read(), 3))

    async def socks(self, atyp, address, port):
        reader, writer = await self.connect()
        writer.write(b'\x05\x01\x00' + b'\x05\x01\x00' + bytes([atyp]) + address + struct.pack('!H', port) + b'hello')
        self.assertEqual(await reader.readexactly(2), b'\x05\x00')
        result = await reader.readexactly(10)
        self.assertEqual(result[:2], b'\x05\x00')
        self.assertEqual(await reader.readexactly(5), b'hello')

    async def test_socks5_ipv4_and_coalesced_data(self):
        port = await self.backend(self.echo)
        await self.socks(1, socket.inet_aton('127.0.0.1'), port)

    async def test_socks5_domain(self):
        port = await self.backend(self.echo)
        await self.socks(3, b'\x09localhost', port)

    async def test_socks_rejects_unsupported_auth(self):
        reader, writer = await self.connect()
        writer.write(b'\x05\x01\x02')
        self.assertEqual(await reader.readexactly(2), b'\x05\xff')

    async def test_socks_udp_is_explicitly_unsupported(self):
        reader, writer = await self.connect()
        writer.write(b'\x05\x01\x00\x05\x03\x00\x01\x7f\x00\x00\x01\x00\x35')
        self.assertEqual(await reader.readexactly(2), b'\x05\x00')
        self.assertEqual((await reader.readexactly(10))[1], 7)

    async def test_connect_to_self_is_rejected(self):
        reader, writer = await self.connect()
        writer.write(f'CONNECT localhost:{self.port} HTTP/1.1\r\nHost: localhost\r\n\r\n'.encode())
        self.assertIn(b'403 Forbidden', await asyncio.wait_for(reader.read(), 3))

    async def test_refused_connection_returns_502(self):
        sock = socket.socket()
        sock.bind(('127.0.0.1', 0))
        port = sock.getsockname()[1]
        sock.close()
        reader, writer = await self.connect()
        writer.write(f'CONNECT 127.0.0.1:{port} HTTP/1.1\r\nHost: localhost\r\n\r\n'.encode())
        self.assertIn(b'502 Bad Gateway', await asyncio.wait_for(reader.read(), 3))

    async def test_local_api_rejects_foreign_host(self):
        reader, writer = await self.connect()
        writer.write(b'GET /status.json HTTP/1.1\r\nHost: attacker.example\r\n\r\n')
        self.assertIn(b'403 Forbidden', await reader.read())

    async def test_stop_requires_secret(self):
        response = await self.request('/_control/stop', 'POST', 'Content-Length: 0\r\n')
        self.assertIn(b'403 Forbidden', response)
        self.assertFalse(self.proxy.stop_event.is_set())

    async def test_authenticated_stop_and_runtime_cleanup(self):
        state = json.loads((Path(self.temp.name) / 'state.json').read_text())
        response = await self.request('/_control/stop', 'POST', f"X-Stop-Token: {state['stop_token']}\r\nContent-Length: 0\r\n")
        self.assertIn(b'200 OK', response)
        await asyncio.wait_for(self.proxy.stop_event.wait(), 1)
        await self.proxy.close()
        self.assertFalse((Path(self.temp.name) / 'state.json').exists())

    async def test_invalid_framing_is_rejected(self):
        reader, writer = await self.connect()
        writer.write(b'POST http://example.com/ HTTP/1.1\r\nHost: example.com\r\nContent-Length: 2\r\nTransfer-Encoding: chunked\r\n\r\n')
        self.assertIn(b'400 Bad Request', await reader.read())

    async def test_oversized_headers_are_rejected(self):
        reader, writer = await self.connect()
        writer.write(b'GET / HTTP/1.1\r\nX-Large: ' + b'a' * 70000 + b'\r\n\r\n')
        self.assertIn(b'431', await reader.read(4096))

    async def test_parallel_tunnels(self):
        port = await self.backend(self.echo)
        await asyncio.gather(*(self.socks(1, socket.inet_aton('127.0.0.1'), port) for _ in range(12)))


if __name__ == '__main__':
    unittest.main()
