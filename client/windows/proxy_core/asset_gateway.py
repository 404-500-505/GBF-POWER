"""TLS termination only for exact GBF CDN hosts, streaming verified origin responses."""
import asyncio
from contextlib import asynccontextmanager
import logging
from pathlib import Path
import ssl
import time

import h11
from asset_cache import ASSET_HOSTS, Entry, cacheable, eligible, header_map
from origin_pool import OriginPool, read_event

LOG = logging.getLogger('gbf-local-proxy')
HOP = {'connection','keep-alive','proxy-authenticate','proxy-authorization','proxy-connection',
       'te','trailer','transfer-encoding','upgrade'}


def clean_headers(headers):
    mapped = header_map(headers)
    removed = HOP | {x.strip().lower() for x in mapped.get('connection','').split(',')}
    return [(k,v) for k,v in headers if k.lower() not in removed and k.lower() != 'x-gbf-cache']


async def event(connection,reader):
    return await read_event(connection,reader)


class AssetGateway:
    def __init__(self,cache,cert_dir,open_origin,origin_context=None):
        self.cache, self.cert_dir, self.open_origin = cache,Path(cert_dir),open_origin
        self.origin_context = origin_context or ssl.create_default_context()
        self.origin_pool = OriginPool(open_origin)
        self.server = None
        self.bindings = {}
        self.tasks, self.writers = set(),set()
        self.locks = {}
        self.slots = asyncio.Semaphore(16)
        self.stats = dict(hits=0,misses=0,revalidated=0,legacy_hits=0,bypassed=0,
                          saved_bytes=0,stored=0,errors=0,downloads=0)

    async def start(self):
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.set_alpn_protocols(['http/1.1'])
        context.load_cert_chain(self.cert_dir/'leaf.pem',self.cert_dir/'leaf-key.pem')
        def sni(ssl_object,name,ctx):
            if name not in ASSET_HOSTS:
                return ssl.ALERT_DESCRIPTION_UNRECOGNIZED_NAME
            ssl_object.gbf_host = name
        context.set_servername_callback(sni)
        self.server = await asyncio.start_server(self.handle,'127.0.0.1',0,ssl=context,
                                                 ssl_handshake_timeout=10,ssl_shutdown_timeout=2,limit=65536)
        self.port = self.server.sockets[0].getsockname()[1]

    async def close(self):
        if self.server:
            self.server.close()
            # Handshaking TLS clients have not entered handle() / self.writers.
            # Python 3.13 tracks these transports on the server itself.
            if hasattr(self.server, 'abort_clients'):
                self.server.abort_clients()
        for writer in tuple(self.writers):
            writer.close()
        tasks = list(self.tasks)
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks,return_exceptions=True)
        # Persistent browser TLS streams must close before Server.wait_closed().
        if self.server:
            # On Python 3.12 there is no abort_clients(); handshakes still have
            # their own 10s deadline, but must not hold up the rest of shutdown.
            try:
                await asyncio.wait_for(self.server.wait_closed(), 2)
            except TimeoutError:
                LOG.warning('TLS listener cleanup exceeded deadline')
        await self.origin_pool.close()
        self.bindings.clear()

    def handles(self,host,port):
        return host in ASSET_HOSTS and port == 443

    async def open(self,host):
        reader,writer = await asyncio.open_connection('127.0.0.1',self.port)
        port = writer.get_extra_info('sockname')[1]
        self.bindings[port] = host
        # Failed TLS handshakes never enter handle(), so expire unused bindings.
        asyncio.get_running_loop().call_later(15,self.bindings.pop,port,None)
        return reader,writer

    def status(self):
        return dict(enabled=True, **self.stats, **self.cache.status(), **self.origin_pool.status())

    @asynccontextmanager
    async def single_flight(self,key):
        if key not in self.locks:
            self.locks[key] = [asyncio.Lock(),0]
        pair = self.locks[key]
        pair[1] += 1
        try:
            async with pair[0]:
                yield
        finally:
            pair[1] -= 1
            if not pair[1]:
                del self.locks[key]

    async def handle(self,reader,writer):
        task = asyncio.current_task()
        self.tasks.add(task)
        self.writers.add(writer)
        connection = h11.Connection(h11.SERVER,max_incomplete_event_size=65536)
        try:
            bound = self.bindings.pop(writer.get_extra_info('peername')[1],None)
            sni = getattr(writer.get_extra_info('ssl_object'),'gbf_host',None)
            while True:
                request = await event(connection,reader)
                if isinstance(request,h11.ConnectionClosed):
                    break
                await self.handle_request(connection,reader,writer,request,bound,sni)
                if connection.our_state is not h11.DONE or connection.their_state is not h11.DONE:
                    break
                connection.start_next_cycle()
        except (OSError,ValueError,TimeoutError,h11.ProtocolError,asyncio.IncompleteReadError) as exc:
            if connection.our_state not in (h11.DONE,h11.MUST_CLOSE) and connection.their_state is not h11.IDLE:
                self.stats['errors'] += 1
            LOG.debug('Asset request ended: %s',type(exc).__name__)
            try:
                if connection.their_state is not h11.IDLE:
                    await self.error(connection,writer,502,'Asset origin unavailable or TLS validation failed')
            except (OSError,h11.ProtocolError):
                pass
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except OSError:
                pass
            self.writers.discard(writer)
            self.tasks.discard(task)

    async def handle_request(self,connection,reader,writer,request,bound,sni):
        if not isinstance(request,h11.Request):
            return
        headers = [(k.decode('ascii'),v.decode('latin1')) for k,v in request.headers]
        mapped = header_map(headers)
        host = mapped.get('host','')
        if host.endswith(':443'):
            host = host[:-4]
        if not bound or bound != sni or host != bound:
            await self.error(connection,writer,421,'CDN Host, SNI and CONNECT must agree')
            return
        method,path = request.method.decode('ascii'),request.target.decode('ascii')
        if method not in ('GET','HEAD','OPTIONS'):
            await self.error(connection,writer,405,'Asset CDN accepts GET, HEAD and OPTIONS only')
            return
        if (not path.startswith('/') or path.startswith('//') or '\\' in path or
            'transfer-encoding' in mapped or mapped.get('content-length','0') != '0' or
            'upgrade' in mapped or 'expect' in mapped):
            await self.error(connection,writer,400,'Unsupported asset request framing')
            return
        if not isinstance(await event(connection,reader),h11.EndOfMessage):
            await self.error(connection,writer,400,'Unexpected request body')
            return
        use_cache = (method == 'GET' and eligible(host,path,mapped) and
                     not any(k in mapped for k in ('if-none-match','if-modified-since')))
        if use_cache:
            async with self.single_flight(self.cache.key(host,path,mapped)):
                await self.serve(connection,writer,method,host,path,headers,mapped,True)
        else:
            self.stats['bypassed'] += 1
            await self.serve(connection,writer,method,host,path,headers,mapped,False)

    async def error(self,connection,writer,status,message):
        data = message.encode()
        writer.write(connection.send(h11.Response(status_code=status,headers=[('Content-Length',str(len(data))),('Connection','close'),('Cache-Control','no-store')])))
        writer.write(connection.send(h11.Data(data=data)))
        writer.write(connection.send(h11.EndOfMessage()))
        await writer.drain()

    async def cached(self,connection,writer,entry,label):
        headers = [(k,v) for k,v in clean_headers(entry.response_headers()) if k.lower() != 'content-length']
        headers += [('Content-Length',str(len(entry.body))),('X-GBF-Cache',label)]
        writer.write(connection.send(h11.Response(status_code=200,headers=headers)))
        for start in range(0,len(entry.body),65536):
            writer.write(connection.send(h11.Data(data=entry.body[start:start+65536])))
            await writer.drain()
        writer.write(connection.send(h11.EndOfMessage()))
        await writer.drain()
        self.stats['saved_bytes'] += len(entry.body)

    async def serve(self,connection,writer,method,host,path,headers,mapped,use_cache):
        async with self.slots:
            await self._serve(connection,writer,method,host,path,headers,mapped,use_cache)

    async def validate_legacy_head(self,host,path,headers,entry):
        old = header_map(entry.headers)
        tag = old.get('etag','')
        if not tag.startswith('"') or not tag.endswith('"'):
            return None  # A weak validator cannot establish identical wire bytes.
        outgoing = [(k,v) for k,v in clean_headers(headers) if k.lower() not in ('host','content-length')]
        outgoing += [('Host',host),('If-None-Match',tag)]
        async with self.origin_pool.request(host,self.origin_context,'HEAD',path,outgoing) as (upstream,response):
            if not isinstance(await event(upstream.protocol,upstream.reader),h11.EndOfMessage):
                raise ValueError('Invalid HEAD framing')
            received = clean_headers([(k.decode('ascii'),v.decode('latin1')) for k,v in response.headers])
            new = header_map(received)
            if response.status_code == 304:
                changed = set(new) | {'content-length','age'}
                merged = [(k,v) for k,v in entry.headers if k.lower() not in changed]
                merged += [(k,v) for k,v in received if k.lower() != 'content-length']
                return merged if cacheable(200,merged) else None
            if (response.status_code == 200 and new.get('etag') == tag and
                new.get('content-length') == str(len(entry.body)) and
                new.get('content-encoding','identity') == old.get('content-encoding','identity') and
                cacheable(200,received)):
                return received
            return None

    async def _serve(self,connection,writer,method,host,path,headers,mapped,use_cache):
        entry = None
        if use_cache:
            entry = await asyncio.to_thread(self.cache.lookup,host,path,mapped)
            if entry and entry.fresh(mapped):
                self.stats['hits'] += 1
                await self.cached(connection,writer,entry,'HIT')
                return
            if not entry:
                entry = await asyncio.to_thread(self.cache.legacy,host,path,mapped)
                if entry and entry.fresh(mapped):
                    self.stats['hits'] += 1
                    self.stats['legacy_hits'] += 1
                    await self.cached(connection,writer,entry,'ACGP-HIT')
                    return
            self.stats['misses'] += 1
            if entry and entry.legacy:
                verified = await self.validate_legacy_head(host,path,headers,entry)
                if verified:
                    await asyncio.to_thread(self.cache.store,host,path,mapped,200,verified,entry.body)
                    self.stats['legacy_hits'] += 1
                    self.stats['revalidated'] += 1
                    await self.cached(connection,writer,Entry(verified,entry.body,time.time(),0),'LEGACY-VALIDATED')
                    return
        outgoing = [(k,v) for k,v in clean_headers(headers) if k.lower() not in ('host','content-length')]
        if entry:
            outgoing += list(entry.validators().items())
        outgoing += [('Host',host)]
        async with self.origin_pool.request(host,self.origin_context,method,path,outgoing) as (upstream,response):
            remote,remote_reader = upstream.protocol,upstream.reader
            status = response.status_code
            received = [(k.decode('ascii'),v.decode('latin1')) for k,v in response.headers]
            received = clean_headers(received)
            if status == 304 and entry:
                if not isinstance(await event(remote,remote_reader),h11.EndOfMessage):
                    raise ValueError('Invalid 304 framing')
                # Preserve representation headers omitted by a 304; replace returned fields.
                changed = {k.lower() for k,v in received} | {'content-length','age'}
                merged = [(k,v) for k,v in entry.headers if k.lower() not in changed] + [(k,v) for k,v in received if k.lower()!='content-length']
                self.stats['revalidated'] += 1
                if entry.legacy:
                    self.stats['legacy_hits'] += 1
                if cacheable(200,merged):
                    await asyncio.to_thread(self.cache.store,host,path,mapped,200,merged,entry.body)
                else:
                    await asyncio.to_thread(self.cache.invalidate,host,path,mapped)
                await self.cached(connection,writer,Entry(merged,entry.body,time.time(),0),
                                  'LEGACY-VALIDATED' if entry.legacy else 'REVALIDATED')
                return
            if use_cache:
                await asyncio.to_thread(self.cache.invalidate,host,path,mapped)
            store_body = bytearray() if use_cache and cacheable(status,received) else None
            downloaded = 0
            client_headers = received + [('X-GBF-Cache','MISS' if use_cache else 'BYPASS')]
            writer.write(connection.send(h11.Response(status_code=status,headers=client_headers)))
            await writer.drain()
            while True:
                chunk = await event(remote,remote_reader)
                if isinstance(chunk,h11.Data):
                    downloaded += len(chunk.data)
                    if store_body is not None:
                        if len(store_body)+len(chunk.data) <= self.cache.max_item_bytes:
                            store_body.extend(chunk.data)
                        else:
                            store_body = None  # Large objects continue streaming, without caching.
                    writer.write(connection.send(h11.Data(data=chunk.data)))
                    await writer.drain()
                elif isinstance(chunk,h11.EndOfMessage):
                    if method == 'GET' and 200 <= status < 300 and downloaded:
                        self.stats['downloads'] += 1
                    # Never commit partial data. Conservative: responses with trailers aren't cached.
                    if store_body is not None and not chunk.headers:
                        if await asyncio.to_thread(self.cache.store,host,path,mapped,status,received,bytes(store_body)):
                            self.stats['stored'] += 1
                    writer.write(connection.send(h11.EndOfMessage()))
                    await writer.drain()
                    return
                else:
                    raise ValueError('Incomplete origin body')
