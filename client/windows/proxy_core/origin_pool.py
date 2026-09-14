"""Bounded HTTP/1.1 TLS connection reuse for the asset gateway only."""
import asyncio
from contextlib import asynccontextmanager
from dataclasses import dataclass

import h11


async def read_event(connection, reader):
    while True:
        item = connection.next_event()
        if item is not h11.NEED_DATA:
            return item
        connection.receive_data(await asyncio.wait_for(reader.read(65536), 30))


@dataclass(eq=False)
class OriginConnection:
    key: tuple
    reader: asyncio.StreamReader
    writer: asyncio.StreamWriter
    protocol: h11.Connection
    timer: object = None


class OriginPool:
    def __init__(self, open_origin, idle_seconds=30, max_idle=16, per_host=4):
        self.open_origin = open_origin
        self.idle_seconds, self.max_idle, self.per_host = idle_seconds, max_idle, per_host
        self.idle = {}
        self.connections = set()
        self.closing = set()
        self.closed = False
        self.opened = self.reused = self.retries = 0

    def status(self):
        return dict(origin_opened=self.opened, origin_reused=self.reused,
                    origin_retries=self.retries, origin_idle=sum(map(len,self.idle.values())))

    def discard(self, item):
        if item.timer:
            item.timer.cancel()
            item.timer = None
        queue = self.idle.get(item.key, [])
        if item in queue:
            queue.remove(item)
        if not queue:
            self.idle.pop(item.key, None)
        self.connections.discard(item)
        item.writer.close()
        async def finish():
            try:
                await asyncio.wait_for(item.writer.wait_closed(), 2)
            except (OSError, TimeoutError):
                pass
        task = asyncio.create_task(finish())
        self.closing.add(task)
        task.add_done_callback(self.closing.discard)

    async def acquire(self, host, context, fresh=False):
        if self.closed:
            raise OSError('Asset origin pool is closed')
        key = (host, context)
        queue = self.idle.get(key, [])
        while queue and not fresh:
            item = queue.pop()
            if not queue:
                self.idle.pop(key, None)
            if item.timer:
                item.timer.cancel()
                item.timer = None
            if item.reader.at_eof() or item.reader.exception() or item.writer.is_closing():
                self.discard(item)
                continue
            self.reused += 1
            return item, True
        reader, writer = await self.open_origin(host, 443)
        item = OriginConnection(key, reader, writer, h11.Connection(h11.CLIENT,max_incomplete_event_size=65536))
        self.connections.add(item)
        try:
            await asyncio.wait_for(writer.start_tls(context,server_hostname=host),15)
            if self.closed:
                raise OSError('Asset origin pool closed during connect')
        except BaseException:
            self.discard(item)
            raise
        self.opened += 1
        return item, False

    def release(self, item):
        protocol = item.protocol
        if (self.closed or item.writer.is_closing() or item.reader.at_eof() or item.reader.exception()
                or protocol.our_state is not h11.DONE or protocol.their_state is not h11.DONE
                or protocol.trailing_data[0] or protocol.trailing_data[1]
                or sum(map(len,self.idle.values())) >= self.max_idle
                or sum(len(queue) for key,queue in self.idle.items() if key[0] == item.key[0]) >= self.per_host):
            self.discard(item)
            return
        protocol.start_next_cycle()
        self.idle.setdefault(item.key,[]).append(item)
        item.timer = asyncio.get_running_loop().call_later(self.idle_seconds,self.discard,item)

    @asynccontextmanager
    async def request(self, host, context, method, path, headers):
        item = None
        try:
            for attempt in range(2):
                item, reused = await self.acquire(host,context,fresh=bool(attempt))
                try:
                    item.writer.write(item.protocol.send(h11.Request(method=method,target=path,headers=headers)))
                    item.writer.write(item.protocol.send(h11.EndOfMessage()))
                    await item.writer.drain()
                    response = await read_event(item.protocol,item.reader)
                    while isinstance(response,h11.InformationalResponse):
                        if response.status_code == 101:
                            raise ValueError('CDN upgrades are not supported')
                        response = await read_event(item.protocol,item.reader)
                    if not isinstance(response,h11.Response):
                        raise OSError('Origin closed before response headers')
                    break
                except (OSError,h11.RemoteProtocolError,asyncio.IncompleteReadError):
                    self.discard(item)
                    item = None
                    if not reused or attempt or method not in ('GET','HEAD'):
                        raise
                    self.retries += 1
            yield item, response
        except BaseException:
            if item is not None:
                self.discard(item)
                item = None
            raise
        finally:
            if item is not None:
                self.release(item)

    async def close(self):
        self.closed = True
        for item in tuple(self.connections):
            self.discard(item)
        if self.closing:
            await asyncio.gather(*tuple(self.closing),return_exceptions=True)
