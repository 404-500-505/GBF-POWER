"""Conservative public-asset cache. Legacy ACG POWER files are read-only."""
from collections import OrderedDict
from dataclasses import dataclass
from email.utils import parsedate_to_datetime
import hashlib
import json
from pathlib import Path
import re
import sqlite3
import threading
import time

ASSET_HOSTS = frozenset(
    [f'prd-game-a{n}-granbluefantasy.akamaized.net' for n in ['',1,2,3,4,5]] +
    [f'prd-game-a{n}-gbf.akamaized.net' for n in ['',1,2,3,4,5,6]])
EXTENSIONS = frozenset(['.png','.jpg','.jpeg','.gif','.webp','.avif','.svg','.ico',
                        '.js','.mjs','.css','.woff','.woff2','.ttf','.otf','.mp3','.ogg','.m4a','.mp4','.webm'])


def header_map(headers):
    result = {}
    for name, value in headers:
        key = name.lower()
        result[key] = result[key] + ', ' + value if key in result else value
    return result


def directives(value):
    return {part.strip().partition('=')[0].lower():part.strip().partition('=')[2].strip('"')
            for part in value.split(',') if part.strip()}


def eligible(host, path, headers):
    # Query variants are forwarded but never cached or matched to query-less legacy files.
    if host not in ASSET_HOSTS or not re.fullmatch(r'/assets/[A-Za-z0-9_@./+\-]+', path):
        return False
    if any(p in ('', '.', '..') or p.endswith('.') for p in path[1:].split('/')):
        return False
    if Path(path).suffix.lower() not in EXTENSIONS:
        return False
    if any(k in headers for k in ('cookie','authorization','range','if-range','if-match','if-unmodified-since')):
        return False
    return 'no-store' not in directives(headers.get('cache-control',''))


def cacheable(status, headers):
    mapped = header_map(headers)
    control = directives(mapped.get('cache-control',''))
    vary = {s.strip().lower() for s in mapped.get('vary','').split(',')} - {''}
    content_type = mapped.get('content-type','').split(';')[0].strip().lower()
    public_type = (content_type.startswith(('image/','audio/','video/','font/')) or
                   content_type in ('text/css','text/javascript','application/javascript',
                                    'application/x-javascript','application/font-woff',
                                    'application/vnd.ms-fontobject','application/octet-stream'))
    return (status == 200 and public_type and ',' not in mapped.get('content-type','') and not control.keys() & {'no-store','private'}
            and not mapped.keys() & {'set-cookie','content-range'} and vary <= {'accept-encoding','origin'})


def remaining_lifetime(headers, now):
    mapped = header_map(headers)
    control = directives(mapped.get('cache-control',''))
    if control.keys() & {'no-cache','no-store','private'}:
        return 0
    try:
        age = max(0, int(mapped.get('age','0')))
        date = parsedate_to_datetime(mapped['date']).timestamp() if 'date' in mapped else now
        age = max(age, now-date)
        if 's-maxage' in control or 'max-age' in control:
            ttl = int(control.get('s-maxage', control.get('max-age','0')))
        elif 'expires' in mapped:
            ttl = parsedate_to_datetime(mapped['expires']).timestamp() - date
        elif 'last-modified' in mapped:
            # RFC 9111 heuristic freshness, conservatively capped at ONE minute.
            modified = parsedate_to_datetime(mapped['last-modified']).timestamp()
            ttl = min(60,max(0,(date-modified)*0.1))
        else:
            ttl = 0
        return max(0, min(86400, ttl-age))
    except (ValueError, TypeError, OverflowError):
        return 0


@dataclass
class Entry:
    headers: list
    body: bytes
    stored_at: float
    expires_at: float
    legacy: bool = False

    def fresh(self, request):
        control = directives(request.get('cache-control',''))
        if control.keys() & {'no-cache','no-store'} or 'no-cache' in request.get('pragma','').lower():
            return False
        if 'max-age' in control:
            try:
                if time.time()-self.stored_at >= int(control['max-age']):
                    return False
            except ValueError:
                return False
        return not self.legacy and time.time() < self.expires_at

    def validators(self):
        headers = header_map(self.headers)
        if headers.get('etag'):
            return {'if-none-match':headers['etag']}
        if headers.get('last-modified'):
            return {'if-modified-since':headers['last-modified']}
        return {}

    def response_headers(self):
        headers = [(k,v) for k,v in self.headers if k.lower() != 'age']
        old = header_map(self.headers)
        try:
            initial = max(int(old.get('age','0')), self.stored_at - parsedate_to_datetime(old['date']).timestamp())
        except (ValueError, KeyError, TypeError):
            initial = 0
        return headers + [('Age',str(max(0,int(initial+time.time()-self.stored_at))))]


class AssetCache:
    def __init__(self, directory, legacy_dir=None, max_bytes=5*1024**3, max_item_bytes=16*1024**2,
                 *, max_memory_bytes=64*1024**2, max_memory_entries=512):
        directory = Path(directory)
        directory.mkdir(parents=True, exist_ok=True)
        self.legacy_dir = Path(legacy_dir).resolve() if legacy_dir else None
        self.max_bytes, self.max_item_bytes = max_bytes, max_item_bytes
        self.lock = threading.RLock()
        self._memory = OrderedDict()
        self.max_memory_entries = max(0, max_memory_entries)
        self.max_memory_bytes = max(0, max_memory_bytes)
        self.memory_bytes = 0
        self.memory_hits = 0
        self.db = sqlite3.connect(directory/'assets.sqlite3', check_same_thread=False)
        self.db.execute('PRAGMA journal_mode=WAL')
        self.db.execute('PRAGMA synchronous=NORMAL')
        self.db.execute('CREATE TABLE IF NOT EXISTS assets (key TEXT PRIMARY KEY, headers TEXT, body BLOB, stored REAL, expires REAL, used REAL, size INTEGER)')
        self.db.execute('CREATE INDEX IF NOT EXISTS assets_lru ON assets(used,size)')
        self.db.commit()

    def close(self):
        with self.lock:
            self._memory.clear()
            self.memory_bytes = 0
            self.db.close()

    def key(self, host, path, request):
        return hashlib.sha256(json.dumps([host,path,request.get('accept-encoding',''),request.get('origin','')]).encode()).hexdigest()

    def status(self):
        with self.lock:
            count, size = self.db.execute('SELECT COUNT(*),COALESCE(SUM(size),0) FROM assets').fetchone()
            return dict(entries=count, bytes=size, max_bytes=self.max_bytes,
                        memory_hits=self.memory_hits, memory_entries=len(self._memory),
                        memory_bytes=self.memory_bytes, max_memory_bytes=self.max_memory_bytes,
                        legacy_available=bool(self.legacy_dir and self.legacy_dir.is_dir()))

    def _forget_memory(self, key):
        cached = self._memory.pop(key, None)
        if cached is not None:
            self.memory_bytes -= cached[1]

    @staticmethod
    def _copy_entry(entry):
        return Entry([list(pair) for pair in entry.headers], entry.body,
                     entry.stored_at, entry.expires_at, entry.legacy)

    def _remember(self, key, entry, serialized_headers):
        # Account payload and serialized metadata plus a bounded entry/key overhead.
        # This is a cache budget estimate, not a measurement of interpreter RSS.
        size = len(entry.body) + len(serialized_headers.encode('utf-8')) + 256
        self._forget_memory(key)
        if not self.max_memory_entries or size > self.max_memory_bytes:
            return
        self._memory[key] = (entry, size)
        self.memory_bytes += size
        while len(self._memory) > self.max_memory_entries or self.memory_bytes > self.max_memory_bytes:
            self._forget_memory(next(iter(self._memory)))

    def lookup(self, host, path, request):
        if not eligible(host,path,request):
            return None
        key = self.key(host,path,request)
        with self.lock:
            if key in self._memory:
                # Hot hits touch only memory LRU. Disk LRU is deliberately approximate:
                # only disk reads/stores refresh it, avoiding SQLite writes on hot hits.
                self.memory_hits += 1
                self._memory.move_to_end(key)
                return self._copy_entry(self._memory[key][0])
            row = self.db.execute('SELECT headers,body,stored,expires FROM assets WHERE key=?',(key,)).fetchone()
            if not row:
                return None
            self.db.execute('UPDATE assets SET used=? WHERE key=?',(time.time(),key))
            self.db.commit()
            entry = Entry(json.loads(row[0]),bytes(row[1]),row[2],row[3])
            self._remember(key, entry, row[0])
            return self._copy_entry(entry)

    def invalidate(self, host, path, request):
        with self.lock:
            key = self.key(host,path,request)
            self._forget_memory(key)
            self.db.execute('DELETE FROM assets WHERE key=?',(key,))
            self.db.commit()

    def store(self, host, path, request, status, headers, body):
        if not eligible(host,path,request) or not cacheable(status,headers) or len(body)>min(self.max_bytes,self.max_item_bytes):
            return False
        now = time.time()
        with self.lock:
            self._forget_memory(self.key(host,path,request))
            self.db.execute('INSERT OR REPLACE INTO assets VALUES (?,?,?,?,?,?,?)',
                (self.key(host,path,request),json.dumps(headers),body,now,now+remaining_lifetime(headers,now),now,len(body)))
            size = self.db.execute('SELECT COALESCE(SUM(size),0) FROM assets').fetchone()[0]
            while size > self.max_bytes:
                key, removed = self.db.execute('SELECT key,size FROM assets ORDER BY used LIMIT 1').fetchone()
                self._forget_memory(key)
                self.db.execute('DELETE FROM assets WHERE key=?',(key,))
                size -= removed
            self.db.commit()
        return True

    def legacy(self, host, path, request):
        if not self.legacy_dir or not eligible(host,path,request):
            return None
        target = (self.legacy_dir/'https'/path.lstrip('/')).resolve()
        if not target.is_relative_to(self.legacy_dir):
            return None
        try:
            sidecar = Path(str(target)+'.ext').resolve()
            if not sidecar.is_relative_to(self.legacy_dir) or sidecar.stat().st_size > 8192:
                return None
            if target.stat().st_size > self.max_item_bytes:
                return None
            meta = json.loads(sidecar.read_text(encoding='utf-8-sig'))
            encoding = (meta.get('ce') or '').lower()
            if encoding and encoding != 'identity':
                encodings = {}
                for item in request.get('accept-encoding','').lower().split(','):
                    name, _, params = item.strip().partition(';')
                    encodings[name] = float(params.partition('=')[2]) if params else 1
                if encodings.get(encoding,encodings.get('*',0)) <= 0:
                    return None
            body = target.read_bytes()
            if hashlib.md5(body).hexdigest() != meta.get('md5'):
                return None
            headers = [('Content-Type',meta.get('ct',''))]
            for old,new in [('ce','Content-Encoding'),('ETag','ETag'),('LastModified','Last-Modified')]:
                if meta.get(old):
                    value = meta[old]
                    if not isinstance(value,str) or any(ord(c)<32 or ord(c)==127 for c in value):
                        return None
                    headers.append((new,value))
            if not cacheable(200,headers) or not any(k in meta for k in ('ETag','LastModified')):
                return None
            return Entry(headers,body,0,0,True)
        except (OSError,ValueError,TypeError,AttributeError):
            return None
