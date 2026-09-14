"""Bounded, privacy-filtered observations; no proxy control or routing changes."""
from collections import deque
import copy
import threading


class Metrics:
    def __init__(self):
        self.lock = threading.RLock()
        self.previous = None
        self.current = {}
        self.history = deque(maxlen=300)
        self.pings = deque(maxlen=61)
        self.responses = deque(maxlen=41)
        self.events = deque(maxlen=30)

    def event(self, message, now):
        self.events.appendleft({'time': now, 'message': message})

    def update(self, source, now):
        with self.lock:
            old = self.current
            valid = isinstance(source, dict) and source.get('app') == 'gbf-local-proxy'
            s = source if valid else {}
            t = s.get('tunnel') or {}
            cache = s.get('cache') or {}
            state = {'time': now, 'proxy_online': valid,
                     'connected': valid and t.get('connected') is True,
                     'down_bps': None, 'up_bps': None}
            for field in ('instance', 'version', 'uptime_seconds', 'active_connections',
                          'errors', 'bytes_uploaded', 'bytes_downloaded'):
                state[field] = s.get(field)
            state['tunnel'] = {k: t.get(k) for k in ('server', 'connected', 'reconnects')}
            state['cache'] = {k: cache.get(k) for k in (
                'enabled', 'hits', 'misses', 'revalidated', 'legacy_hits', 'bypassed',
                'saved_bytes', 'stored', 'errors', 'entries', 'bytes', 'max_bytes',
                'memory_hits', 'memory_entries', 'memory_bytes', 'max_memory_bytes',
                'origin_opened', 'origin_reused', 'origin_retries', 'origin_idle')}
            previous = self.previous
            restarted = bool(valid and previous and (
                s.get('instance') != previous.get('instance') or
                (s.get('uptime_seconds') or 0) < (previous.get('uptime_seconds') or 0)))
            if restarted:
                self.event('本地代理重新启动，速率基线已重置', now)
            if valid and previous and not restarted and 0 < now - previous['time'] <= 5:
                for counter, rate in (('bytes_downloaded', 'down_bps'), ('bytes_uploaded', 'up_bps')):
                    a, b = s.get(counter), previous.get(counter)
                    if isinstance(a, (float, int)) and isinstance(b, (float, int)) and a >= b:
                        state[rate] = (a - b) / (now - previous['time'])
            if old.get('connected') != state['connected'] or old.get('proxy_online') != valid:
                self.event('日本通道已连接' if state['connected'] else
                           ('日本通道断开，本地代理仍在运行' if valid else '本地代理状态不可用 / 已断开'), now)
            elif valid and old.get('tunnel', {}).get('reconnects') != state['tunnel']['reconnects']:
                self.event('SSH 重连计数发生变化', now)
            self.current = state
            self.previous = state if valid else None
            self.history.append({k: state[k] for k in ('time', 'down_bps', 'up_bps', 'connected')})

    def ping(self, ms, now):
        with self.lock:
            self.pings.append({'time': now, 'ms': ms})

    def gbf(self, ms, status, now):
        with self.lock:
            self.responses.append({'time': now, 'ms': ms, 'status': status})

    def snapshot(self, now):
        with self.lock:
            pings = [p for p in self.pings if 0 <= now - p['time'] < 600]
            responses = [p for p in self.responses if 0 <= now - p['time'] < 600]
            received = sum(p['ms'] is not None for p in pings)
            ping = {'sent': len(pings), 'received': received,
                    'loss_percent': (len(pings) - received) * 100 / len(pings) if received else None,
                    'ms': pings[-1]['ms'] if pings and now - pings[-1]['time'] <= 25 else None,
                    'time': pings[-1]['time'] if pings else None, 'history': pings}
            gbf = dict(responses[-1]) if responses else {'ms': None, 'status': None, 'time': None}
            if gbf['time'] is not None and now - gbf['time'] > 35:
                gbf['ms'] = None
                gbf['status'] = None
            gbf['history'] = responses
            state = dict(self.current)
            if not state or now - state.get('time', 0) > 5:
                state.update(proxy_online=False, connected=False, down_bps=None, up_bps=None)
            state.update(ping=ping, gbf=gbf, history=list(self.history), events=list(self.events))
            return copy.deepcopy(state)
