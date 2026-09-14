"""Honest session metrics and UI operation state; no network side effects."""
from collections import deque
import math
import threading

def number(value):
    return '—' if value is None else str(int(value))

def display_stats(status):
    s=status or {}; c=s.get('cache') or {}
    tunnels=None
    if 'connect_tunnels' in s and 'socks5_tunnels' in s:
        tunnels=s['connect_tunnels']+s['socks5_tunnels']
    return dict(tunnels=tunnels,asset_requests=c.get('requests'),cache_hits=c.get('hits'),
                active=s.get('active_connections'),errors=s.get('errors'),
                saved_bytes=c.get('saved_bytes'))

class OperationGate:
    def __init__(self):
        self.state='stopped';self.busy=False;self.lock=threading.Lock()
    def begin(self,state):
        with self.lock:
            if self.busy:return False
            self.busy=True;self.state=state;return True
    def finish(self,state):
        with self.lock:self.state=state;self.busy=False

class Rates:
    def __init__(self):self.previous=None
    def update(self,instance,value,now):
        previous=self.previous
        self.previous=(instance,value,now) if value is not None else None
        if not previous or value is None:return None
        old,a,t=previous
        if old!=instance or value<a or not 0<now-t<=5:return None
        return (value-a)/(now-t)

class PingWindow:
    def __init__(self):self.samples=deque(maxlen=120)
    def add(self,ms,now):self.samples.append((now,ms))
    def view(self,now):
        rows=[(t,v) for t,v in self.samples if 0<=now-t<600]
        values=[v for _,v in rows if v is not None]
        return dict(sent=len(rows),received=len(values),
                    loss=(len(rows)-len(values))*100/len(rows) if values else None,
                    latest=rows[-1][1] if rows and now-rows[-1][0]<=20 else None,
                    average=sum(values)/len(values) if values else None)
    def quality(self,now):
        rows=[v for t,v in self.samples if 0<=now-t<600]
        values=sorted(v for v in rows if v is not None)
        timeouts=0
        for value in reversed(rows):
            if value is not None:break
            timeouts+=1
        p95=values[max(0,math.ceil(len(values)*.95)-1)] if values else 0
        return {'p95_ms':max(0,min(60000,round(p95))),'consecutive_timeouts':min(100,timeouts)}
