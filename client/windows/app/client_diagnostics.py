"""Bounded client probes and snapshots, independent of Tk and credentials."""
import queue
import socket
import threading
import time

# DNS resolution is not covered by socket's connect timeout on every platform.
# Daemon workers must not hold process exit, and stalled DNS must not grow threads.
_probe_slots = {key: threading.BoundedSemaphore(1) for key in ('tokyo','tokyo_cn2','osaka')}


def tcp_probe(node):
    started = time.monotonic()
    try:
        with socket.create_connection((node['host'], int(node['port'])), timeout=2):
            return (time.monotonic() - started) * 1000
    except (OSError, ValueError, TypeError, KeyError):
        return None


def probe_nodes(nodes, probe=tcp_probe, timeout=2.5):
    selected = {key: node for key, node in nodes.items()
                if key in ('tokyo', 'tokyo_cn2', 'osaka') and isinstance(node, dict)}
    if not selected:
        return {}
    results = {key: None for key in selected}
    completed = queue.Queue()
    pending = 0
    def worker(key, node):
        try:
            try: value = probe(node)
            except Exception: value = None
            completed.put((key, value))
        finally:
            _probe_slots[key].release()
    for key, node in selected.items():
        if not _probe_slots[key].acquire(blocking=False):
            continue
        try:
            threading.Thread(target=worker,args=(key,node),daemon=True,name='node-probe').start()
            pending += 1
        except Exception:
            _probe_slots[key].release()
            raise
    deadline = time.monotonic() + timeout
    for _ in range(pending):
        try:
            key, value = completed.get(timeout=max(0,deadline-time.monotonic()))
        except queue.Empty:
            break
        results[key] = value
    return results


def runtime_route(status):
    status = status or {}
    servers = {(status.get(key) or {}).get('server') for key in ('tunnel', 'game_channel')
               if (status.get(key) or {}).get('connected')}
    if len(servers) != 1 or not next(iter(servers)):
        return None
    return status.get('instance'), next(iter(servers))


class CertificateSnapshot:
    def __init__(self, read):
        self.read = read
        self.root = None
        self.checked = None
        self.value = None

    def get(self, root, now, refresh=False):
        if refresh or root != self.root or self.checked is None or now-self.checked >= 30:
            self.value = self.read(root)
            self.root, self.checked = root, now
        return self.value
