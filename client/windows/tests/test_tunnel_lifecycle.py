import asyncio
from pathlib import Path
import sys
import time
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'proxy_core'))

import gbf_proxy
from ssh_tunnel import SshTunnel


class TimedResource:
    def __init__(self, delay):
        self.delay = delay
        self.started = False
        self.closed = False

    async def start(self):
        self.started = True
        await asyncio.sleep(self.delay)

    async def close(self):
        self.closed = True
        await asyncio.sleep(self.delay)


class StubbornProcess:
    def __init__(self):
        self.returncode = None
        self.terminated = False
        self.killed = False

    def terminate(self):
        self.terminated = True

    def kill(self):
        self.killed = True
        self.returncode = -9

    async def wait(self):
        if self.killed:
            return self.returncode
        await asyncio.Event().wait()


class TunnelLifecycleTests(unittest.IsolatedAsyncioTestCase):
    async def test_two_tunnels_start_concurrently(self):
        first = TimedResource(.15)
        second = TimedResource(.15)
        started = time.monotonic()
        await gbf_proxy.start_tunnels(first, second)
        elapsed = time.monotonic() - started
        self.assertTrue(first.started and second.started)
        self.assertLess(elapsed, .25, f'tunnel startup was serial: {elapsed:.3f}s')

    async def test_resources_close_concurrently(self):
        first = TimedResource(.15)
        second = TimedResource(.15)
        started = time.monotonic()
        await gbf_proxy.close_resources(first, second)
        elapsed = time.monotonic() - started
        self.assertTrue(first.closed and second.closed)
        self.assertLess(elapsed, .25, f'resource cleanup was serial: {elapsed:.3f}s')

    async def test_stubborn_ssh_process_is_killed_within_short_deadline(self):
        tunnel = SshTunnel({}, Path('.'), Path('.'))
        process = StubbornProcess()
        tunnel.process = process
        started = time.monotonic()
        await tunnel.stop_process()
        elapsed = time.monotonic() - started
        self.assertTrue(process.terminated)
        self.assertTrue(process.killed)
        self.assertLess(elapsed, 1.5, f'SSH shutdown exceeded deadline: {elapsed:.3f}s')


if __name__ == '__main__':
    unittest.main()
