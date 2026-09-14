"""Real Windows parent crash -> job child and grandchild are terminated."""
import json
from pathlib import Path
import socket
import subprocess
import sys
import time
import unittest

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'app'))
from client_runtime import ports_free

class JobTests(unittest.TestCase):
    def test_parent_crash_releases_grandchild_listener(self):
        with socket.socket() as s:s.bind(('127.0.0.1',0));port=s.getsockname()[1]
        grandchild=f'import socket,time; s=socket.socket(); s.bind(("127.0.0.1",{port})); s.listen(); time.sleep(60)'
        child='import sys,subprocess,time; sys.stdin.readline(); p=subprocess.Popen([sys.executable,"-c",'+repr(grandchild)+']); p.wait()'
        parent=('import sys,subprocess,time; sys.path.insert(0,'+repr(str(Path(__file__).resolve().parents[1]/'app'))+'); '
                'from win_job import Job; j=Job(); p=subprocess.Popen([sys.executable,"-c",'+repr(child)+'],stdin=subprocess.PIPE); '
                'j.assign(p); p.stdin.write(b"go\\n"); p.stdin.flush(); time.sleep(60)')
        p=subprocess.Popen([sys.executable,'-c',parent],creationflags=subprocess.CREATE_NO_WINDOW,
                           stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        try:
            due=time.monotonic()+7
            while time.monotonic()<due and ports_free([port]):time.sleep(.1)
            self.assertFalse(ports_free([port]),'fixture grandchild did not start')
            p.terminate();p.wait(timeout=5)
            due=time.monotonic()+5
            while time.monotonic()<due and not ports_free([port]):time.sleep(.1)
            self.assertTrue(ports_free([port]),'grandchild survived parent crash')
        finally:
            if p.poll() is None:p.terminate();p.wait(timeout=5)

if __name__=='__main__':unittest.main()
