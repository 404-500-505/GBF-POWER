import asyncio
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import AsyncMock,patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'app'))
import client_runtime
import engine_entry as e
import asset_gateway

class EngineTests(unittest.IsolatedAsyncioTestCase):
    async def test_unique_session_each_restart(self):
        rules={'domain_suffixes':[],'exact_hosts':[],'socks5_hosts':[]}
        a=e.SessionProxy(rules=rules);b=e.SessionProxy(rules=rules)
        self.assertNotEqual(a.instance,b.instance)
    async def test_requests_count_at_real_gateway_entry(self):
        class Cache:
            def status(self):return {}
        g=e.CountedGateway(Cache(),Path('unused'),None)
        with patch.object(asset_gateway.AssetGateway,'serve',new_callable=AsyncMock) as serve:
            await g.serve('connection','writer','GET','host','path',[],{},True)
            await g.serve('connection','writer','GET','host','path',[],{},True)
            self.assertEqual(g.stats['requests'],2)
            self.assertEqual(serve.await_count,2)
