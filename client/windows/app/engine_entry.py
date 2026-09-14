"""Reuse the verified proxy core without editing the live script installation."""
from pathlib import Path
import sys
import time
import re
import uuid
import h11
import asset_gateway
import gbf_proxy

class CountedGateway(asset_gateway.AssetGateway):
    def __init__(self,*args,**kwargs):
        super().__init__(*args,**kwargs)
        self.stats['requests']=0
    async def serve(self,*args,**kwargs):
        # Reached only after CDN/SNI/Host, method and framing validation.
        self.stats['requests']+=1
        return await super().serve(*args,**kwargs)

class SessionProxy(gbf_proxy.ProxyServer):
    def __init__(self,*args,**kwargs):
        super().__init__(*args,**kwargs)
        self.instance=uuid.uuid4().hex

def run_engine(root,gate):
    # Parent assigns its Job Object before authorizing any network activity.
    if not re.fullmatch(r'start-[0-9a-f]{32}\.gate',gate):return 2
    permit=Path(root)/'runtime'/gate
    deadline=time.monotonic()+10
    while not permit.is_file():
        if time.monotonic()>deadline:return 2
        time.sleep(.03)
    permit.unlink()
    gbf_proxy.ROOT=Path(root).resolve()
    gbf_proxy.load_rules.__defaults__=(gbf_proxy.ROOT/'rules.json',)
    asset_gateway.AssetGateway=CountedGateway
    gbf_proxy.ProxyServer=SessionProxy
    sys.argv=[sys.argv[0]]
    return gbf_proxy.main()
