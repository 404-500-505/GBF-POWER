"""Explicit-whitelist reproducible client payload. No runtime directories included."""
import ctypes
import hashlib
import importlib.metadata
import json
import re
from pathlib import Path
import shutil
import subprocess
import sys

ROOT=Path(__file__).resolve().parent
CORE=ROOT.parent/'proxy_core'
ASSETS=ROOT/'assets'

def main():
    ASSETS.mkdir(exist_ok=True)
    bootstrap=json.loads((ASSETS/'activation.local.json').read_text(encoding='utf-8'))
    if (set(bootstrap)!={'host','port','certificate_sha256'} or
            not re.fullmatch('[a-zA-Z0-9.-]+',bootstrap.get('host','')) or
            bootstrap['host'].endswith('.example.com') or
            not 1<=int(bootstrap.get('port',0))<=65535 or
            not re.fullmatch('[0-9a-fA-F]{64}',bootstrap.get('certificate_sha256','')) or
            bootstrap['certificate_sha256']=='0'*64):
        raise RuntimeError('Copy activation.example.json to activation.local.json and provide a real deployment endpoint and certificate pin')
    # Public routing rules only; never copy the static user PAC or a configuration/key bundle.
    rules=CORE/'rules.local.json'
    if not rules.is_file():
        raise RuntimeError('Copy rules.example.json to rules.local.json and review the destination allowlist')
    json.loads(rules.read_text(encoding='utf-8'))
    shutil.copyfile(rules,ASSETS/'rules.json')
    shutil.copyfile(ROOT/'README.md',ASSETS/'README.md')
    notices=ASSETS/'licenses';notices.mkdir(exist_ok=True)
    shutil.copyfile(Path(sys.base_prefix)/'LICENSE.txt',notices/'Python.txt')
    for package in ('pyinstaller','cryptography','cffi','h11','pillow'):
        distribution=importlib.metadata.distribution(package)
        for entry in distribution.files or []:
            if '/licenses/' in str(entry) and Path(str(entry)).name.upper().startswith(('LICENSE','COPYING')):
                shutil.copyfile(distribution.locate_file(entry),notices/(package+'-'+Path(str(entry)).name))
    flags=['--noconfirm','--onedir','--windowed','--name','GBFPower',
           '--additional-hooks-dir',str(ROOT/'hooks'),
           '--distpath',str(ROOT/'dist'),'--workpath',str(ROOT/'build'),
           '--specpath',str(ROOT),'--paths',str(CORE),
           '--add-data',str(ASSETS)+':assets',
           '--hidden-import','engine_entry','--hidden-import','gbf_proxy',
           '--hidden-import','asset_gateway','--hidden-import','cache_certificate',
           '--hidden-import','cryptography','--hidden-import','h11',str(ROOT/'app.py')]
    subprocess.run([sys.executable,'-m','PyInstaller',*flags],check=True,cwd=ROOT)
    payload=ROOT/'dist/GBFPower'
    forbidden={'id_ed25519','leaf-key.pem','ca.pem','state.json','client.json','config.json','tls.key','owner-activation-code.txt'}
    files=[]
    for path in payload.rglob('*'):
        if path.is_file():
            relative=path.relative_to(payload).as_posix()
            if path.name in forbidden or 'runtime/' in relative:raise RuntimeError('Private runtime artifact in payload')
            if path.suffix in ('.pem','.key','.txt','.json') and re.search(rb'-----BEGIN [A-Z ]*PRIVATE KEY-----',path.read_bytes()):
                raise RuntimeError('Private key material in payload')
            files.append({'path':relative,'bytes':path.stat().st_size,'sha256':hashlib.sha256(path.read_bytes()).hexdigest()})
    for required in ('tcl86t.dll','tk86t.dll','_tkinter.pyd'):
        if not (payload/'_internal'/required).is_file():raise RuntimeError('Missing bundled Tk runtime: '+required)
    (ROOT/'payload-manifest.json').write_text(json.dumps(files,indent=2),encoding='utf-8')
    iscc=shutil.which('ISCC.exe') or shutil.which('iscc')
    if not iscc:raise RuntimeError('Inno Setup compiler was not found on PATH')
    subprocess.run([iscc,'/Qp',str(ROOT/'installer.iss')],check=True,cwd=ROOT)
    print('Built installer; payload manifest verified (no private keys/configuration/runtime).')

if __name__=='__main__':main()
