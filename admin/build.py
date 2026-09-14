"""Build a separate owner UI; only explicitly public assets are bundled."""
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess
import sys

ROOT=Path(__file__).resolve().parent

def main():
    assets=ROOT/'assets'
    assets.mkdir(exist_ok=True)
    shutil.copyfile(ROOT/'README.md',assets/'README.md')
    allowed={'README.md'}
    if any(p.name not in allowed for p in assets.iterdir()):raise RuntimeError('Unexpected admin asset')
    args=['--noconfirm','--onedir','--windowed','--name','GBFPowerAdmin',
          '--distpath',str(ROOT/'dist'),'--workpath',str(ROOT/'build'),
          '--specpath',str(ROOT),'--add-data',str(assets)+':assets',
          str(ROOT/'app.py')]
    subprocess.run([sys.executable,'-m','PyInstaller',*args],cwd=ROOT,check=True)
    manifest=[]
    for path in (ROOT/'dist/GBFPowerAdmin').rglob('*'):
        if not path.is_file():continue
        if path.name in ('id_ed25519','connection.json','state.json','ops.json','tls.key','owner-activation-code.txt'):raise RuntimeError('Private artifact in payload')
        if path.suffix.lower() in ('.txt','.json','.pem','.key'):
            if re.search(rb'-----BEGIN [A-Z ]*PRIVATE KEY-----|GBF-[A-F0-9]{32}',path.read_bytes()):raise RuntimeError('Private content in payload')
        manifest.append({'path':path.relative_to(ROOT/'dist/GBFPowerAdmin').as_posix(),'sha256':hashlib.sha256(path.read_bytes()).hexdigest()})
    (ROOT/'payload-manifest.json').write_text(json.dumps(manifest,indent=2),encoding='utf-8')
    iscc=shutil.which('ISCC.exe') or shutil.which('iscc')
    if not iscc:raise RuntimeError('Inno Setup compiler was not found on PATH')
    subprocess.run([iscc,'/Qp',str(ROOT/'installer.iss')],cwd=ROOT,check=True)
    print('Admin installer built; private artifact checks passed.')

if __name__=='__main__':main()
