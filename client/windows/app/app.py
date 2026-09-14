"""GBF Desktop entry point (GUI or job-owned engine)."""
import os
from pathlib import Path
import sys
import traceback

BASE=Path(__file__).resolve().parent
if not getattr(sys,'frozen',False):sys.path.insert(0,str(BASE.parent/'proxy_core'))

if __name__=='__main__':
    if len(sys.argv)==5 and sys.argv[1]=='--engine' and sys.argv[3]=='--gate':
        from engine_entry import run_engine
        data=Path(sys.argv[2])
        try:code=run_engine(sys.argv[2],sys.argv[4])
        except Exception:
            (data/'runtime/worker-error.log').write_text(traceback.format_exc(),encoding='utf-8');code=1
        raise SystemExit(code)
    if len(sys.argv)==3 and sys.argv[1]=='--self-test':
        from frozen_check import check
        check(sys.argv[2]);raise SystemExit(0)
    try:
        from desktop_ui import main
        main()
    except Exception:
        folder=(Path(sys.argv[sys.argv.index('--home')+1]) if '--home' in sys.argv
                else Path(os.environ['LOCALAPPDATA'])/'GBFDesktop')
        folder.mkdir(parents=True,exist_ok=True)
        error_file=folder/'desktop-error.log'
        error_file.write_text(traceback.format_exc(),encoding='utf-8')
        if '--preview' not in sys.argv and '--uninstall' not in sys.argv:
            import ctypes
            ctypes.windll.user32.MessageBoxW(None,'客户端启动失败，详细信息：\n'+str(error_file),'GBF POWER',0x10)
        raise SystemExit(1)
