"""Standalone owner administration application."""
import argparse
import ctypes
import json
import os
from pathlib import Path

def main():
    parser=argparse.ArgumentParser();parser.add_argument('--home',type=Path);parser.add_argument('--preview',action='store_true');parser.add_argument('--screenshot',type=Path);parser.add_argument('--self-test',type=Path)
    args=parser.parse_args()
    from admin_ui import AdminWindow,create_root
    home=args.home or Path(os.environ['LOCALAPPDATA'])/'GBFPowerAdmin'
    root=create_root();app=AdminWindow(root,home,preview=args.preview or bool(args.self_test))
    if args.self_test:
        assert not app.licenses.get_children();assert '尚未连接' in app.status.cget('text')
        args.self_test.write_text(json.dumps({'passed':['native-window','empty-not-online','no-network-in-self-test']}),encoding='utf-8');root.destroy();return
    if args.screenshot:
        def shot():
            from PIL import ImageGrab
            root.update();hwnd=ctypes.windll.user32.GetParent(root.winfo_id())
            try:ImageGrab.grab(window=hwnd).save(args.screenshot)
            finally:app.closed=True;root.destroy()
        root.after(1200,shot)
    root.mainloop()

if __name__=='__main__':
    try:main()
    except Exception:
        # Never log exception payloads: a failing create operation may contain a code.
        ctypes.windll.user32.MessageBoxW(None,'管理窗口启动失败，请检查安装是否完整及数据目录权限。','GBF POWER 管理',0x10)
        raise SystemExit(1)
