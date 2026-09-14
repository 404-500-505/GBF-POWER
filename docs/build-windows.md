# Windows 客户端与管理端构建

## 环境

建议在干净的 64 位 Windows 构建机使用受支持的 Python 3、PyInstaller、`cryptography`、`cffi`、`h11`、Pillow 和 Inno Setup。`ISCC.exe` 必须位于 `PATH`。构建机不应保存生产 SSH 管理密钥或服务端状态。

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install pyinstaller cryptography cffi h11 pillow
```

依赖版本和许可证需按实际发布锁定并更新 [THIRD_PARTY.md](../THIRD_PARTY.md)。

## 客户端

1. 把 `client/windows/app/assets/activation.example.json` 复制为 `activation.local.json`。
2. 填入自建控制服务域名、端口和真实证书 SHA-256 摘要；示例域名和全零摘要会让构建失败。
3. 把 `client/windows/proxy_core/rules.example.json` 复制为 `rules.local.json`，只保留必要目标。
4. 运行构建：

```powershell
python client\windows\app\build.py
```

构建脚本采用显式文件清单，生成 payload 哈希清单，并拒绝设备私钥、运行目录、状态、生产配置与 PEM 私钥进入安装包。安装后设备密钥才在本机生成。

仓库只提供原创中性 [SVG 图标](../assets/icon.svg)。如需替换图标，必须确认拥有分发权，并自行生成合法的 ICO/PNG 资源；不要提交游戏角色、商标或来源不明的图片。

## 管理端

```powershell
python admin\build.py
```

管理端不打包 `known_hosts`、SSH 私钥或线上地址。首次运行由运营者在连接设置中选择独立管理密钥和主机公钥文件。普通用户不应获得管理端或管理 SSH 权限。

## 发布前检查

```powershell
python -m unittest discover -s client\windows\tests -p 'test_*.py' -v
python -m unittest discover -s admin\tests -p 'test_*.py' -v
pwsh -File scripts\check-public-release.ps1
```

安装包仅供学习、研究与技术交流。分发者和使用者必须遵守所在地法律法规及服务条款，禁止未经许可经营 VPN、公共代理、绕过访问控制或从事其他违法行为。
