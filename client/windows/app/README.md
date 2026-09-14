# Windows 客户端源码

公开仓库不会携带线上激活入口、证书摘要、设备私钥或服务器主机记录。

构建前把 `assets/activation.example.json` 复制为被 Git 忽略的 `assets/activation.local.json`，填入自建控制服务地址与证书 SHA-256 摘要；再把 `../proxy_core/rules.example.json` 复制为 `../proxy_core/rules.local.json` 并复核最小目标白名单。

客户端首次激活时在用户配置目录生成设备 Ed25519 私钥。请勿复制或公开该文件；泄露者在凭据被撤销前可以冒充对应设备。

本地素材缓存使用 ACGP 兼容的版本目录、原文件和 `.ext` 元数据布局。旧 ACGP 缓存路径不固定，用户可在客户端菜单中自行选择 ACGP 程序根目录或 `cache`、`gbf`、`https`、`assets` 层级；安装包不会携带任何用户缓存或写死旧路径。

本项目仅供学习、研究与技术交流。请遵守所在地法律法规和相关服务条款；禁止未经许可经营 VPN、公共代理、绕过访问控制或实施其他违法行为。
