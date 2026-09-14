# Windows 客户端源码

公开仓库不会携带线上激活入口、证书摘要、设备私钥或服务器主机记录。

构建前把 `assets/activation.example.json` 复制为被 Git 忽略的 `assets/activation.local.json`，填入自建控制服务地址与证书 SHA-256 摘要；再把 `../proxy_core/rules.example.json` 复制为 `../proxy_core/rules.local.json` 并复核最小目标白名单。

客户端首次激活时在用户配置目录生成设备 Ed25519 私钥。请勿复制或公开该文件；泄露者在凭据被撤销前可以冒充对应设备。
