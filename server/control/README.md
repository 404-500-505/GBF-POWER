# 控制服务配置

`config.example.json` 是单节点模板，`config.multinode.example.json` 是新增一个远程节点时的模板。复制到仓库外或被忽略的 `*.local.json` 后填写；不要提交真实地址、证书摘要、SSH 主机公钥、节点身份公钥或状态目录内容。

安装器会在控制机生成主节点 SSH 主机密钥，并替换 `PRIMARY_NODE_HOST_PUBLIC_KEY`。其他 `GATEWAY_*` 占位符由多节点接入脚本替换。可用 `gbf-activation check-config --config FILE` 离线验证严格 JSON 结构。

本项目仅供学习、研究与技术交流。请遵守所在地法律法规和相关服务条款；禁止未经许可经营 VPN、公共代理、绕过访问控制或实施其他违法行为。
