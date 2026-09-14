# 配置参考

所有 `*.example.json` 都是公开模板，不是可直接上线的配置。本项目仅供学习、研究与技术交流；请遵守所在地法律法规与服务条款，禁止未经许可经营 VPN、公共代理、绕过访问控制或实施其他违法行为。

## 控制服务

[单节点模板](../server/control/config.example.json)包含：

- `data_dir`：状态数据库与 `admin.sock` 所在绝对目录；
- `listen`：激活 HTTPS 监听地址；
- `tls_cert`、`tls_key`：控制端证书与私钥；
- `metering_listen`、`metering_host_key`、`metering_rules`：主节点 SSH 转发监听、主机密钥和目标规则；
- `node`：向客户端公布的主节点地址、端口、用户名和固定主机公钥。

安装器在目标机生成主节点 Ed25519 主机密钥，并替换 `PRIMARY_NODE_HOST_PUBLIC_KEY` 占位符。`data_dir` 和密钥路径必须是绝对路径，未知字段会被拒绝。

[多节点模板](../server/control/config.multinode.example.json)增加 `nodes` 与 `node_public_keys`。两节点组合必须为 `tokyo`、`osaka`；三节点组合为 `tokyo`、`tokyo_cn2`、`osaka`。顶层 `node` 必须与 `nodes.tokyo` 完全一致。

## 远程网关

[网关模板](../server/gateway/config.example.json)由安装器替换 `NODE_ID`、`CONTROL_URL`、`CONTROL_CERT_SHA256` 和 `CAPACITY_BPS`。控制地址必须使用 HTTPS，证书摘要是 64 位十六进制 SHA-256。`capacity_bps` 是调度参考容量，不是系统级带宽保证。

[规则模板](../server/gateway/rules.example.json)支持域名后缀、精确主机、SOCKS 主机和精确主机端口。公开模板使用保留地址与示例域名；运营者必须只填入有权访问且确有业务需要的最小目标集合。不要加入任意目标、通配公网或常见测速/下载站。

## Windows 构建配置

把 [activation.example.json](../client/windows/app/assets/activation.example.json) 复制为 `activation.local.json`，填入控制域名、端口和证书摘要。把 [rules.example.json](../client/windows/proxy_core/rules.example.json) 复制为 `rules.local.json` 并复核白名单。这两个 `*.local.json` 已被 Git 忽略。

离线校验命令：

```text
gbf-activation check-config --config control.json
gbf-activation check-gateway-config --config gateway.json
```

校验只解析结构，不绑定端口、不创建状态，也不证明引用的证书、密钥或网络端点可用。
