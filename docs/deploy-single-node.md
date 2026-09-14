# 单节点部署

本部署仅用于学习、研究与技术交流。请遵守所在地法律法规和服务条款；禁止未经许可经营 VPN、公共代理、绕过访问控制或实施其他违法行为。

## 准备配置

服务器需有 systemd、OpenSSH、Bash、`runuser` 与基础 GNU 工具。构建 amd64 Linux 二进制：

```bash
cd server/control
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -o ../../gbf-activation .
cd ../..
```

复制 `server/control/config.example.json` 为仓库外的 `control.local.json`，把 `node.host` 改为客户端可达的自有域名或地址。保留 `PRIMARY_NODE_HOST_PUBLIC_KEY` 占位符，安装器会用目标机生成的主机公钥替换它。

准备控制服务 TLS 证书和私钥。客户端固定叶证书摘要，证书必须与客户端配置同时管理。将 `server/gateway/rules.example.json` 复制为 `rules.local.json`，只加入经授权的必要目标。

## 防火墙

仅开放控制 HTTPS 端口和主节点 SSH 转发端口，例如 `18444/tcp` 与 `2222/tcp`。管理 SSH 应限制到运营来源地址。不要开放 `admin.sock`；它是本机 Unix Socket，不需要网络端口。

云防火墙与主机防火墙必须同时核对。出站侧也应限制到规则允许的业务目标。

## 安装

从仓库根运行：

```bash
sudo ./deploy/control/install.sh \
  --binary ./gbf-activation \
  --config ./control.local.json \
  --tls-cert ./control.crt \
  --tls-key ./control.key \
  --metering-rules ./rules.local.json
```

安装器创建不可登录的 `gbf-control` 账户，以 `0700` 创建配置和状态目录，以 `0600` 保存私钥和配置，执行离线校验后再替换文件。重复运行不会删除 `state.json`。

## 验证

```bash
sudo systemctl status gbf-control.service --no-pager
sudo ss -lntp
sudo -u gbf-control /usr/local/lib/gbf-power/gbf-activation \
  --admin /var/lib/gbf-power/control/admin.sock list
```

再从实际客户端网络验证证书摘要、激活、一台设备连接、白名单目标成功以及非白名单目标被拒绝。不要用真实账号凭据做自动化部署测试。

## 回滚

安装器在服务重启失败时自动恢复本次替换前的二进制、配置、证书、规则和 unit，再尝试启动旧服务。状态目录不参与替换。人工升级前仍应备份 `/var/lib/gbf-power/control`，并验证备份权限。

## 卸载

先撤销设备并停止服务：

```bash
sudo systemctl disable --now gbf-control.service
sudo rm -f /etc/systemd/system/gbf-control.service
sudo systemctl daemon-reload
```

确认不再有网关共用二进制后，才删除 `/usr/local/lib/gbf-power/gbf-activation`。配置、私钥和状态包含敏感信息；先完成合规留存或安全销毁决策，不要直接复制到公开位置。
