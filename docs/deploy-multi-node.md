# 多节点部署

本部署仅供学习、研究与技术交流。必须遵守所在地法律法规、网络使用政策和服务条款；禁止未经许可经营 VPN、公共代理、绕过访问控制或实施其他违法行为。

## 准备配置

先按[单节点部署](deploy-single-node.md)完成主节点。远程节点必须拥有独立系统、独立 Ed25519 主机密钥与节点身份密钥，不能复制主节点或其他网关的私钥。

将 `deploy/multinode/parameters.example.json` 复制为被 Git 忽略的 `parameters.local.json`。填写两个 SSH 管理端点、已固定的 `known_hosts`、管理私钥路径、控制证书摘要、节点容量和实际可达主机名。管理账户应具备受控的 `sudo` 权限，不要求使用 root 直接登录。

首次扩展为两节点时，控制服务当前接受 `tokyo` 与 `osaka` 组合；扩展为三节点时使用 `tokyo`、`tokyo_cn2`、`osaka`。控制配置模板必须描述完整目标拓扑，只给本次新增节点保留 `GATEWAY_*` 占位符。

## 防火墙

远程网关仅开放其 SSH 转发端口，例如 `2222/tcp`，并把管理 SSH 限制到运营来源。它需要出站访问控制 HTTPS 和白名单业务目标。控制端内部节点接口复用控制 HTTPS，但仍要求节点签名与证书摘要固定。

## 安装

在 Windows PowerShell 中执行：

```powershell
pwsh -File deploy/multinode/Add-Gateway.ps1 -ParametersFile .\parameters.local.json
```

脚本会上传公开二进制与配置模板，在目标网关本地生成两把私钥，只接收两把公钥，然后把公钥写入完整控制配置并通过控制安装器更新。任何远程地址都来自参数文件；私钥不会下载到管理电脑。

## 验证

在两台服务器上分别检查：

```bash
sudo systemctl status gbf-gateway.service --no-pager
sudo systemctl status gbf-control.service --no-pager
```

管理端应看到节点签名上报时间更新、健康状态正常、实际连接数与设备会话一致。再验证用户选择线路、自动选择、节点断开后的收敛，以及非白名单目标拒绝。不要把 Ping 中间跳丢包直接当成业务丢包。

## 回滚

网关安装器和控制安装器分别在本机保留本次暂存备份并在重启失败时自动恢复，但跨两台服务器不是分布式事务。若网关成功而控制更新失败，网关不会获得有效设备授权；修复控制模板后重跑，或停止新网关服务。

## 卸载

先从控制配置移除节点并重启控制服务，等待租约过期，再在网关执行：

```bash
sudo systemctl disable --now gbf-gateway.service
sudo rm -f /etc/systemd/system/gbf-gateway.service
sudo systemctl daemon-reload
```

确认没有其他服务共用二进制后再删除程序。节点私钥留在 `/etc/gbf-power/gateway`；按组织的密钥销毁流程处理，不要下载留档。
