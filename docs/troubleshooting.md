# 故障排查

## 客户端提示端口占用

Windows `WinError 10048` 表示本机监听地址已被进程占用，常见原因是上次代理仍在运行。先在客户端点击停止；仍失败时检查对应端口的 PID，再确认它是否属于当前安装。不要盲目结束不明进程或反复启动多个实例。

## SSH 密钥 Permission denied

区分管理密钥与设备密钥。管理部署脚本读取的私钥必须由当前管理员账户可读，且 Windows OpenSSH 会拒绝 ACL 过宽的私钥。不要把管理密钥复制进客户端、安装包或仓库；修复文件所有者和 ACL 后，用 `ssh -F none -i ...` 单独验证。

普通用户不应配置服务器私钥或服务器公钥文件。客户端激活后自行生成设备私钥，服务端返回已固定的 SSH 主机公钥。

## 服务启动失败

依次检查：

```bash
sudo systemctl status gbf-control.service --no-pager
sudo journalctl -u gbf-control.service -n 100 --no-pager
/usr/local/lib/gbf-power/gbf-activation check-config --config /etc/gbf-power/control/config.json
```

网关改用 `gbf-gateway.service` 和 `check-gateway-config`。重点核对文件所有者、`0600` 私钥、未替换占位符、证书路径、监听端口及云/主机防火墙。

## 节点显示正常但设备离线

节点健康上报与设备会话是不同指标。检查客户端是否仍有认证 SSH 会话、设备是否被撤销、租约是否过期、系统时钟是否偏差，以及控制端和网关是否使用匹配的节点身份公钥。

## 浏览器请求 Stalled 或红叉

先查看 Request URL、端口、错误类型与时间线。长轮询/实时端点可能持续处于 pending；刷新触发的旧请求取消也可能显示红叉。只有业务操作确实未更新，并且目标端点被规则遗漏、连接提前 EOF 或持续超时，才是代理异常证据。

## 延迟异常

同时对控制地址、节点、业务 HTTPS 做多轮 TCP/TLS 探测。WinMTR 中间跳高丢包但最终节点 0% 通常是 ICMP 限速；最终节点持续丢包、最差延迟突增且业务请求同步变慢，才应更换线路或节点。客户端“线路延迟”与“公开页响应”测量对象不同，不能混为一个数。
