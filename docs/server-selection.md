# 服务器选型

本文不推荐具体商家。先购买月付或可退款的小规格实例，在真实用户网络的晚高峰连续测试，再决定长期方案。

## 起步规格

约 20 名轻度至中度用户可从以下规格测试：

- 1 核 CPU、1 GiB 内存、20 GiB SSD；
- 固定公网 IPv4；
- 端口速率最低 20 Mbps，约 20 人更建议 50 Mbps；
- 每月 200 GB 流量作为起步值，并按管理端实际上下行趋势留出至少 30% 余量。

200 GB 不是人数保证。素材缓存策略、游戏更新、同时在线时间、误入白名单的大文件和上下行计费方式都会改变消耗。先观察一周的 P95 与日累计，再扩容。

## 网络验收

从主要用户所在运营商分别测量：晚高峰 P50/P95 RTT、最终节点丢包、TCP 建连、TLS 首包、连续小请求和回程抖动。中间路由器不回复 ICMP 很常见；只有最终目标也持续丢包、TCP 重传或业务超时，才能支持“链路丢包”的结论。

对实时战斗更重要的是稳定的小请求延迟和抖动，不是测速站的峰值带宽。新节点至少观察 24 小时，保留旧节点作为回滚路径。

## 操作系统

新部署选择仍处于安全支持期的 Debian stable、Ubuntu LTS 或 Enterprise Linux 兼容发行版。CentOS Linux 7 已于 2024-06-30 停止维护，只作为遗留兼容环境，不建议新装。生命周期应以发行版官方页面为准：

- [Debian Releases](https://www.debian.org/releases/)说明稳定版及约五年的常规与 LTS 生命周期；
- [Ubuntu release cycle](https://ubuntu.com/about/release-cycle)说明 LTS 的标准安全维护周期；
- [CentOS Linux](https://www.centos.org/centos-linux/)列出 CentOS Linux 7 的停止维护日期。

脚本依赖 systemd、OpenSSH、GNU coreutils、`runuser`、`readlink` 和 Bash。遗留系统部署前要自行验证这些命令以及 Go 构建产物的运行兼容性。
