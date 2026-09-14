# GBF Power

GBF Power 是一个用于学习和研究设备授权、加密通信、受限目标转发、远程节点计量及 Windows 桌面打包流程的开源参考项目。仓库包含控制服务、网关、Windows 客户端、运营管理端、通用部署脚本和测试。

本项目为非官方项目，与任何游戏开发商、发行商或平台均无隶属关系，也未获得其背书。项目仅供学习、研究与技术交流。使用者必须遵守所在地法律法规以及相关服务条款。

禁止使用本项目在未经许可的情况下搭建或经营 VPN、公共代理，绕过访问控制，或实施任何违法行为。项目维护者不鼓励、支持或授权此类用途。

仅为学习交流使用，请各位骑空士加油·呆

## 快速开始

先阅读架构和安全边界，再选择单节点或多节点部署：

- [系统架构](docs/architecture.md)
- [安全模型](docs/security-model.md)
- [服务器选型](docs/server-selection.md)
- [单节点部署](docs/deploy-single-node.md)
- [多节点部署](docs/deploy-multi-node.md)
- [配置参考](docs/configuration.md)
- [日常运维](docs/operations.md)
- [Windows 构建](docs/build-windows.md)
- [故障排查](docs/troubleshooting.md)
- [常见问题](docs/faq.md)

示例配置只能作为模板。部署前必须替换全部占位符、缩小目标白名单，并把真实配置保存在仓库外或被 Git 忽略的 `*.local.json` 中。

## 许可证

本项目以 `AGPL-3.0-only` 许可发布。完整条款见 [LICENSE](LICENSE)。

依赖组件仍受各自许可证约束，记录要求见 [THIRD_PARTY.md](THIRD_PARTY.md)。

## 安全

请先阅读 [SECURITY.md](SECURITY.md)。不要在公开议题、提交、日志或截图中披露漏洞细节、设备私钥、激活凭据或基础设施信息。

## 参与贡献

开发流程、测试要求、脱敏规则与发布门禁见 [CONTRIBUTING.md](CONTRIBUTING.md)。
