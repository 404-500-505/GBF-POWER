# GBF POWER 客户端 0.5.3

## 修复内容

- 旧 ACGP `.ext` 元数据不包含 CORS 响应头。此前直接命中版本化 JavaScript 时，浏览器可能收到 `200 OK` 后仍因 CORS 拒绝执行资源。
- 代理现在仅对受严格主机、路径、扩展名及无凭据条件约束的公共 GBF CDN 缓存资源恢复 `Access-Control-Allow-Origin: *`。
- 旧缓存文件保持只读，不需要清空或重新下载；游戏登录、战斗接口和实时连接仍保持 TLS 加密透传。

## 回归测试

测试使用 ACGP 格式的压缩 JavaScript 与 `.ext` 元数据，确认跨域游戏页面命中旧缓存时返回 CORS 头、保持 `ACGP-HIT`，且不会访问源站。
