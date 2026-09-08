# AGENTS.md

## 踩坑记录

- 安全校验结果类型（如 CRL/证书吊销检查）默认必须 fail-closed：新增状态分支时显式枚举所有"拒绝"分支，禁止用兜底 `return false`/放行代替；同时检查既有测试是否已将错误的放行行为固化为"预期断言"。
- 服务端发起的 HTTP 请求，若目标 URL 来源于对端证书等不可信数据（如 CDP URI），必须校验目标地址禁止 loopback/private/link-local/元数据地址，并用 `io.LimitReader`/`http.MaxBytesReader` 限制响应体大小。
