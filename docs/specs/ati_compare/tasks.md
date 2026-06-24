# ati-golang-sdk 任务清单

> 本文档为 [总任务清单](./tasks.md) 的子文档。

## 分析任务

- [x] 定位 VerificationPolicy 类型定义（PolicyPKI / PolicyPKIBadge / PolicyPKIBadgeDANE）
- [x] 分析 NewAgentClient() TLS 1.3 强制配置与 tls.Config 构建
- [x] 分析 ServerVerifier.Verify() 单阶段顺序验证流程（7 步）
- [x] 分析 CertIdentity 证书身份提取（含 ATIName 显式解析）
- [x] 分析 DANEVerifier 本地 DNSSEC 链验证（miekg/dns，仅 DANE-EE Usage=3）
- [x] 分析失败策略体系（FailClosed / FailOpenWithCache / FailOpen）
- [x] 分析 SCITT 终结性语义（签名失败不可降级）
- [x] 分析 Spec §9.4 扩展类型存根（TrustPolicy, OCSPChecker 等）
- [x] 分析 VerificationOutcome 13 种结果类型与类型化 error 体系

## 对齐建议（Go SDK 侧）

| 优先级 | 建议 | 参考 Java SDK 实现 |
|--------|------|-----------------|
| P0 | 评估是否需要兼容 TLS 1.2 | Java SDK `getSecureSslParameters()` |
| P1 | 补充 IDCA 信任配置便捷封装 | `AtiSdkProperties.Idca` Spring Boot starter |
| P1 | 考虑 Badge + DANE 异步并行化 | Java SDK CompletableFuture 并行预取 |
| P2 | 支持 Badge ACTIVE/DEPRECATED 多指纹轮转 | Java SDK BadgeVerifier 多指纹匹配 |
