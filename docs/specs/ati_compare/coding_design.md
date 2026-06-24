# ati-golang-sdk 编码方案设计

> 本文档为 [总编码方案](./coding_design.md) 的子文档，聚焦 Go SDK 的 PKI 验证实现细节。

## 当前实现概要

### 核心结构与模块

| 组件 | 文件 | 职责 |
|------|------|------|
| `VerificationPolicy` | `ati/policy.go` | 定义 PolicyPKI / PolicyPKIBadge / PolicyPKIBadgeDANE 三级策略 |
| `NewAgentClient()` | `ati/client.go` | 构建 http.Client + tls.Config（TLS 1.3 minimum） |
| `clientConfig` / Options | `ati/options.go` | identity, caPool, policy, verifyConn 配置 |
| `ServerVerifier` | `verify/verify.go` | 单阶段顺序验证流程编排 |
| `CertIdentity` | `verify/cert.go` | 证书身份提取（CN, SAN, 指纹, ATI Name） |
| `DANEVerifier` | `verify/dane.go` | 本地 DNSSEC 链验证 + DANE-EE (Usage=3) 匹配 |
| `StandardDANEResolver` | `verify/dane.go` | 独立 DNSSEC 解析器（miekg/dns） |
| 失败策略 | `verify/policy.go` | FailClosed / FailOpenWithCache / FailOpen |
| 扩展类型存根 | `verify/extended_types.go` | Spec §9.4 前瞻性接口定义 |

### 验证流程

```
ServerVerifier.Verify(cert, hostname)
  │
  ├─ 1. 缓存检查（FQDN → 已缓存 TLResponse）
  │      命中 → 跳到步骤 6
  │
  ├─ 2. DNS 发现
  │      解析 _ati-badge TXT 记录 → FindPreferredBadge()
  │
  ├─ 3. URL 重写
  │      Badge URL 主机名 → 可信 TL 主机 (tl.ansagent.cn:8180)
  │
  ├─ 4. URL 校验
  │      验证域名在可信 RA 域名白名单内
  │
  ├─ 5. TL 获取
  │      拉取 TLResponse
  │
  ├─ 6. Badge 验证 (verifyWithTLResponse)
  │      Agent 状态有效性 + SHA-256 指纹匹配 + 主机名匹配
  │
  └─ 7. 可选 DANE 检查
         DANEVerifier.Verify()
         ├─ 查询 TLSA 记录
         ├─ 本地 DNSSEC 链验证（不信任 resolver AD flag）
         ├─ 仅 DANE-EE (Usage=3) 匹配
         └─ 可覆盖/拒绝 Badge 结果
```

### 与 Java SDK 对比下的差异特征

1. **TLS 1.3 强制**：不兼容 TLS 1.2，安全性更高但兼容性受限
2. **顺序验证**：Badge → DANE 顺序执行，逻辑清晰但可能延迟更高
3. **灵活失败策略**：FailClosed/FailOpenWithCache/FailOpen 三选一，适应不同可用性需求
4. **本地 DNSSEC 验证**：不信任中间 resolver，安全性更高
5. **SCITT 终结性**：签名验证失败永远拒绝，不可降级
6. **显式 ATI Name**：从 URI SAN 显式解析版本化 ATI 名称
7. **Spec §9.4 前瞻**：预留 TrustPolicy, OCSPChecker 等扩展接口
8. **无框架绑定**：无 Spring Boot 等框架集成，需手动配置 CA 池

### 对齐建议（从 Java SDK 借鉴）

- 考虑是否需要兼容 TLS 1.2（视目标部署环境而定）
- 补充 IDCA 信任配置的便捷封装（类似 Spring Boot starter 的作用）
- 考虑异步并行化 Badge + DANE 查询以降低延迟
- 评估 Badge 验证是否需要支持 ACTIVE/DEPRECATED 多指纹轮转
