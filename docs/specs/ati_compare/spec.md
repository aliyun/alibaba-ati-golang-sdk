# ati-golang-sdk PKI 验证机制规格

## 1. 验证策略等级

**类型定义**：`VerificationPolicy` type（`ati/policy.go`）。

| 策略名 | 值 | 含义 | 验证内容 |
|--------|-----|------|----------|
| `PolicyPKI` | 0 | 最低级别 | 仅标准 CA 链验证 |
| `PolicyPKIBadge` | 1 | **默认** | CA 链 + 透明日志 Badge 验证 |
| `PolicyPKIBadgeDANE` | 2 | 最高级别 | CA 链 + Badge + DANE/TLSA DNSSEC 验证 |

策略为渐进式包含关系，通过 iota 数值递增表示。

## 2. TLS 配置

- **TLS 版本**：强制 **TLS 1.3 最低版本**（`tls.VersionTLS13`），不支持 TLS 1.2
- **tls.Config 构建**：`NewAgentClient()` 直接构建 `http.Client` + `tls.Config`
- **证书捕获**：通过 `tls.Config.VerifyConnection` 回调函数实现，无需自定义 TrustManager
- **clientConfig 结构体**：
  - `identity`：mTLS 客户端证书
  - `caPool`：用于 server 验证的根 CA 池
  - `policy`：验证策略
  - `verifyConn`：自定义 VerifyConnection 回调
- **Options 函数**：`WithMTLSCerts`, `WithClientCAs`, `WithClientPolicy`, `WithVerifyConnection`

## 3. 验证流程架构

采用**单阶段顺序流**，通过 `ServerVerifier.Verify()` 实现（`verify/verify.go`）：

1. **缓存检查**：按 FQDN 查找已缓存的 TL 响应
2. **DNS 发现**：解析 `_ati-badge` TXT 记录（`FindPreferredBadge()`）
3. **URL 重写**：将 Badge URL 主机名替换为可信 TL 主机（`tl.ansagent.cn:8180`）
4. **URL 校验**：验证 Badge URL 域名在可信 RA 域名白名单内
5. **TL 获取**：从透明日志服务拉取 `TLResponse`
6. **Badge 验证**（`verifyWithTLResponse`）：校验 agent 状态有效性、SHA-256 指纹匹配、主机名匹配
7. **可选 DANE 检查**：若配置了 `DANEResolver`，执行 TLSA 验证，可覆盖/拒绝 Badge 结果

## 4. 证书身份提取

**`CertIdentity` 结构体**（`verify/cert.go`）：
- `CommonName`, `DNSSANs`, `URISANs`, SHA-256 `Fingerprint`
- `CertIdentityFromX509()`：从 `x509.Certificate` 提取身份，包含 `ati://` URI SAN
- `CertFingerprint`：SHA-256 指纹，支持 `SHA256:<hex>` 格式解析
- `CheckCertValidity()`：校验时间有效性 + 计算剩余生命周期百分比（<20% 告警）
- **ATIName**：从 `ati://v<major>.<minor>.<patch>.<fqdn>` URI SAN 解析

## 5. DANE/TLSA 验证

**`DANEVerifier.Verify()`**（`verify/dane.go`）：
- 查询 TLSA 记录
- **本地 DNSSEC 链验证**（不依赖 resolver 的 AD flag），使用 `miekg/dns` 库
- **仅匹配 DANE-EE (Usage=3)** 记录
- 对比 cert SHA-256 指纹
- **`StandardDANEResolver`**：可配置 DNS server、timeout、trust anchor

### DANE 验证结果
- `DANEVerified`：验证通过
- `DANEMismatch`：指纹不匹配（拒绝）
- `DANESkipped`：无 DNSSEC
- `DANEDNSSECFailed`：DNSSEC 验证失败（拒绝）
- `DANENoRecords`：无 TLSA 记录
- `DANELookupError`：DNS 查询错误

## 6. 失败处理策略

**三种失败策略**（`verify/policy.go`）：

| 策略 | 行为 | 推荐度 |
|------|------|--------|
| `FailClosed` | 任何故障即拒绝（**默认**） | 推荐 |
| `FailOpenWithCache` | 使用过期缓存（最多 10 分钟陈旧度） | 有限容错 |
| `FailOpen` | 无验证即接受 | **不推荐** |

**关键约束**：SCITT 签名验证失败**永远是终结性的**，不受 FailOpen 策略影响。

## 7. 错误处理

- **类型化错误**（`verify/errors.go`）：`DNSError`, `TlogError`, `DANEError`, `VerificationError`
- **VerificationError 子类型**：指纹不匹配、主机名不匹配、ATI Name 不匹配、状态无效、无 CN、无 URI SAN
- **`VerificationOutcome`**（`verify/outcome.go`）：13 种结果类型，包含 `OutcomeDANERejection`, `OutcomeScittError` 等
- `ToError()` 将 outcome 转换为类型化 Go error

## 8. IDCA 集成

- **无显式 IDCA 引用**
- 信任锚定通过标准 `x509.CertPool`（系统或自定义 CA）+ 透明日志 Badge + DANE/DNSSEC 实现

## 9. 扩展能力

**Spec §9.4 存根类型**（`verify/extended_types.go`）：
- `TrustPolicy`：可信签发者、最低密钥强度
- `OCSPChecker`：OCSP 检查器
- `SessionMonitor`：会话监控
- `AgentCardVerifier`：Agent Card 验证
- `ProducerKeyLookup`：Producer 密钥查找

这些均为预留接口/类型，尚未实现。
