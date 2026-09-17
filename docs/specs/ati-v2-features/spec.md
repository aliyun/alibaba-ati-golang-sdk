# Spec: ATI v2 Features — Go SDK

**Status:** ready-for-implementation  
**Source:** ati-java-sdk commits 039762c1..90e99e06  
**Target:** ati-golang-sdk branch features/ati-v2 (当前 online-v2)  

---

## Overview

将 Java SDK 从 commit 039762c1 到 90e99e06 的全部功能改动移植到 Go SDK，涵盖六个特性领域：
1. VerificationPolicy 重命名 + NONE 策略
2. Dual-hostname model（identityHost / accessHost）
3. DNS TXT Discovery — 删除 OpenAPI 代码
4. NONE verification policy 客户端行为
5. Full Semver Range Matching（完整 semver 约束支持）
6. IDCA CRL Certificate Revocation

---

## Feature 1: VerificationPolicy Rename

### Goal
将 Go SDK trust level 命名对齐 ATI Console，从内部技术命名（PKIOnly/BadgeRequired/DANEAndBadge）迁移到用户友好的分级命名（NONE/BASIC/ENHANCED/ADVANCED）。

### Requirements

| 旧名称 | 新名称 | ATI Console 标签 | 含义 |
|--------|--------|-----------------|------|
| (无) | NONE | L0 无认证 | 跳过 TLS 验证和 ATI 验证（仅 dev/test） |
| PKIOnly | BASIC | L1 基础认证 | 标准 PKI 验证 |
| BadgeRequired | ENHANCED | L2 增强认证 | PKI + Badge |
| DANEAndBadge | ADVANCED | L3 高级认证 | PKI + Badge + DANE |

### Design
- 新增 `VerificationPolicy` 类型（`type VerificationPolicy int`）
- 定义常量：`PolicyNone`, `PolicyBasic`, `PolicyEnhanced`, `PolicyAdvanced`
- 保留旧 `TrustLevel` 类型作为 deprecated alias
- 新增 `DisplayName()` 方法返回 Console 标签
- `ValidForClient()` / `ValidForServer()` 反映策略限制

### Acceptance Criteria
- 新常量可正常编译使用
- 旧常量 (PKIOnly 等) 仍可编译但标记 Deprecated
- `DisplayName()` 返回正确标签

---

## Feature 2: NONE Verification Policy

### Goal
客户端 NONE 策略跳过所有 TLS 证书验证（`InsecureSkipVerify: true`），用于开发测试环境。服务端 NONE 策略表示不请求客户端证书。

### Requirements

**客户端 (R2.1)**：
- `PolicyNone` 时设置 `tls.Config.InsecureSkipVerify = true`
- 不执行 Badge/DANE 验证
- 连接日志中打印 WARN 级别警告

**服务端 (R2.2)**：
- `PolicyNone` 对应 `tls.NoClientCert`（已有行为 — 不配 trustLevel 时即是）
- 显式设置 `WithClientVerifier(PolicyNone)` 时 server 不请求客户端证书

**限制 (R2.3)**：
- 客户端 `PolicyNone` 仅在显式配置时启用，不作为默认值
- 服务端不允许 `PolicyNone` 与 `WithClientCA()` 同时使用

### Acceptance Criteria
- NONE 客户端可连接自签证书服务端
- NONE 客户端日志输出安全警告
- NONE + WithClientCA 配置时返回错误

---

## Feature 3: Dual-hostname Model

### Goal
分离 Identity Hostname（Badge 查询、identity DANE）和 Access Hostname（transport DANE `_443._tcp`），支持代理网关场景下身份与访问地址不同的部署拓扑。

### Requirements

**客户端 (R3.1)**：
- `AgentClientOption` 新增 `WithIdentityHost(host string)` 和 `WithAccessHost(host string)`
- Badge 和 identity DANE 使用 identityHost（默认回退到连接 URL host）
- Transport DANE (`_443._tcp`) 使用 accessHost（默认回退到连接 URL host）

**服务端 (R3.2)**：
- 服务端不需要 dual-hostname（服务端验证客户端证书，不做 DANE 对外查询）

### Acceptance Criteria
- 指定 identityHost 时 Badge 查询使用 identityHost 而非连接地址
- 指定 accessHost 时 transport DANE 查询使用 accessHost
- 不指定时行为不变（使用连接 URL host）

---

## Feature 4: Delete OpenAPI Discovery

### Goal
删除 `AliyunATIDiscovery`（OpenAPI 方式），仅保留 DNS TXT `_ati` 记录作为唯一发现机制。Go SDK 已有 `StandardDNSResolver.LookupATIDiscovery`，OpenAPI 代码完全移除。

### Requirements

- R4.1: 删除 `verify/aliyun_discovery.go` 及其测试文件
- R4.2: 删除 `WithServerAliyunDiscovery` ServerOption
- R4.3: 删除 `AliyunATIConfig` 及所有相关类型
- R4.4: 清理 go.mod 中不再使用的 OpenAPI 依赖（darabonba-openapi, openapi-util, tea, tea-utils）
- R4.5: `go mod tidy` 后编译通过

### Acceptance Criteria
- `verify/aliyun_discovery.go` 不存在
- `go build ./...` 成功
- DNS TXT 方式继续正常工作
- 所有剩余测试通过

---

## Feature 5: Full Semver Range Matching

### Goal
将 DNS TXT `_ati` 记录中多条 `av` 字段的版本匹配升级为完整 semver range 支持，对齐 Java SDK 的 `semver4j` 行为。当发现多条 TXT 记录时，按 semver 约束过滤并选取最新版本。

### Requirements

**R5.1 — 支持的约束格式**：
- `^1.2.0` — >=1.2.0 <2.0.0（同 major，且 >= 指定 minor.patch）
- `~1.2.0` — >=1.2.0 <1.3.0（同 major.minor）
- `>=1.0.0` — >= 指定版本
- `>=1.0.0 <2.0.0` — 范围表达式
- 精确版本 `1.2.3` — 完全匹配
- 无约束 — 返回所有记录中的最新版本

**R5.2 — 匹配逻辑**：
- 从 DNS TXT 响应中解析所有 `_ati` 记录的 `av` 字段
- 按用户指定的 semver constraint 过滤满足条件的记录
- 在满足条件的记录中选取版本最高的
- 无匹配时返回错误

**R5.3 — 依赖**：
- 引入 `github.com/Masterminds/semver/v3` 库（Go 生态标准 semver 库）

### Acceptance Criteria
- `^1.2.0` 正确匹配 1.2.0, 1.3.0, 1.99.0；不匹配 1.1.9, 2.0.0
- `~1.2.0` 正确匹配 1.2.0, 1.2.5；不匹配 1.3.0
- 无约束返回最新版本
- 不满足约束时返回明确错误

---

## Feature 6: IDCA CRL Certificate Revocation

### Goal
服务端 mTLS 场景下，通过 PKIX CRL（从证书链 CDP 扩展获取）验证客户端 Identity Certificate 是否已被吊销。

### Non-goals (this phase)
- OCSP（已有独立 ocsp.go）
- 运营商可配置 CRL URL fallback
- 客户端侧 CRL 检查
- 替换 TL Badge Registration Revocation

### Requirements

**R6.1 — CDP Discovery**
- 从客户端 leaf cert 的 `CRLDistributionPoints` 读取 CDP
- Leaf 无 CDP → 从 issuing CA cert 读取
- 链上均无 CDP → **跳过 CRL**（debug 日志），不 fail
- CDP 存在但无有效 HTTP(S) URI → **fail-closed**

**R6.2 — CRL Fetch and Validate**
- HTTP(S) GET 从 CDP URI 获取 CRL
- 使用 issuing CA 公钥验证 CRL 签名
- Client cert serial 在 CRL 中 → 拒绝连接

**R6.3 — Fail-closed**
- CDP 存在且 CRL 已启动：fetch 失败 / 签名无效 / 解析失败 → 拒绝 mTLS

**R6.4 — Policy Scope**
- `WithClientCA()` + trustLevel ≠ nil 时启用
- 适用 BASIC / ENHANCED / ADVANCED；不适用 NONE

**R6.5 — Dual-track with Badge**
- CRL 和 Badge revocation 独立运行，任一失败即拒绝

**R6.6 — CRL Cache**
- 按 CDP URI 缓存
- `nextUpdate` 到达时刷新
- 最大缓存时间 12h

**R6.7 — Configuration API**
- `WithCRLCheck()` — 显式启用（CA bundle + trustLevel 时自动启用）
- `WithCRLCheckDisabled()` — 显式关闭
- `WithCRLHTTPClient(*http.Client)` — 自定义 HTTP client

**R6.8 — Testing**
- Mock CDP/CRL fixture
- 覆盖：revoked→拒绝、valid→通过、no CDP→跳过、fetch fail→拒绝、bad signature→拒绝

### Architecture

```
verify/crl/
├── cdp.go          // CDP discovery
├── checker.go      // Orchestrator
├── fetcher.go      // CRL fetch + cache
├── result.go       // Result type
└── validator.go    // CRL signature + serial check
```

Integration: `ati/server.go` → `buildVerifyConnection` → CRL check after cert validity, before Badge.

### Acceptance Criteria
1. Mock cert with CDP + revoked serial → mTLS 被拒
2. Mock cert with CDP + valid serial → mTLS 继续
3. Mock cert without CDP → mTLS 正常（CRL skipped）
4. CDP 存在 + URL 不可达 → mTLS 被拒
5. CRL cache 遵守 nextUpdate 和 12h 上限
6. Badge + CRL 双轨互不干扰
