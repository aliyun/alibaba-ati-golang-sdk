# Tasks: ATI v2 Features — Go SDK

## 总览

将 Java SDK (039762c1..90e99e06) 的全部改动移植到 ati-golang-sdk，按特性域和模块依赖拆分任务。

---

## Task 1: VerificationPolicy 重命名

**文件**: `ati/verification_policy.go` (新), `ati/verification_policy_test.go` (新), `ati/trust_level.go` (改)

**内容**:
- 新增 `VerificationPolicy` 类型和常量 (PolicyNone/PolicyBasic/PolicyEnhanced/PolicyAdvanced)
- `DisplayName()` 方法返回 Console 标签（L0/L1/L2/L3）
- `HasBadgeVerification()` / `HasDANEVerification()` / `ValidForClient()` / `ValidForServer()`
- `trust_level.go` 中旧 TrustLevel/PKIOnly/BadgeRequired/DANEAndBadge 改为 type alias + Deprecated 注释
- 保留所有旧别名向后兼容

**测试覆盖**:
- 各策略的 DisplayName 正确性
- HasBadge/HasDANE 判断
- 旧别名类型兼容

---

## Task 2: NONE Policy — 客户端行为

**文件**: `ati/mtls_client.go` (改), `ati/mtls_client_test.go` (改)

**依赖**: Task 1

**内容**:
- NewAgentClient 中检测 PolicyNone → 设置 InsecureSkipVerify = true
- 跳过 Badge/DANE 验证
- WARN 日志输出安全警告
- PolicyNone + caBundleFile → 返回错误

**测试覆盖**:
- NONE 客户端可连接自签证书服务端
- NONE 客户端跳过 Badge 验证
- 安全警告日志输出

---

## Task 3: NONE Policy — 服务端行为

**文件**: `ati/server.go` (改), `ati/server_test.go` (改)

**依赖**: Task 1

**内容**:
- WithClientVerifier(PolicyNone) → NoClientCert
- PolicyNone + WithClientCA → 返回配置错误
- buildVerifyConnection 中 PolicyNone 不做任何验证

**测试覆盖**:
- PolicyNone 服务端不请求客户端证书
- PolicyNone + WithClientCA 返回错误
- 已有 trust level 行为无回归

---

## Task 4: Dual-hostname Model

**文件**: `ati/mtls_client.go` (改), `ati/mtls_client_test.go` (改)

**依赖**: Task 1

**内容**:
- agentClientConfig 新增 identityHost / accessHost 字段
- 新增 WithIdentityHost(host string) / WithAccessHost(host string) Options
- Badge 查询使用 resolveIdentityHost(connectionHost)
- Transport DANE 查询使用 resolveAccessHost(connectionHost)
- 不设置时回退到连接 URL host

**测试覆盖**:
- 设置 identityHost → Badge 使用指定 host
- 设置 accessHost → DANE 使用指定 host
- 不设置 → 使用连接 host（行为不变）

---

## Task 5: 删除 OpenAPI Discovery

**文件**: `verify/aliyun_discovery.go` (删), `verify/aliyun_discovery_test.go` (删), `ati/server.go` (改), `go.mod` (改)

**内容**:
- 删除 `verify/aliyun_discovery.go` 及其测试文件
- 删除 `WithServerAliyunDiscovery` ServerOption
- 删除 `AliyunATIConfig` 及相关类型
- 清理 go.mod 中不再使用的 OpenAPI 依赖
- `go mod tidy` 后编译通过

**测试覆盖**: 所有剩余测试通过（DNS TXT 路径不受影响）

---

## Task 6: Full Semver Range Matching

**文件**: `ati/version_policy.go` (改), `ati/version_policy_test.go` (改), `go.mod` (改)

**依赖**: 无

**内容**:
- 引入 `github.com/Masterminds/semver/v3` 库
- 重写 `resolveLatestCompatible`：使用 `semver.NewConstraint(requested)` 解析约束
- 遍历 records，用 `constraint.Check(version)` 过滤满足条件的记录
- 在满足条件的记录中选取版本最高的
- 保持 `VersionPolicyLatest`（无约束→最新）和 `VersionPolicyExact`（精确匹配）逻辑不变
- 废弃或删除旧 `parseMajorFromRange` 辅助函数

**测试覆盖**:
- `^1.2.0` 匹配 1.2.0, 1.3.0；不匹配 1.1.9, 2.0.0
- `~1.2.0` 匹配 1.2.0, 1.2.5；不匹配 1.3.0
- `>=1.0.0` 匹配 1.0.0, 2.0.0
- 无约束返回最新
- 无满足记录返回错误

---

## Task 7: CRL — Result 类型

**文件**: `verify/crl/result.go` (新), `verify/crl/result_test.go` (新)

**内容**:
- Status 枚举: Skipped, Passed, Revoked, Failed
- Result struct: Status, Message, CDPURI
- ShouldReject() bool

---

## Task 8: CRL — CDP Discovery

**文件**: `verify/crl/cdp.go` (新), `verify/crl/cdp_test.go` (新)

**内容**:
- CDPStatus / CDPResult 类型
- ResolveCDP(chain []*x509.Certificate) CDPResult
- findIssuingCA(leaf, chain) 辅助函数
- 利用 x509.Certificate.CRLDistributionPoints (原生 string slice)

**测试覆盖**:
- Leaf 有 CDP → Found
- Leaf 无, issuer 有 → Found
- 链上无 CDP → Skipped
- CDP 有但仅非 HTTP URI → Failed
- 空链 → Skipped

---

## Task 9: CRL — Validator

**文件**: `verify/crl/validator.go` (新), `verify/crl/validator_test.go` (新)

**内容**:
- Parse(crlBytes) / VerifySignature(crl, issuer) / IsRevoked(crl, serial)
- ValidateNotRevoked 组合函数
- 错误定义: ErrRevoked, ErrInvalidSignature, ErrParseFailed

**测试覆盖**:
- 有效 CRL + 有效签名 + 未吊销 → nil
- Serial 在 CRL → ErrRevoked
- 无效签名 → ErrInvalidSignature
- 无效 DER → ErrParseFailed

---

## Task 10: CRL — Fetcher + Cache

**文件**: `verify/crl/fetcher.go` (新), `verify/crl/fetcher_test.go` (新)

**依赖**: Task 9 (用 Parse 确定 TTL)

**内容**:
- Fetcher struct (sync.Mutex + map + http.Client)
- NewFetcher(opts...) / Fetch(ctx, cdpURI)
- Cache: TTL = min(nextUpdate - fetchedAt, 12h)
- Options: WithHTTPClient, WithMaxAge

**测试覆盖**:
- 首次 fetch → HTTP + 缓存
- 缓存命中 → 不 HTTP
- 过期 → 重新 fetch
- HTTP 失败 → error
- nextUpdate < 12h → 用 nextUpdate
- nextUpdate > 12h → cap 12h

---

## Task 11: CRL — Checker

**文件**: `verify/crl/checker.go` (新), `verify/crl/checker_test.go` (新)

**依赖**: Task 7, 8, 9, 10

**内容**:
- Checker struct + NewChecker(opts...)
- Check(ctx, leaf, chain) Result
- 编排: ResolveCDP → findIssuer → Fetch → ValidateNotRevoked

**测试覆盖**:
- 正常路径 → Passed
- Revoked serial → Revoked
- Fetch 失败 → Failed
- 签名无效 → Failed
- 无 CDP → Skipped
- 无 issuer → Failed

---

## Task 12: CRL — Server Integration

**文件**: `ati/server.go` (改), `ati/server_test.go` (改)

**依赖**: Task 11, Task 1

**内容**:
- WithCRLCheck() / WithCRLCheckDisabled() / WithCRLHTTPClient Options
- serverConfig 新增 crlEnabled / crlChecker / crlHTTPClient
- NewServerTLSConfig: 自动创建 Checker (CA bundle + trustLevel != nil/NONE)
- buildVerifyConnection: cert validity 后 Badge 前插入 CRL check

**测试覆盖**:
- mTLS + revoked → 拒绝
- mTLS + valid + CDP → 正常
- mTLS + no CDP → 正常 (skipped)
- WithCRLCheckDisabled → 不运行
- Badge + CRL 双轨

---

## 建议实现顺序

```
Task 1 (VerificationPolicy)
├─ Task 2 (NONE 客户端)
├─ Task 3 (NONE 服务端)
├─ Task 4 (Dual-hostname)
└─ Task 5 (删除 OpenAPI Discovery)

Task 6 (Full Semver Range Matching)

Task 7 (CRL Result)
Task 8 (CRL CDP)
Task 9 (CRL Validator)
├─ Task 10 (CRL Fetcher) [依赖 Task 9]
   └─ Task 11 (CRL Checker) [依赖 7,8,9,10]
      └─ Task 12 (CRL Server Integration) [依赖 Task 11, Task 1]
```

建议并行路径：
- 路径 A: Task 1 → 2 → 3 → 4 → 5
- 路径 B: Task 6（独立）
- 路径 C: Task 7 → 8 → 9 → 10 → 11
- 最终: Task 12（合并路径 A + C）

---

## 参考资料

- Java 实现: ati-java-sdk commit range 039762c1..90e99e06
- Java Spec: `.scratch/idca-crl/spec.md`
- ADR: `docs/adr/0003-dns-based-discovery.md`, `docs/adr/0004-idca-crl-revocation.md`
- Go SDK 入口: `ati/server.go`, `ati/mtls_client.go`, `verify/aliyun_discovery.go`

---

## 任务工单分解（Tracer-Bullet Tickets）

按依赖顺序排列，被阻塞的工单在后。

### 01 — VerificationPolicy type + deprecation expand
- **Blocked by**: 无
- **交付内容**: 新 `VerificationPolicy` 类型 (NONE/BASIC/ENHANCED/ADVANCED)，旧 TrustLevel 变为 deprecated alias，所有现有代码无修改编译通过
- **验收标准**: 新常量可用，旧别名兼容，DisplayName() 正确
- **工单文件**: `/home/admin/workitem/workitem6b8c29008ed44c50bf/output/tickets/01-verification-policy-type.md`

### 02 — NONE policy end-to-end (client + server)
- **Blocked by**: 01
- **交付内容**: NONE 客户端跳过 TLS 验证连接自签服务端；NONE 服务端不请求客户端证书；冲突配置被拒绝
- **验收标准**: NONE 客户端连接成功、安全警告日志、冲突报错、无回归
- **工单文件**: `/home/admin/workitem/workitem6b8c29008ed44c50bf/output/tickets/02-none-policy-end-to-end.md`

### 03 — Dual-hostname client routing
- **Blocked by**: 01
- **交付内容**: WithIdentityHost/WithAccessHost 将 Badge 和 DANE 查询路由到不同 hostname
- **验收标准**: Badge 用 identityHost，DANE 用 accessHost，不设置时行为不变
- **工单文件**: `/home/admin/workitem/workitem6b8c29008ed44c50bf/output/tickets/03-dual-hostname-routing.md`

### 04 — Delete OpenAPI discovery
- **Blocked by**: 无
- **交付内容**: 删除 AliyunATIDiscovery/AliyunATIConfig/WithServerAliyunDiscovery 代码，清理依赖
- **验收标准**: 文件已删、编译通过、DNS TXT 路径正常
- **工单文件**: `/home/admin/workitem/workitem6b8c29008ed44c50bf/output/tickets/04-delete-openapi-discovery.md`

### 05 — CRL core library (verify/crl package)
- **Blocked by**: 无
- **交付内容**: 独立 verify/crl 包：CDP 发现 + CRL 获取缓存 + 签名验证 + 序列号检查，单元测试覆盖全部路径
- **验收标准**: revoked→error, valid→pass, no-CDP→skip, fetch-fail→error, bad-sig→error, cache-hit/miss
- **工单文件**: `/home/admin/workitem/workitem6b8c29008ed44c50bf/output/tickets/05-crl-core-library.md`

### 06 — CRL server integration
- **Blocked by**: 01, 05
- **交付内容**: CRL 自动嵌入服务端 mTLS 流程，WithCRLCheck/WithCRLCheckDisabled/WithCRLHTTPClient 选项，集成测试
- **验收标准**: revoked cert 被拒、valid cert 通过、no-CDP 通过、Disabled 不运行、Badge+CRL 双轨独立
- **工单文件**: `/home/admin/workitem/workitem6b8c29008ed44c50bf/output/tickets/06-crl-server-integration.md`

### 07 — Full semver range matching
- **Blocked by**: 无
- **交付内容**: DNS TXT 多记录版本选择升级为完整 semver range（^/~/>=），引入 Masterminds/semver 库
- **验收标准**: ^1.2.0 正确过滤、~1.2.0 正确过滤、无约束返回最新、无匹配报错
- **工单文件**: `/home/admin/workitem/workitem6b8c29008ed44c50bf/output/tickets/07-semver-range-matching.md`
