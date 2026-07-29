# Coding Design: ATI v2 Features — Go SDK

## 概要

将 Java SDK 从 039762c1 到 90e99e06 的改动移植到 Go SDK，涵盖六个特性：VerificationPolicy 重命名、NONE 策略、Dual-hostname、删除 OpenAPI Discovery、Full Semver Range Matching、IDCA CRL。

---

## Module 1: VerificationPolicy Rename + NONE

### 文件: `ati/verification_policy.go` (新文件)

```go
package ati

type VerificationPolicy int

const (
    PolicyNone     VerificationPolicy = iota // L0 无认证
    PolicyBasic                               // L1 基础认证 (PKI only)
    PolicyEnhanced                            // L2 增强认证 (PKI + Badge)
    PolicyAdvanced                            // L3 高级认证 (PKI + Badge + DANE)
)

func (p VerificationPolicy) DisplayName() string
func (p VerificationPolicy) HasBadgeVerification() bool
func (p VerificationPolicy) HasDANEVerification() bool
func (p VerificationPolicy) ValidForClient() bool   // 全部有效
func (p VerificationPolicy) ValidForServer() bool   // 全部有效
```

### 文件: `ati/trust_level.go` (修改 — 添加 deprecated 标记)

```go
// Deprecated: Use VerificationPolicy instead.
type TrustLevel = VerificationPolicy

// Deprecated: Use PolicyBasic instead.
const PKIOnly = PolicyBasic
// Deprecated: Use PolicyEnhanced instead.
const BadgeRequired = PolicyEnhanced
// Deprecated: Use PolicyAdvanced instead.
const DANEAndBadge = PolicyAdvanced
```

保留所有旧别名以向后兼容，但添加 `// Deprecated:` godoc 注释。

### iota 值变更兼容性分析

新枚举 iota 序列为 PolicyNone=0, PolicyBasic=1, PolicyEnhanced=2, PolicyAdvanced=3。旧代码中 PKIOnly=0(iota), BadgeRequired=1, DANEAndBadge=2。通过 type alias `const PKIOnly = PolicyBasic`，PKIOnly 的整数值从 0 变为 1。

**兼容性结论**：Go SDK 内部不对 VerificationPolicy/TrustLevel 的整数值做序列化、持久化或网络传输，仅作为内存枚举用于分支判断。因此数值变更不影响已有行为。调用方若直接使用常量名（`PKIOnly`）则行为不变；若硬编码整数值（如 `TrustLevel(0)`）则会得到 PolicyNone 而非原来的 PKIOnly — 但 SDK 公共 API 不暴露整数构造方式，此场景不存在。

### 文件: `ati/mtls_client.go` (修改)

NONE 策略支持：

```go
// 在 NewAgentClient 中
if cfg.trustLevel != nil && *cfg.trustLevel == PolicyNone {
    tlsConfig.InsecureSkipVerify = true
    slog.Warn("[ati-client] NONE verification policy: TLS validation disabled (dev/test only)")
}
```

### 文件: `ati/server.go` (修改)

NONE 策略限制：

```go
// WithClientVerifier 中：
if level == PolicyNone {
    // server NONE = no client auth, compatible with existing nil trustLevel behavior
}

// NewServerTLSConfig 中：
if cfg.trustLevel != nil && *cfg.trustLevel == PolicyNone && cfg.caBundleFile != "" {
    return nil, errors.New("PolicyNone cannot be used with WithClientCA()")
}
```

---

## Module 2: Dual-hostname Model

### 文件: `ati/mtls_client.go` (修改)

新增 `agentClientConfig` 字段和 Options：

```go
type agentClientConfig struct {
    // ...existing...
    identityHost string // for Badge + identity DANE lookups
    accessHost   string // for transport DANE (_443._tcp) lookups
}

func WithIdentityHost(host string) AgentClientOption
func WithAccessHost(host string) AgentClientOption
```

### 修改验证逻辑

在客户端 Badge/DANE 验证流程中：
- Badge 查询使用 `resolveIdentityHost(connectionHost)` 
- Transport DANE 查询使用 `resolveAccessHost(connectionHost)`

```go
func (c *AgentClient) resolveIdentityHost(connectionHost string) string {
    if c.identityHost != "" { return c.identityHost }
    return connectionHost
}

func (c *AgentClient) resolveAccessHost(connectionHost string) string {
    if c.accessHost != "" { return c.accessHost }
    return connectionHost
}
```

---

## Module 3: Delete OpenAPI Discovery

### 文件: `verify/aliyun_discovery.go` (删除)

完全删除该文件及其测试文件 `verify/aliyun_discovery_test.go`。该文件包含 `AliyunATIDiscovery` struct 和 `AliyunATIConfig` 等类型，已被 DNS TXT (`_ati` records) 方式取代。

### 文件: `ati/server.go` (修改)

删除 `WithServerAliyunDiscovery(cfg verify.AliyunATIConfig) ServerOption` 函数及其注册逻辑。

### 文件: `go.mod` (修改)

清理不再使用的 OpenAPI 相关依赖：
- `github.com/alibabacloud-go/darabonba-openapi`
- `github.com/alibabacloud-go/openapi-util`
- `github.com/alibabacloud-go/tea`
- `github.com/alibabacloud-go/tea-utils`

执行 `go mod tidy` 确保编译通过。

---

## Module 4: Full Semver Range Matching

### 文件: `ati/version_policy.go` (修改)

引入 `github.com/Masterminds/semver/v3` 库，重写 DNS TXT 多记录版本匹配逻辑：

```go
import "github.com/Masterminds/semver/v3"

func resolveLatestCompatible(records []ATIRecord, requested string) (*ATIRecord, error) {
    if requested == "" {
        // VersionPolicyLatest: 返回所有记录中版本最高的
        return selectLatest(records)
    }

    constraint, err := semver.NewConstraint(requested)
    if err != nil {
        // 无法解析为 semver constraint，尝试精确匹配（VersionPolicyExact）
        return findExact(records, requested)
    }

    var matched []ATIRecord
    for _, r := range records {
        v, err := semver.NewVersion(r.Version)
        if err != nil {
            continue
        }
        if constraint.Check(v) {
            matched = append(matched, r)
        }
    }
    if len(matched) == 0 {
        return nil, fmt.Errorf("no records satisfy constraint %q", requested)
    }
    return selectLatest(matched)
}
```

### 设计要点

1. **引入外部依赖**: `github.com/Masterminds/semver/v3` — Go 生态标准 semver 库，支持 `^`/`~`/`>=`/range 表达式
2. **重写 `resolveLatestCompatible`**: 用 `semver.NewConstraint` 替代旧的 `parseMajorFromRange` 手工解析
3. **保留已有策略**: `VersionPolicyLatest`（无约束→最新）和 `VersionPolicyExact`（精确匹配）逻辑保持不变
4. **废弃旧函数**: `parseMajorFromRange` 辅助函数不再需要，标记 deprecated 或直接删除
5. **与 `models.ParseVersion` 的关系**: 现有 `ParseVersion` 仅解析版本号字符串为结构体，不处理约束；新逻辑用 semver 库处理约束，选出匹配记录后仍可使用 `ParseVersion` 做后续操作

---

## Module 5: IDCA CRL Certificate Revocation

### 5.1 `verify/crl/result.go`

```go
package crl

type Status int
const (
    Skipped Status = iota
    Passed
    Revoked
    Failed
)

type Result struct {
    Status  Status
    Message string
    CDPURI  string
}

func (r Result) ShouldReject() bool
```

### 5.2 `verify/crl/cdp.go`

```go
type CDPStatus int
const (
    CDPSkipped CDPStatus = iota
    CDPFound
    CDPFailed
)

type CDPResult struct {
    Status  CDPStatus
    URI     string
    Message string
}

func ResolveCDP(chain []*x509.Certificate) CDPResult
func findIssuingCA(leaf *x509.Certificate, chain []*x509.Certificate) *x509.Certificate
```

实现要点：
- `x509.Certificate.CRLDistributionPoints` 原生支持（string slice）
- 过滤 http:// / https:// URI
- 链上无 CDP → Skipped；CDP 存在但无有效 URI → Failed

### 5.3 `verify/crl/validator.go`

```go
var (
    ErrRevoked          = errors.New("certificate serial is revoked")
    ErrInvalidSignature = errors.New("CRL signature verification failed")
    ErrParseFailed      = errors.New("failed to parse CRL")
)

func Parse(crlBytes []byte) (*x509.RevocationList, error)
func VerifySignature(crl *x509.RevocationList, issuer *x509.Certificate) error
func IsRevoked(crl *x509.RevocationList, serial *big.Int) bool
func ValidateNotRevoked(crlBytes []byte, issuer *x509.Certificate, serial *big.Int) error
```

实现要点：
- `x509.ParseRevocationList()` 解析 DER
- `crl.CheckSignatureFrom(issuer)` 验签
- 遍历 `crl.RevokedCertificateEntries` 匹配 serial

### 5.4 `verify/crl/fetcher.go`

```go
type Fetcher struct {
    mu         sync.Mutex
    cache      map[string]*cachedEntry
    httpClient *http.Client
    maxAge     time.Duration
}

type FetcherOption func(*Fetcher)
func WithHTTPClient(client *http.Client) FetcherOption
func WithMaxAge(d time.Duration) FetcherOption

func NewFetcher(opts ...FetcherOption) *Fetcher
func (f *Fetcher) Fetch(ctx context.Context, cdpURI string) ([]byte, error)
```

Cache 逻辑：
- `cachedEntry{data, fetchedAt, ttl}`
- TTL = min(nextUpdate - fetchedAt, maxAge)
- 默认 maxAge = 12h, HTTP timeout = 30s
- `Accept: application/pkix-crl` header

### 5.5 `verify/crl/checker.go`

```go
type Checker struct {
    fetcher *Fetcher
}

type CheckerOption func(*Checker)

func NewChecker(opts ...CheckerOption) *Checker
func (c *Checker) Check(ctx context.Context, leaf *x509.Certificate, chain []*x509.Certificate) Result
```

Check 流程：
1. `ResolveCDP(chain)` → CDPSkipped/CDPFailed/CDPFound
2. `findIssuingCA(leaf, chain)` → 若无 issuer → Failed
3. `fetcher.Fetch(ctx, cdpURI)` → IO error → Failed
4. `ValidateNotRevoked(crlBytes, issuer, leaf.SerialNumber)` → ErrRevoked/其他

### 5.6 `ati/server.go` Integration

新增 Options：
```go
func WithCRLCheck() ServerOption
func WithCRLCheckDisabled() ServerOption
func WithCRLHTTPClient(client *http.Client) ServerOption
```

serverConfig 新增：
```go
crlEnabled    *bool
crlChecker    *crl.Checker
crlHTTPClient *http.Client
```

自动启用逻辑（NewServerTLSConfig）：
```go
if shouldEnableCRL(cfg) {
    var fetcherOpts []crl.FetcherOption
    if cfg.crlHTTPClient != nil {
        fetcherOpts = append(fetcherOpts, crl.WithHTTPClient(cfg.crlHTTPClient))
    }
    cfg.crlChecker = crl.NewChecker(crl.WithFetcher(crl.NewFetcher(fetcherOpts...)))
}
```

buildVerifyConnection 插入点（cert validity 之后，Badge 之前）：
```go
if cfg.crlChecker != nil {
    crlResult := cfg.crlChecker.Check(context.Background(), peerCert, cs.PeerCertificates)
    if crlResult.ShouldReject() {
        slog.Error("[server-verify] CRL check FAILED", "status", crlResult.Status, "message", crlResult.Message)
        return fmt.Errorf("CRL check failed: %s", crlResult.Message)
    }
    if crlResult.Status == crl.Passed {
        slog.Info("[server-verify] CRL check PASSED", "cdpURI", crlResult.CDPURI)
    }
}
```

---

## 依赖

### 新增外部依赖

- `github.com/Masterminds/semver/v3` — Go 生态标准 semver 库，用于 Full Semver Range Matching (Module 4)。支持 `^`/`~`/`>=`/range 约束表达式。

### Go 标准库

- `crypto/x509` — CRL 解析、CDP 字段、证书操作
- `net/http` — CRL 下载
- `math/big` — 序列号比较
- `sync` — 缓存并发控制

---

## 与 Java SDK 的完整对照

| Java 改动 | Go 对应 |
|-----------|---------|
| VerificationPolicy enum rename | ati/verification_policy.go + trust_level.go deprecated |
| NONE policy (client skip TLS) | ati/mtls_client.go InsecureSkipVerify |
| ConnectOptions.identityHost/accessHost | ati/mtls_client.go WithIdentityHost/WithAccessHost |
| DefaultConnectionVerifier dual-hostname | AgentClient.resolveIdentityHost/resolveAccessHost |
| AtiDiscoveryClient 删除 | verify/aliyun_discovery.go 删除 |
| DnsTxtRecordLookup | 已有 StandardDNSResolver.LookupATIDiscovery |
| semver4j range matching | ati/version_policy.go + Masterminds/semver/v3 |
| CdpExtractor | verify/crl/cdp.go |
| CrlHttpClient / DefaultCrlHttpClient | verify/crl/fetcher.go (内嵌 http.Client) |
| CrlFetcher (Caffeine cache) | verify/crl/fetcher.go (sync.Mutex + map) |
| CrlValidator | verify/crl/validator.go |
| CrlRevocationChecker | verify/crl/checker.go |
| CrlRevocationResult | verify/crl/result.go |
| AtiServerAutoConfiguration CRL bean | ati/server.go WithCRLCheck option |
