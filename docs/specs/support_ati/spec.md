# ATI Golang SDK 技术规格文档

v3.0 | 2026-06-15 | 基于代码实现同步更新

## 30 秒快速上手

### Client 端（调用其他 Agent）

```go
package main

import "gitlab.alibaba-inc.com/alibaba-dns/ati-golang-sdk/ati"

func main() {
    client, _ := ati.NewAgentClient(
        ati.WithMTLSCerts("./certs/identity.pem", "./certs/key.pem",
                          "./certs/server.pem", "./certs/ca_bundle.pem"),
    )

    // SDK 提供安全传输层（mTLS + DNS 发现 + 多级信任验证）
    resp, _ := client.Post(ctx, "https://translate.example.com/mcp",
        map[string]any{"method": "translate", "params": map[string]string{"text": "Hello"}})

    // resp.VerificationOutcome 包含 TrustOutcome（AchievedLevel + 各项检查状态）
}
```

### Server 端（被其他 Agent 调用）

```go
package main

import "gitlab.alibaba-inc.com/alibaba-dns/ati-golang-sdk/ati"

func main() {
    tlsConfig, _ := ati.NewServerTLSConfig(
        ati.WithServerCert("./certs/server.pem", "./certs/key.pem"),
        ati.WithClientCA("./certs/cnnic_ca_bundle.pem"),
    )

    server := &http.Server{
        Addr:      ":443",
        TLSConfig: tlsConfig,  // TLS 1.3 minimum, VerifyConnection callback 内置
        Handler:   http.HandlerFunc(handler),
    }
    server.ListenAndServeTLS("", "")
}

func handler(w http.ResponseWriter, r *http.Request) {
    peer, _ := ati.PeerATIName(r.TLS)
    fmt.Printf("来访 Agent: %s (v%s)\n", peer.Host, peer.Version)
}
```

### 离线验证（无网络场景）

```go
import "gitlab.alibaba-inc.com/alibaba-dns/ati-golang-sdk/verify"

verifier := verify.NewOfflineVerifier(tlPublicKey, producerKeys)
result, err := verifier.VerifyOffline(ctx, embeddedStatement, certIdentity)
// result.IsSuccess(), result.TrustLevel, result.Warnings
```

---

## 设计约束

- **SDK 不做注册** — PRD 5.1：注册须通过控制台 GUI 完成，SDK 仅加载证书 + 通信
- **只做安全传输层** — SDK 提供 mTLS + DNS 发现 + 信任验证，不封装应用协议（MCP/A2A/OpenAPI 由用户自行构造请求）
- **Client + Server 双端** — SDK 既支持调用其他 Agent（Client），也支持被其他 Agent 调用时验证对方身份（Server）
- **TLS 1.3 最低版本** — 所有 mTLS 连接强制 TLS 1.3
- **开发者体验优先** — 每个决策回答"对调 SDK 的开发者意味着什么"
- **API 表面最小化** — 公开 ~15 个方法（Client 端 + Server 端），注册相关方法收入 internal
- **SDK 不需要 OAuth2** — OAuth2 是控制台后端调 CNNIC 写接口用的；SDK 只调公开只读的 TL 查询接口和 DNS
- **多级信任可选** — 支持 TrustPKI / TrustBadge / TrustFull 三级，默认 auto-detect

---

## 架构概览

### 三条验证路径

SDK 提供三条独立的验证路径，适用于不同场景：

```
Path A: Badge-based Verification (ServerVerifier / ClientVerifier)
    用于实时 mTLS 连接验证，由 ati/ 公开 API 驱动。
    DNS _ati-badge → TLog Badge Fetch → Fingerprint Match + Hostname Match → DANE (optional)

Path B: Gold/TL-based Verification (VerifyGold)
    用于完整 TL 透明日志深度验证，含密码学证明。
    DNS _ati Discovery → TL Response Fetch → Receipt Sig → Merkle Proof → Producer Sig → Fingerprint Match → Status Check

Path C: SCITT Verification (VerifyWithScitt)
    用于带 SCITT Headers 的连接，兼容 GoDaddy ANS 遗留系统。
    SCITT Receipt → Status Token → Fingerprint Match → ATIName Binding → DANE (optional)
```

### 公开 API 层信任等级

```go
type TrustLevel int

const (
    TrustNone  TrustLevel = iota  // 仅 TLS 握手（Server only）
    TrustPKI                       // CA 链 + DNS 发现 + SAN 匹配（Client only）
    TrustBadge                     // PKI + Badge 验证
    TrustFull                      // Badge + DANE/TLSA 验证
)

// 向下兼容别名
const (
    Bronze = TrustPKI
    Silver = TrustBadge
    Gold   = TrustFull
)
```

**Auto-detect 模式**（默认）：不指定 TrustLevel 时，SDK 自动探测所有级别并报告达到的最高级别。
**Explicit 模式**：通过 `WithTrustLevel()` / `WithClientVerifier()` 指定要求的级别，未达到则拒绝连接。

### 五阶段验证管道（Gold Path）

```
Stage 1: DNS Discovery (Parallel)
    ├── _ati.{host} TXT → ATI Record (id, ra, version, mode)
    ├── _ati-badge.{host} TXT → Badge Record (url, version)
    ├── TLSA → DANE records
    └── HTTPS/SVCB → ALPN, ECH, port

Stage 2: TL Log Fetch
    GET /tl/agents/{agentId}/logs/latest → TLResponse (three-layer nested)

Stage 3: Cryptographic Verification
    ├── Receipt Signature (ECDSA P-256 over JCS-canonicalized {merkleRoot, treeSize, timestamp})
    ├── Merkle Inclusion Proof (RFC 6962, SHA-256 with 0x00/0x01 prefixes)
    └── Producer Signature (ECDSA P-256 over JCS-canonicalized EventPayload)

Stage 4: Identity Binding
    ├── Certificate Fingerprint Match (SHA-256, identity cert or server cert)
    └── Agent Status Check (ACTIVE/WARNING/DEPRECATED/EXPIRED/REVOKED)

Stage 5: Trust Assessment
    ├── Trust Index Computation (0-100, 12 weighted signals)
    └── Trust Level Assignment (NONE/BASIC/VERIFIED/HIGH)
```

### 三层嵌套 TL Response 模型

```
TLResponse
├── Status: "ACTIVE" | "WARNING" | "DEPRECATED" | "EXPIRED" | "REVOKED"
├── Receipt (TL 签发的 inclusion receipt)
│   ├── Alg: "ES256"
│   ├── Kid: key identifier
│   ├── Issuer: TL service name
│   ├── MerkleRoot: hex-encoded SHA-256
│   ├── TreeSize: int64
│   ├── InclusionProof: {LeafIndex, AuditPath}
│   ├── Timestamp: time.Time
│   └── Signature: base64(ASN1 DER ECDSA)
├── ProducerEnvelope (Producer/RA 签名信封)
│   ├── Alg: "ES256"
│   ├── Kid: producer key identifier
│   ├── Producer: RA identifier (e.g. "aliyun")
│   └── Signature: base64(ASN1 DER ECDSA)
└── EventPayload (内层 agent 事件数据)
    ├── AnsID: agent identifier
    ├── AnsName: "ati://agent.example.com"
    ├── EventType: "attestation"
    ├── Agent: {Host, Name, Version, ProviderID}
    ├── Attestations:
    │   ├── IdentityCert: {Fingerprint, Type}
    │   ├── ServerCert: {Fingerprint, Type}
    │   ├── TrustCard: {CapabilitiesHash, HashAlg, Canonicalization, TrustCardUrl}
    │   ├── SchemaHashes: map[string]string
    │   ├── DNSRecordsProvisioned: map[string]string
    │   ├── DomainValidation: string
    │   └── DNSSECStatus: string
    ├── IssuedAt: time.Time
    ├── ExpiresAt: *time.Time (optional)
    └── RAID: string
```

---

## 外部依赖与通信接口

### Go Module 直接依赖

| 依赖 | 用途 | 状态 |
|------|------|------|
| `github.com/miekg/dns` | DNS 查询（TXT / TLSA / HTTPS SVCB / DNSSEC） | 保留 |
| `github.com/fxamacker/cbor/v2` | COSE/CBOR 解析（SCITT 兼容层） | 保留 |
| `golang.org/x/sync` | errgroup（并行 DNS 查询） | 保留 |
| `golang.org/x/crypto` | OCSP 验证 | 保留 |

### SDK 需要通信的外部服务

| 接口 | 通信对象 | 地址 | 协议 | 认证方式 | SDK 使用场景 |
|------|---------|------|------|---------|-------------|
| CNNIC TL 查询 | CNNIC 透明日志服务 | `https://tl.ansagent.cn:8180/ans/api/v1` | HTTPS | 无（公开只读） | Gold 验证：获取 TL 日志 + Receipt |
| Agent-to-Agent | 目标 Agent 端点 | 动态（按 host） | **mTLS**（TLS 1.3） | Identity Certificate | 核心通信 |
| DNS 递归解析器 | DNS 服务 | 系统默认（可配置） | UDP/TCP | 无（DNSSEC 验证） | _ati / _ati-badge / TLSA / HTTPS 查询 |
| Agent Card 端点 | Agent 主机 | 动态（从 _ati TXT url） | HTTPS | 无 | mode=card 时获取元数据 |
| OCSP Responder | CA OCSP 服务 | 动态（从证书 AIA 扩展） | HTTP POST | 无 | 证书吊销状态检查 |

### 加密传输总结

| 通道 | 加密 | 认证 | 完整性 |
|------|------|------|--------|
| SDK → CNNIC TL（查询） | TLS 1.3 | 仅服务端证书 | TLS |
| SDK → Agent（mTLS） | **TLS 1.3** | **双向证书认证** | TLS |
| SDK → DNS | 明文 | 无 | DNSSEC 签名验证 |
| SDK → OCSP | TLS | 服务端证书 | TLS + OCSP 签名 |

---

## 核心验证模块

### 模块一：Receipt Signature 验证

验证 TL 服务对 Merkle tree 状态的签名承诺。

**算法流程**：
1. 从 Receipt 提取 `{merkleRoot, treeSize, timestamp}`
2. JSON 序列化 → JCS (RFC 8785) 规范化
3. SHA-256 哈希
4. ECDSA P-256 ASN1 DER 签名验证（使用 TL 公钥）

```go
func VerifyReceiptSignature(resp *models.TLResponse, trustedKey *ecdsa.PublicKey) error
func VerifySeal(resp *models.TLResponse, trustedKey *ecdsa.PublicKey) error // legacy alias
```

### 模块二：Merkle Inclusion Proof 验证

验证 EventPayload 确实被包含在 Merkle tree 中。

**算法流程**：
1. JCS 规范化 EventPayload → 计算 leaf hash: `SHA-256(0x00 || canonical_payload)`
2. 从 InclusionProof.AuditPath 按 RFC 6962 算法重建 root hash
3. 使用 `crypto/subtle.ConstantTimeCompare` 比对计算出的 root hash == Receipt.MerkleRoot

```go
func VerifyInclusionProof(resp *models.TLResponse) error
```

**Merkle 节点哈希规则**（RFC 6962）：
- Leaf: `H(0x00 || data)`
- Internal: `H(0x01 || left || right)`
- Audit path 中的哈希值为 hex 编码

**边界检查**：
- `treeSize` 必须为正整数
- `leafIndex` 必须在 `[0, treeSize)` 范围内
- Audit path 元素数量必须精确匹配（多余或不足均报错）

### 模块三：Producer Signature 验证

验证 RA（Registration Authority）对 EventPayload 的签名背书。

**算法流程**：
1. JCS 规范化 EventPayload
2. SHA-256 哈希
3. ECDSA P-256 ASN1 DER 签名验证（使用 Producer 公钥，通过 Kid 查找）

```go
type ProducerKeyLookup interface {
    GetProducerKey(kid string) (*ecdsa.PublicKey, error)
}

func VerifyProducerSignature(resp *models.TLResponse, keys ProducerKeyLookup) error
```

### 模块四：Certificate Fingerprint Matching

绑定 TL 记录到 TLS 连接中实际出示的证书。支持 identity cert 和 server cert 双向匹配。

```go
type CertIdentity struct {
    Fingerprint CertFingerprint  // SHA-256 of DER-encoded certificate
}

type CertFingerprint struct {
    hash [32]byte
}

func CertFingerprintFromDER(der []byte) CertFingerprint
func CertFingerprintFromX509(cert *x509.Certificate) CertFingerprint
func CertIdentityFromX509(cert *x509.Certificate) *CertIdentity
```

**验证规则**（`matchFingerprint` 函数）：
- 先检查 `IdentityCert.Fingerprint` 是否匹配
- 再检查 `ServerCert.Fingerprint` 是否匹配
- 任一匹配即通过（identity cert 和 server cert 可能使用不同证书）

### 模块五：Agent Status 检查

```go
type TLAgentStatus string

const (
    TLStatusActive     TLAgentStatus = "ACTIVE"      // 验证通过
    TLStatusWarning    TLAgentStatus = "WARNING"      // 通过，附加 Warning
    TLStatusDeprecated TLAgentStatus = "DEPRECATED"   // 通过，附加 Warning
    TLStatusExpired    TLAgentStatus = "EXPIRED"      // 硬失败（终态）
    TLStatusRevoked    TLAgentStatus = "REVOKED"      // 硬失败（终态）
)

func (s TLAgentStatus) IsValidForConnection() bool  // ACTIVE/WARNING/DEPRECATED → true
func (s TLAgentStatus) IsTerminal() bool             // REVOKED/EXPIRED → true
```

- ACTIVE → 通过
- WARNING → 通过，附加 Warning
- DEPRECATED → 通过，附加 Warning
- EXPIRED → 失败（ANS-3006）
- REVOKED → 失败（ANS-3005）

---

## Trust 评估系统

### Trust Level（Gold Path 输出等级）

```go
type TrustLevel string

const (
    TrustLevelNone     TrustLevel = "NONE"     // 验证失败
    TrustLevelBasic    TrustLevel = "BASIC"     // 基础验证通过
    TrustLevelVerified TrustLevel = "VERIFIED"  // 主要验证通过
    TrustLevelHigh     TrustLevel = "HIGH"      // 全部验证通过
)
```

### Trust Index（0-100 分，12 项加权信号）

```go
type TrustIndexParams struct {
    IdentityVerified   bool   // 身份证书验证
    DANEVerified       bool   // DANE/TLSA 验证
    DNSSECValidated    bool   // DNSSEC 签名验证
    TLReceiptVerified  bool   // TL Receipt 签名
    ProducerSigValid   bool   // Producer/RA 签名
    MerkleProofValid   bool   // Merkle 包含性证明
    FingerprintMatch   bool   // 证书指纹匹配
    StatusActive       bool   // Agent 状态为 ACTIVE
    AgentCardVerified  bool   // Agent Card 验证
    CapHashValid       bool   // capabilitiesHash 完整性
    SchemaHashValid    bool   // Schema hash 验证
    ClaimsVerified     int    // 已验证 claims 数量
    ClaimsTotal        int    // claims 总数量
    CertExpiryWarning  bool   // 证书即将过期（扣分项）
}

func ComputeTrustIndex(params TrustIndexParams) (int, TrustLevel)
```

**计分规则**（总计 100 分）：

| 信号 | 权重 | 说明 |
|------|------|------|
| IdentityVerified | +15 | 身份证书已验证 |
| TLReceiptVerified | +15 | TL Receipt 签名有效 |
| DANEVerified | +10 | DANE/TLSA 记录匹配 |
| ProducerSigValid | +10 | RA Producer 签名有效 |
| MerkleProofValid | +10 | Merkle 包含性证明有效 |
| FingerprintMatch | +10 | 证书指纹与 TL 记录匹配 |
| DNSSECValidated | +5 | DNSSEC 验证通过 |
| StatusActive | +5 | Agent 状态为 ACTIVE |
| AgentCardVerified | +5 | Agent Card 验证通过 |
| CapHashValid | +5 | capabilitiesHash 完整性通过 |
| SchemaHashValid | +5 | Schema hash 匹配 |
| ClaimsVerified | +5 | `(verified/total) × 5`（按比例） |
| CertExpiryWarning | -5 | 证书即将过期（扣分） |

**Level 映射**：
- 0-29 → NONE
- 30-54 → BASIC
- 55-79 → VERIFIED
- 80-100 → HIGH

---

## Trust Policy 配置

```go
type DNSSECMode string
const (
    DNSSECModeRequire DNSSECMode = "REQUIRE"  // DNSSEC 验证失败则拒绝
    DNSSECModePrefer  DNSSECMode = "PREFER"   // DNSSEC 验证失败则降级
)

type FailureAction string
const (
    FailureActionFail    FailureAction = "FAIL"     // 硬拒绝
    FailureActionDegrade FailureAction = "DEGRADE"  // 允许降级
)

type TrustPolicy struct {
    DNSSECMode              DNSSECMode    // REQUIRE / PREFER
    TLUnreachable           FailureAction // FAIL / DEGRADE
    CapHashMismatch         FailureAction // FAIL / DEGRADE
    StaplingRequired        bool
    MinTrustLevel           TrustLevel
    OfflineMode             bool
    LongConnRecheckInterval time.Duration
}

func DefaultTrustPolicy() TrustPolicy
func HighSecurityTrustPolicy() TrustPolicy
```

**DefaultTrustPolicy**:
- DNSSECMode: PREFER
- TLUnreachable: DEGRADE
- CapHashMismatch: DEGRADE
- StaplingRequired: false
- MinTrustLevel: BASIC
- LongConnRecheckInterval: 5m

**HighSecurityTrustPolicy**:
- DNSSECMode: REQUIRE
- TLUnreachable: FAIL
- CapHashMismatch: FAIL
- StaplingRequired: true
- MinTrustLevel: VERIFIED
- LongConnRecheckInterval: 2m

**Policy 判断方法**：
```go
func (p *TrustPolicy) ShouldRejectDNSSECInsecure() bool   // DNSSECMode == REQUIRE
func (p *TrustPolicy) ShouldRejectTLUnreachable() bool     // TLUnreachable == FAIL
func (p *TrustPolicy) ShouldRejectCapHashMismatch() bool   // CapHashMismatch == FAIL
```

---

## DNS Discovery（并行）

### Parallel Discovery

```go
type DiscoveryResult struct {
    AgentCardURL    string
    TLQueryURL      string
    IdentityTLSA    []TLSARecord
    ServerTLSA      []TLSARecord
    HTTPSParams     *SVCBResult
    SelectedVersion *models.Version
    DNSSECStatus    string  // "fully_validated" | "insecure" | "bogus"
    AgentID         string
}

func ParallelDiscovery(ctx context.Context, fqdn models.Fqdn, resolver DNSResolver, daneResolver DANEResolver) (*DiscoveryResult, error)
```

使用 `sync.WaitGroup` 并行查询：
- `_ati.{host}` TXT → ATI Records（必需，缺失则报错 ANS-1001）
- `_ati-badge.{host}` TXT → Badge Records（非致命）
- `_443._tcp.{host}` TLSA → DANE records（需 DANEResolver，非致命）

### _ati TXT Record

```
_ati.{host} TXT "v=ati1; id={agentId}; ra=aliyun; version=v1.0.0; mode=direct"
```

| 字段 | 说明 | 必需 |
|------|------|------|
| v | 版本标识，固定 `ati1` | 是 |
| id | Agent ID | 是 |
| ra | 签发 RA 标识符 | 是 |
| version | semver（v前缀） | 是 |
| mode | card / direct | 是 |
| p | 协议过滤（mcp/a2a/openapi） | 否 |
| url | 元数据端点（mode=card时必需） | 条件必需 |

### _ati-badge TXT Record

```
_ati-badge.{host} TXT "v=ati-badge1; version=v1.0.0; url=https://tl.ansagent.cn:8180/..."
```

DNS 解析器支持 `_ati-badge` → `_ra-badge` 的自动回退（仅在 NXDOMAIN 时）。

### HTTPS/SVCB Record

```go
type SVCBResult struct {
    Found     bool
    ALPN      []string  // e.g. ["h2", "h3"]
    Port      uint16
    ECHConfig []byte
    Target    string
}

func LookupHTTPSSVCB(ctx context.Context, server string, fqdn models.Fqdn) (*SVCBResult, error)
```

---

## mTLS + Handshake 集成

### Client 端 VerifyConnection（TLS 1.3）

```go
func NewAgentClient(opts ...AgentClientOption) (*AgentClient, error)
```

**验证流程**（`Do` 方法内执行）：
1. DNS 发现: `_ati.{host}` TXT 查询 → 获取 AgentID
2. mTLS 请求: TLS 1.3 + Identity Certificate + CA 链验证
3. VerifyConnection callback: 证书有效期检查 + 过期警告（≤30天）
4. PKI 级验证: CA 链 + DNS 发现 + URI SAN 匹配 → `TrustPKI`
5. Badge 验证: ServerVerifier.Verify(fqdn, cert) → `TrustBadge`
6. DANE 验证: DANEVerifier.Verify(fqdn, 443, cert) → `TrustFull`

**Auto-detect 模式**：逐步探测，报告 `AchievedLevel`（最高达到的级别）。
**Explicit 模式**：指定 `WithTrustLevel(level)`，未达到则请求失败并关闭连接。

### Server 端 VerifyConnection（TLS 1.3）

```go
func NewServerTLSConfig(opts ...ServerOption) (*tls.Config, error)
```

- TLS 1.3 minimum
- ClientAuth: RequireAndVerifyClientCert
- VerifyConnection callback:
  1. 证书有效期检查
  2. Badge 验证（通过 ClientVerifier）
  3. DANE 验证（需要 `WithServerDANEResolver()`）
  4. 结果存入 `sync.Map`（按 cert fingerprint 索引）

**查询对方信任等级**：
```go
func PeerTrustLevel(state *tls.ConnectionState, peerLevels *sync.Map) *TrustLevel
```

### 证书有效性检查

```go
type CertValidityCheck struct {
    Valid            bool
    RemainingPercent float64
    ExpiresAt        time.Time
    Warning          string   // non-empty if <30 days remaining
}

func CheckCertValidity(cert *x509.Certificate, now time.Time) *CertValidityCheck
```

---

## Badge-based 验证路径（ServerVerifier / ClientVerifier）

### ServerVerifier（验证 server 证书）

```go
type ServerVerifier struct { config *verifierConfig }

func NewServerVerifier(opts ...Option) *ServerVerifier
func (v *ServerVerifier) Verify(ctx context.Context, fqdn models.Fqdn, cert *CertIdentity) *VerificationOutcome
func (v *ServerVerifier) Prefetch(ctx context.Context, fqdn models.Fqdn) (*models.Badge, error)
func (v *ServerVerifier) VerifyWithScitt(ctx context.Context, fqdn models.Fqdn, cert *CertIdentity, headers *scitt.Headers) *VerificationOutcome
```

**Verify 流程**：
1. Cache 查找（有缓存且非指纹不匹配 → 直接返回）
2. DNS 查询 `_ati-badge` → 获取 badge URL
3. Badge URL 安全验证（域名白名单）+ TL Host 重写（信任锚点）
4. TLog 获取 badge
5. 缓存 badge
6. 验证: badge status + server cert fingerprint + hostname 匹配
7. 可选 DANE/TLSA 检查

### ClientVerifier（验证 client 证书）

```go
type ClientVerifier struct { config *verifierConfig }

func NewClientVerifier(opts ...Option) *ClientVerifier
func (v *ClientVerifier) Verify(ctx context.Context, cert *CertIdentity) *VerificationOutcome
func (v *ClientVerifier) VerifyWithScitt(ctx context.Context, cert *CertIdentity, headers *scitt.Headers) *VerificationOutcome
```

**Verify 流程**：
1. 从证书提取 FQDN（CN）
2. 从 URI SAN 提取 ATI Name（`ati://host/version`）
3. 提取 version
4. Cache 查找（按 FQDN + version）
5. DNS 查询 `_ati-badge` → 版本匹配 badge URL
6. TLog 获取 badge
7. 缓存 badge
8. 验证: badge status + identity cert fingerprint + hostname + ATI Name 匹配
9. 可选 DANE/TLSA 检查

### AnsVerifier（统一门面）

```go
type AnsVerifier struct {
    server *ServerVerifier
    client *ClientVerifier
}

func NewAnsVerifier(opts ...Option) *AnsVerifier
func (v *AnsVerifier) VerifyServer(ctx context.Context, fqdnStr string, cert *CertIdentity) *VerificationOutcome
func (v *AnsVerifier) VerifyClient(ctx context.Context, cert *CertIdentity) *VerificationOutcome
func (v *AnsVerifier) VerifyServerWithScitt(ctx context.Context, fqdnStr string, cert *CertIdentity, headers *scitt.Headers) *VerificationOutcome
func (v *AnsVerifier) VerifyClientWithScitt(ctx context.Context, cert *CertIdentity, headers *scitt.Headers) *VerificationOutcome
func (v *AnsVerifier) Prefetch(ctx context.Context, fqdnStr string) (*models.Badge, error)
```

### Failure Policy

```go
type FailurePolicy int
const (
    FailClosed         FailurePolicy = iota  // DNS/TLog 错误 → 拒绝
    FailOpenWithCache                         // DNS/TLog 错误 → 尝试 stale cache
    FailOpen                                  // DNS/TLog 错误 → 放行（附加 warning）
)
```

**注意**：Failure Policy 仅适用于 DNS 和 TLog 基础设施故障。SCITT 验证失败（签名无效、格式错误）始终是终态拒绝，不受 FailOpen 影响。

### Badge URL 安全验证

```go
type URLValidator struct {
    trustedDomains []string
}

func NewDefaultURLValidator() *URLValidator
func NewURLValidator(domains []string) *URLValidator
func (v *URLValidator) Validate(rawURL string) error
```

Badge URL 域名必须在信任白名单中（防止 DNS 投毒攻击导向恶意 TL 服务器）。

### TL Host 重写

```go
const DefaultTrustedTLHost = "tl.ansagent.cn:8180"
func RewriteBadgeURLHost(rawURL string, trustedHost string) (string, error)
```

Badge TXT 记录中的 URL 主机名会被替换为配置的可信 TL 主机（信任锚点），确保 badge 始终从可信 TL 服务获取。

---

## Gold Verification Pipeline（完整 TL 深度验证流程）

```go
type GoldVerifierConfig struct {
    TLBaseURL    string
    TLPublicKey  *ecdsa.PublicKey
    ProducerKeys ProducerKeyLookup
    DNSResolver  DNSResolver
    TLogClient   TransparencyLogClient
    TrustPolicy  *TrustPolicy
    Logger       *slog.Logger
}

func VerifyGold(ctx context.Context, fqdn models.Fqdn, cert *CertIdentity, cfg *GoldVerifierConfig) *VerificationResult
```

**完整流程**：
1. DNS Discovery → `_ati.{host}` → 获取 Agent ID
2. Fetch TL Response → `GET {TLBaseURL}/tl/agents/{agentId}/logs/latest`
3. Verify Receipt Signature（TL 公钥 + JCS + SHA-256 + ECDSA）
4. Verify Merkle Inclusion Proof（RFC 6962 + constant-time compare）
5. Verify Producer Signature（RA 公钥 + JCS + SHA-256 + ECDSA, 可选但推荐）
6. Certificate Fingerprint Cross-Match（identity cert 或 server cert 任一匹配）
7. Status Check（REVOKED/EXPIRED → ANS-3005/3006 硬失败）
8. Compute Trust Index → Assign Trust Level

**输出**：`*VerificationResult`，包含 TrustIndex (0-100)、TrustLevel、各项验证状态、Warnings。

---

## Agent Card 验证

### 验证管道

```go
type AgentCardVerifier struct {
    producerKeys ProducerKeyLookup
    httpClient   *http.Client  // 3s timeout
    logger       *slog.Logger
}

type AgentCardResult struct {
    SignatureValid  bool                    `json:"signatureValid"`
    CapHashValid   bool                    `json:"capHashValid"`
    SchemaValid    bool                    `json:"schemaValid"`
    ClaimsVerified []VerifiableClaimResult `json:"claimsVerified,omitempty"`
}

type VerifiableClaimResult struct {
    ClaimType string `json:"claimType"`
    Issuer    string `json:"issuer"`
    Valid     bool   `json:"valid"`
    Error     string `json:"error,omitempty"`
}

func NewAgentCardVerifier(producerKeys ProducerKeyLookup, opts ...AgentCardVerifierOption) *AgentCardVerifier
func (v *AgentCardVerifier) VerifyAgentCard(ctx context.Context, agentCardURL string, attestations *models.EventAttestations) (*AgentCardResult, error)
```

**验证步骤**：
1. Fetch Agent Card（1MB 大小限制）
2. 签名验证（COSE_Sign1，RA producer key）
3. capabilitiesHash 完整性: JCS(card body) → SHA-256 → 比对
4. Schema hash 验证
5. verifiableClaims: 逐项验证第三方签名（返回 `[]VerifiableClaimResult`）

### capabilitiesHash 验证

```
Card Body → JCS Canonicalize → SHA-256 → hex → compare with attestations.capabilitiesHash
```

支持 `SHA256:` / `sha256:` 前缀或裸 hex 格式。仅支持 SHA-256 算法。

---

## Session Monitor（长连接周期性重验证）

```go
type SessionMonitor struct {
    interval    time.Duration
    tlogClient  TransparencyLogClient
    dnsResolver DNSResolver
    tlBaseURL   string
    onRevoked   func(fqdn string, err error)
    logger      *slog.Logger
}

func NewSessionMonitor(interval time.Duration, tlogClient TransparencyLogClient, dnsResolver DNSResolver, onRevoked func(string, error)) *SessionMonitor
func (m *SessionMonitor) Watch(ctx context.Context, fqdn models.Fqdn, cert *CertIdentity) (stop func())
func (m *SessionMonitor) Stop()
```

**行为**：
- 周期性重新查询 DNS + TL 状态
- DNS 失败 → 忽略（非吊销）
- TL 不可达 → 忽略（非吊销）
- 状态变为 REVOKED/EXPIRED → 调用 `onRevoked(fqdn, error)` 回调 + 停止监控
- 默认间隔 5 分钟（interval ≤ 0 时自动设为 5m）
- 通过 TrustPolicy.LongConnRecheckInterval 配置间隔
- 支持并发监控多个连接（每个 fqdn 一个 goroutine）

---

## Offline Verification（离线模式）

```go
type OfflineVerifier struct {
    tlPublicKey  *ecdsa.PublicKey
    producerKeys ProducerKeyLookup
}

func NewOfflineVerifier(tlKey *ecdsa.PublicKey, producerKeys ProducerKeyLookup) *OfflineVerifier
func (v *OfflineVerifier) VerifyOffline(ctx context.Context, tlResponseJSON []byte, cert *CertIdentity) (*VerificationResult, error)
```

**验证流程**（无网络访问）：
1. JSON Unmarshal → `*models.TLResponse`
2. 验证 Receipt 签名（使用预置 TL 公钥）
3. 验证 Merkle Inclusion Proof
4. 验证 Producer 签名（如配置了 ProducerKeys）
5. 证书指纹匹配（identity cert 或 server cert）

**限制**：
- 结果始终附加 Warning: `"offline mode: revocation status unknown"`
- 无法防止 split-view 攻击
- 无法验证实时吊销状态

---

## JWS Detached Signatures（事务级签名）

用于对单次请求/响应的 payload 进行不可否认签名。

```go
func CreateJWSDetached(payload []byte, privateKey *ecdsa.PrivateKey, kid string) (string, error)
func VerifyJWSDetached(signature string, payload []byte, keys ProducerKeyLookup) error
```

**格式**（RFC 7797 b64:false）：
- Header: `{"alg":"ES256","kid":"...","b64":false,"crit":["b64"]}`
- Signature: raw r||s (64 bytes), base64url 编码
- Wire format: `base64url(header)..base64url(signature)` (payload detached)

**签名输入**: `ASCII(base64url(header)) || '.' || payload`

---

## OCSP Dual-Channel Revocation

```go
type OCSPChecker struct {
    httpClient *http.Client
}

type OCSPResult struct {
    Status     string    // "good", "revoked", "unknown"
    ProducedAt time.Time
    Source     string    // "stapled" or "active"
}

func NewOCSPChecker() *OCSPChecker
func (c *OCSPChecker) CheckOCSP(ctx context.Context, cert, issuer *x509.Certificate, stapledResp []byte) (*OCSPResult, error)
```

**双通道策略**：
1. 优先使用 TLS 握手中的 stapled OCSP response
2. Stapled 无效/过期 → 主动 POST 到 AIA 中的 OCSP responder
3. 全部失败 → 返回 "unknown" + Warning

---

## ConnectRequest（连接请求）

```go
type ConnectRequest struct {
    Target  string `json:"target"`           // 目标主机名
    Version string `json:"version,omitempty"` // 可选版本
}

type ConnectResult struct {
    AgentID  string  // _ati TXT 中的 Agent ID
    Endpoint string  // https://{target}
}

func (c *AgentClient) Connect(ctx context.Context, req ConnectRequest) (*ConnectResult, error)
```

**流程**：
1. 验证 target 非空 + 合法 FQDN
2. DNS 查询 `_ati.{target}` → 提取 agentId
3. 返回 `ConnectResult{AgentID, Endpoint}`

---

## Error Code System

### ANSError 结构体

```go
type ANSError struct {
    Code           string   `json:"code"`
    Severity       Severity `json:"severity"`
    Stage          Stage    `json:"stage"`
    Message        string   `json:"message"`
    AnchorEvidence any      `json:"anchorEvidence,omitempty"`
    Cause          error    `json:"-"`
}

type Severity string
const (
    SeverityHard Severity = "HARD"  // 验证失败，不可降级
    SeveritySoft Severity = "SOFT"  // 可按 TrustPolicy 降级
)

type Stage int
const (
    StageDNSDiscovery Stage = 1  // DNS 发现
    StageMTLS         Stage = 2  // mTLS 证书验证
    StageTLVerify     Stage = 3  // TL 透明日志验证
    StageAgentCard    Stage = 4  // Agent Card 验证
    StageSession      Stage = 5  // 会话监控
)
```

### 错误码清单

| Code | Stage | Severity | 含义 |
|------|-------|----------|------|
| ANS-1001 | 1 DNS | HARD | DNS discovery: no _ati records |
| ANS-1002 | 1 DNS | SOFT | DNSSEC validation failed (bogus) |
| ANS-1003 | 1 DNS | SOFT | DNSSEC insecure (unsigned zone) |
| ANS-2001 | 2 mTLS | HARD | Certificate chain invalid |
| ANS-2002 | 2 mTLS | HARD | Certificate expired |
| ANS-2003 | 2 mTLS | HARD | DANE fingerprint mismatch |
| ANS-2004 | 2 mTLS | HARD | SAN URI host mismatch |
| ANS-2005 | 2 mTLS | HARD | SAN URI missing |
| ANS-3001 | 3 TL | HARD | Receipt signature verification failed |
| ANS-3002 | 3 TL | HARD | Merkle inclusion proof invalid |
| ANS-3003 | 3 TL | HARD | Producer signature verification failed |
| ANS-3004 | 3 TL | HARD | Certificate fingerprint mismatch (TL) |
| ANS-3005 | 3 TL | HARD | Agent status REVOKED |
| ANS-3006 | 3 TL | HARD | Agent status EXPIRED |
| ANS-3007 | 3 TL | SOFT | Agent status WARNING |
| ANS-3008 | 3 TL | SOFT | TL service unreachable |
| ANS-4001 | 4 Card | SOFT | Agent Card fetch failed |
| ANS-4002 | 4 Card | SOFT | Capabilities hash mismatch |
| ANS-4003 | 4 Card | SOFT | Agent Card signature invalid |
| ANS-4004 | 4 Card | SOFT | Schema hash mismatch |
| ANS-4005 | 4 Card | SOFT | Verifiable claim invalid |
| ANS-5001 | 5 Session | HARD | Agent revoked during session |
| ANS-5002 | 5 Session | SOFT | Stapling credential expired |

---

## Unified Verification Result（Gold Path）

```go
type VerificationResult struct {
    AnsName           string           `json:"ansName"`
    Connected         bool             `json:"connected"`
    TrustLevel        TrustLevel       `json:"trustLevel"`
    TrustIndex        int              `json:"trustIndex"`
    IdentityVerified  bool             `json:"identityVerified"`
    TLVerified        bool             `json:"tlVerified"`
    AgentCardVerified *AgentCardResult `json:"agentCardVerified,omitempty"`
    DNSSECStatus      string           `json:"dnssecStatus"`
    Status            string           `json:"status"`
    Warnings          []string         `json:"warnings,omitempty"`
    Error             *ANSError        `json:"error,omitempty"`
    Timestamp         time.Time        `json:"timestamp"`
}

func (r *VerificationResult) IsSuccess() bool                       // Connected && Error == nil
func (r *VerificationResult) MeetsTrustLevel(min TrustLevel) bool   // r.TrustLevel >= min
func (r *VerificationResult) ToError() error                        // ANSError or nil
func NewSuccessResult(ansName string, trustIndex int, trustLevel TrustLevel) *VerificationResult
func NewFailureResult(ansName string, err *ANSError) *VerificationResult
```

---

## Verifier Configuration（功能选项）

```go
type verifierConfig struct {
    // Core (Badge path)
    dnsResolver         DNSResolver
    tlogClient          TransparencyLogClient
    cache               *BadgeCache
    failurePolicy       FailurePolicy
    failurePolicyConfig FailurePolicyConfig
    urlValidator        *URLValidator
    trustedTLHost       string
    daneResolver        DANEResolver
    scittKeyLookup      scitt.KeyLookup
    clockSkewTolerance  time.Duration   // default: 120s, max: 10m
    logger              *slog.Logger

    // Extended (Gold path)
    trustPolicy       *TrustPolicy
    producerKeys      ProducerKeyLookup
    agentCardVerifier *AgentCardVerifier
    sessionMonitor    *SessionMonitor
    ocspChecker       *OCSPChecker
    parallelFetch     bool
    offlineMode       bool
}

// Core options
func WithDNSResolver(r DNSResolver) Option
func WithTlogClient(t TransparencyLogClient) Option
func WithCache(cache *BadgeCache) Option
func WithCacheConfig(cfg CacheConfig) Option
func WithFailurePolicy(policy FailurePolicy) Option
func WithFailurePolicyConfig(cfg FailurePolicyConfig) Option
func WithTrustedRADomains(domains []string) Option
func WithoutURLValidation() Option
func WithTrustedTLHost(host string) Option
func WithDANEResolver(d DANEResolver) Option
func WithScittKeyLookup(kl scitt.KeyLookup) Option
func WithClockSkewTolerance(d time.Duration) Option
func WithLogger(l *slog.Logger) Option

// Extended options
func WithTrustPolicy(tp *TrustPolicy) Option
func WithProducerKeys(keys ProducerKeyLookup) Option
func WithAgentCardVerifier(v *AgentCardVerifier) Option
func WithSessionMonitor(sm *SessionMonitor) Option
func WithOCSPCheckerOption(c *OCSPChecker) Option
func WithParallelFetch(enabled bool) Option
func WithOfflineMode(enabled bool) Option
```

---

## Trust Card

### 获取流程

```go
func GetTrustCard(ctx context.Context, host string, version string, opts ...TrustCardOption) (*models.TrustCard, error)
```

1. 解析 `_ati` TXT → 获取 agentId
2. 调用 TL 接口: `GET {tlBaseURL}/tl/agents/{agentId}/logs/latest`
3. 解析 TLResponse → 提取 Trust Card 字段

### Trust Card 结构体

```go
type TrustCard struct {
    AgentID          string              `json:"agentId"`
    AgentName        string              `json:"agentName"`
    AgentDisplayName string              `json:"agentDisplayName"`
    AgentDescription string              `json:"agentDescription"`
    Version          string              `json:"version"`
    AgentHost        string              `json:"agentHost"`
    Endpoints        []TrustCardEndpoint `json:"endpoints"`
    SecuritySchemes  map[string]any      `json:"securitySchemes,omitempty"`
    VerifiableClaims []map[string]any    `json:"verifiableClaims,omitempty"`
}

type TrustCardEndpoint struct {
    Protocol    string             `json:"protocol"`
    AgentURL    string             `json:"agentUrl"`
    MetadataURL string             `json:"metadataUrl,omitempty"`
    DocURL      string             `json:"docUrl,omitempty"`
    Transports  []string           `json:"transports,omitempty"`
    Functions   []EndpointFunction `json:"functions,omitempty"`
}
```

---

## 诊断

```go
func Diagnose(ctx context.Context, host string, opts ...DiagnoseOption) (*DiagnoseResult, error)
```

**9 步诊断**：
1. Host Validation → FQDN 解析
2. DNS Discovery (_ati TXT) → AgentID + Mode
3. DNS Badge Lookup (_ati-badge TXT) → Badge URL
4. TL Response Fetch → Status + AnsName
5. Receipt Signature Verification → Alg + Kid
6. Merkle Inclusion Proof → TreeSize + LeafIndex
7. Producer Signature → Producer + Kid（无 key 则 SKIP）
8. Certificate Fingerprints → Identity + Server
9. Agent Card Commitment → capabilitiesHash

**输出格式**：
```go
type DiagnoseResult struct {
    Host      string         `json:"host"`
    Timestamp string         `json:"timestamp"`
    Steps     []DiagnoseStep `json:"steps"`
    Summary   string         `json:"summary"` // "ALL PASS" / "PARTIAL FAIL" / "FAIL (reason)"
}

type DiagnoseStep struct {
    Name     string `json:"name"`
    Status   string `json:"status"`   // "PASS" / "FAIL" / "SKIP"
    Duration string `json:"duration"`
    Detail   string `json:"detail,omitempty"`
    Error    string `json:"error,omitempty"`
}

func (r *DiagnoseResult) String() string  // 人类可读
func (r *DiagnoseResult) JSON() string    // 结构化 JSON
```

---

## 公开 API 清单

### ati/ 包（公开 API 层）

| API | 角色 | 说明 |
|-----|------|------|
| `NewAgentClient(opts...)` | Client | 创建 mTLS 客户端 |
| `WithMTLSCerts(identity, key, server, ca)` | Client | 证书配置 |
| `WithTrustLevel(level)` | Client | 显式信任级别 |
| `WithClientTimeout(d)` | Client | HTTP 超时 |
| `WithTLogClient(t)` | Client | 自定义 TL 客户端 |
| `WithTLPublicKey(key)` | Client | TL 公钥 |
| `WithAgentDANEResolver(r)` | Client | DANE 解析器 |
| `AgentClient.Connect(ctx, req)` | Client | DNS 验证连接 |
| `AgentClient.Get/Post/Put/Delete/Do` | Client | HTTP 方法（内置验证） |
| `AgentClient.Prefetch(ctx, host)` | Client | 预验证 DNS |
| `AgentClient.CertStatus()` | Client | 证书状态 |
| `NewServerTLSConfig(opts...)` | Server | Server 端 TLS 配置 |
| `WithServerCert(cert, key)` | Server | 服务端证书 |
| `WithClientCA(caBundle)` | Server | Client CA 配置 |
| `WithClientVerifier(level)` | Server | 客户端验证级别 |
| `WithServerDANEResolver(r)` | Server | Server DANE 解析器 |
| `PeerATIName(tlsState)` | Server | 提取对方 ATI 身份 |
| `PeerTrustLevel(state, map)` | Server | 查询对方信任级别 |
| `GetTrustCard(ctx, host, version)` | 通用 | 获取 Trust Card |
| `Diagnose(ctx, host, opts...)` | 通用 | 诊断 |

### verify/ 包（验证引擎层）

| API | 角色 | 说明 |
|-----|------|------|
| `VerifyGold(ctx, fqdn, cert, cfg)` | 验证 | Gold 完整验证 |
| `NewOfflineVerifier(key, keys)` | 验证 | 离线验证器 |
| `NewServerVerifier(opts...)` | 验证 | Badge 验证（server cert） |
| `NewClientVerifier(opts...)` | 验证 | Badge 验证（client cert） |
| `NewAnsVerifier(opts...)` | 验证 | 统一门面 |
| `VerifyReceiptSignature(resp, key)` | 密码学 | Receipt 签名验证 |
| `VerifyInclusionProof(resp)` | 密码学 | Merkle 证明验证 |
| `VerifyProducerSignature(resp, keys)` | 密码学 | Producer 签名验证 |
| `VerifyJWSDetached(sig, payload, keys)` | 签名 | JWS Detached 验证 |
| `CreateJWSDetached(payload, key, kid)` | 签名 | JWS Detached 创建 |
| `NewSessionMonitor(...)` | 监控 | 长连接重验证 |
| `ParallelDiscovery(ctx, fqdn, r, d)` | 发现 | 并行 DNS 查询 |
| `ComputeTrustIndex(params)` | 评估 | Trust 评分 |
| `NewAgentCardVerifier(keys, opts...)` | 验证 | Agent Card 验证器 |
| `NewOCSPChecker()` | 验证 | OCSP 吊销检查 |
| `ParseATIRecord(txt)` | 解析 | _ati TXT 解析 |
| `ParseATIName(atiURI)` | 解析 | ati:// URI 解析 |
| `CheckCertValidity(cert, now)` | 工具 | 证书有效期检查 |
| `ParseECDSAPublicKeyPEM(pem)` | 工具 | PEM 公钥解析 |

---

## 完整验证流程图

### Client → Agent 通信流程

```
┌─────────────────────────────────────────────────────────────────┐
│                    AgentClient.Do(ctx, method, url, body)       │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  1. URL 解析 + HTTPS 校验                                       │
│  2. DNS 发现: _ati.{host} TXT → agentId                        │
│     └── explicit 模式: 未发现 → 立即失败                         │
│                                                                 │
│  3. HTTP 请求（mTLS 握手）                                      │
│     └── VerifyConnection callback:                              │
│         ├── 证书有效期检查                                       │
│         └── 过期 ≤30天 → slog.Warn                              │
│                                                                 │
│  4. PKI 验证（TLS 完成后）                                      │
│     ├── CA 链有效                                                │
│     ├── URI SAN 提取 ati:// name                                │
│     └── SAN host 匹配 → AchievedLevel = TrustPKI               │
│                                                                 │
│  5. Badge 验证（auto-detect 或 explicit ≥ TrustBadge）          │
│     ├── ServerVerifier.Verify(fqdn, certIdentity)               │
│     │   ├── DNS _ati-badge → badge URL                          │
│     │   ├── URL 验证 + TL Host 重写                              │
│     │   ├── TLog fetch badge                                     │
│     │   └── status + fingerprint + hostname 匹配                 │
│     └── 通过 → AchievedLevel = TrustBadge                       │
│                                                                 │
│  6. DANE 验证（auto-detect 或 explicit ≥ TrustFull）            │
│     ├── 需要: daneResolver 已配置 + badge 已通过                 │
│     ├── DANEVerifier.Verify(fqdn, 443, certIdentity)            │
│     └── 通过 → AchievedLevel = TrustFull                       │
│                                                                 │
│  7. Explicit 模式: 未达要求 → 关闭连接 + 返回错误                │
│                                                                 │
│  返回: Response { *http.Response, *TrustOutcome }               │
└─────────────────────────────────────────────────────────────────┘
```

### Server 端 VerifyConnection 流程

```
┌─────────────────────────────────────────────────────────────────┐
│                    TLS Handshake → VerifyConnection             │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  1. 检查: peer cert 存在                                        │
│  2. 证书有效期检查 + 过期警告                                    │
│  3. TrustNone → 直接返回 nil（仅证书验证）                       │
│                                                                 │
│  4. Badge 验证 (TrustBadge+)                                    │
│     └── ClientVerifier.Verify(certIdentity)                     │
│         ├── 从 cert 提取 FQDN + ATI Name                        │
│         ├── DNS _ati-badge → badge URL                          │
│         ├── TLog fetch badge                                     │
│         └── status + fingerprint + hostname + ATI name 匹配     │
│                                                                 │
│  5. DANE 验证 (TrustFull)                                       │
│     └── DANEVerifier.Verify(fqdn, 443, certIdentity)           │
│                                                                 │
│  6. 存储 achieved level: peerLevels[fingerprint] = level        │
│  7. Explicit 模式: 未达要求 → 返回 error（拒绝握手）             │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

### Gold 完整验证流程

```
┌─────────────────────────────────────────────────────────────────┐
│                    VerifyGold(ctx, fqdn, cert, cfg)             │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  Step 1: DNS Discovery                                          │
│     _ati.{host} TXT → agentId                                  │
│     失败 → ANS-1001 HARD                                       │
│                                                                 │
│  Step 2: TL Response Fetch                                      │
│     GET {TLBaseURL}/tl/agents/{agentId}/logs/latest             │
│     失败 → ANS-3008 SOFT                                       │
│                                                                 │
│  Step 3: Receipt Signature                                      │
│     JCS({merkleRoot, treeSize, timestamp}) → SHA-256 → ECDSA   │
│     失败 → ANS-3001 HARD                                       │
│                                                                 │
│  Step 4: Merkle Inclusion Proof                                 │
│     JCS(EventPayload) → leaf hash → RFC 6962 walk → root       │
│     失败 → ANS-3002 HARD                                       │
│                                                                 │
│  Step 5: Producer Signature                                     │
│     JCS(EventPayload) → SHA-256 → ECDSA（Producer key by Kid） │
│     失败 → ANS-3003 HARD（仅在 ProducerKeys 配置时执行）        │
│                                                                 │
│  Step 6: Fingerprint Match                                      │
│     peer cert SHA-256 vs TL identity/server cert fingerprint    │
│     失败 → ANS-3004 HARD                                       │
│                                                                 │
│  Step 7: Status Check                                           │
│     REVOKED → ANS-3005 HARD                                    │
│     EXPIRED → ANS-3006 HARD                                    │
│     WARNING → 通过 + Warning                                    │
│     DEPRECATED → 通过 + Warning                                 │
│     ACTIVE → 通过                                                │
│                                                                 │
│  Step 8: Trust Assessment                                       │
│     ComputeTrustIndex(params) → (score, level)                  │
│     返回: VerificationResult                                    │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

---

## Implementation Checklist

| # | Feature | Status | Files |
|---|---------|--------|-------|
| 1 | Three-layer TL Response model | ✅ | `models/tl_log.go` |
| 2 | TLAgentStatus (5 states) | ✅ | `models/tl_log.go` |
| 3 | Unified error code system (22 codes) | ✅ | `verify/error_codes.go` |
| 4 | TrustPolicy configuration | ✅ | `verify/trust_policy.go` |
| 5 | Trust Index computation (12 signals) | ✅ | `verify/trust_index.go` |
| 6 | Producer signature verification | ✅ | `verify/producer.go` |
| 7 | Unified VerificationResult | ✅ | `verify/verification_result.go` |
| 8 | Receipt signature (seal) | ✅ | `verify/seal.go` |
| 9 | Merkle inclusion proof (RFC 6962) | ✅ | `verify/merkle.go` |
| 10 | Gold verification pipeline | ✅ | `verify/gold.go` |
| 11 | Certificate validity check | ✅ | `verify/cert.go` |
| 12 | Agent Card verification | ✅ | `verify/agent_card.go` |
| 13 | Stapling credential | ✅ | `verify/stapling.go` |
| 14 | Session monitor | ✅ | `verify/session_monitor.go` |
| 15 | Parallel DNS discovery | ✅ | `verify/parallel.go` |
| 16 | HTTPS/SVCB records | ✅ | `verify/svcb.go` |
| 17 | Offline verification | ✅ | `verify/offline.go` |
| 18 | JWS Detached signatures | ✅ | `verify/jws_detached.go` |
| 19 | OCSP dual-channel | ✅ | `verify/ocsp.go` |
| 20 | VerifyConnection (Server) | ✅ | `ati/server.go` |
| 21 | VerifyConnection (Client) | ✅ | `ati/mtls_client.go` |
| 22 | ConnectRequest | ✅ | `ati/connect.go` |
| 23 | Options expansion (19 options) | ✅ | `verify/options.go` |
| 24 | Diagnose (9 steps) | ✅ | `ati/diagnose.go` |
| 25 | Trust Card | ✅ | `ati/trust_card.go` |
| 26 | JCS canonicalization | ✅ | `verify/jcs.go` |
| 27 | DNS DANE/TLSA | ✅ | `verify/dane.go` |
| 28 | Badge-based ServerVerifier | ✅ | `verify/verify.go` |
| 29 | Badge-based ClientVerifier | ✅ | `verify/verify.go` |
| 30 | AnsVerifier (unified facade) | ✅ | `verify/verify.go` |
| 31 | SCITT verification path | ✅ | `verify/verify.go` + `verify/scitt/` |
| 32 | Failure policy (Closed/Cache/Open) | ✅ | `verify/verify.go` + `verify/policy.go` |
| 33 | Badge URL validation | ✅ | `verify/url_validator.go` |
| 34 | TL Host rewriting | ✅ | `verify/url_validator.go` |
| 35 | ATI record parsing | ✅ | `verify/ati_record.go` |
| 36 | Public API trust levels (None/PKI/Badge/Full) | ✅ | `ati/trust_level.go` |
| 37 | Auto-detect trust level mode | ✅ | `ati/mtls_client.go`, `ati/server.go` |
| 38 | TrustCard model | ✅ | `models/trust_card.go` |

---

## Test Coverage

| Package | Test Files | Key Test Scenarios |
|---------|-----------|-------------------|
| `verify` | `gold_test.go` | Success, DNS not found, TL fetch error, bad receipt sig, fingerprint mismatch, revoked, deprecated |
| `verify` | `seal_test.go` | Valid signature, wrong key, tampered payload, empty sig, nil response |
| `verify` | `merkle_test.go` | Single leaf, multi-level tree, empty path, invalid proof |
| `verify` | `producer_test.go` | Valid, invalid sig, key not found, empty sig, tampered payload |
| `verify` | `offline_test.go` | Success, empty response, invalid JSON, bad receipt sig, fingerprint mismatch |
| `verify` | `jws_detached_test.go` | Round-trip, tampered payload, wrong key, invalid format, wrong curve |
| `verify` | `trust_index_test.go` | Full trust, minimal, none, level thresholds |
| `verify` | `trust_policy_test.go` | Default policy, high security, ShouldReject |
| `verify` | `verification_result_test.go` | IsSuccess, MeetsTrustLevel, ToError |
| `verify` | `error_codes_test.go` | Construction, Error(), WithCause, WithEvidence, IsHard |
| `verify` | `jcs_test.go` | Canonicalization, Unicode, nested objects |
| `verify` | `ati_record_test.go` | Parsing, required fields, mode validation |
| `ati` | `diagnose_test.go` | All pass, invalid host, DNS error, TL error, no badge, string/JSON output |
| `ati` | `trust_card_test.go` | Success, invalid host, DNS fail, TL errors, invalid JSON, cancelled ctx |
| `ati` | `trust_level_test.go` | ValidForClient, ValidForServer, String, aliases |
| `ati` | `server_test.go` | VerifyConnection present, TLS 1.3, client auth required |
| `ati` | `mtls_client_test.go` | Certificate loading, URI SAN validation, TLS config |

---

## 明确不做

| 项 | 原因 |
|----|------|
| SDK 注册 API | PRD 5.1：控制台注册 |
| CallAgent() 高级 RPC 封装 | SDK 只做传输层 |
| OAuth2 认证逻辑 | 控制台后端调写接口才需要 |
| DNS 写入 / 传播检查 | 控制台/云解析负责 |
| 蚂蚁链锚定 | V3 候选 |
| SDK WithProxy() | Go stdlib HTTPS_PROXY 已支持 |

---

## 已确认决策

| # | 决策 | 来源 |
|---|------|------|
| D1 | Module path = `gitlab.alibaba-inc.com/alibaba-dns/ati-golang-sdk` | 与用户确认 |
| D2 | TL base URL = `https://tl.ansagent.cn:8180/ans/api/v1` | CNNIC 接口文档 v0.3 |
| D3 | TL 查询公开只读，SDK 不需要 OAuth2 | 透明日志设计原则 |
| D4 | SDK 只做安全传输层 | 与用户确认 |
| D5 | TLS 1.3 最低版本 | ANS/ATI Verification Spec |
| D6 | 三层嵌套 TL Response 替代旧 flat model | 与用户确认 |
| D7 | VerifyConnection 替代 VerifyPeerCertificate | TLS 1.3 best practice |
| D8 | JCS (RFC 8785) 规范化 + ECDSA P-256 | ANS/ATI Verification Spec |
| D9 | Merkle proof 使用 hex 编码（非 base64） | 与 CNNIC 接口对齐 |
| D10 | Receipt 签名对象: `{merkleRoot, treeSize, timestamp}` | Spec §7.2 |
| D11 | 三条验证路径并存: Badge + Gold + SCITT | 代码实现确认 |
| D12 | 公开 API 层信任等级: TrustNone/PKI/Badge/Full | 代码实现确认 |
| D13 | Auto-detect 为默认模式（不指定 TrustLevel） | 代码实现确认 |
| D14 | TLAgentStatus 5 种状态（含 WARNING + EXPIRED） | 代码实现确认 |
| D15 | Badge URL 强制域名白名单验证（防 DNS 投毒） | 安全设计 |
| D16 | TL Host 重写为信任锚点 | 安全设计 |
| D17 | Failure Policy 不适用于 SCITT 验证失败 | 防伪造接受 |
