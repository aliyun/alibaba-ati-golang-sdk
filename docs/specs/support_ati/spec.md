# ATI Golang SDK 技术规格文档

v2.0 | 2026-06-09 | 基于 PRD V2.0 + CNNIC 接口文档 v0.3 + ANS/ATI Verification Spec

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

    // SDK 提供安全传输层（mTLS + DNS 发现 + Gold 验证）
    resp, _ := client.Post(ctx, "https://translate.example.com/mcp",
        map[string]any{"method": "translate", "params": map[string]string{"text": "Hello"}})

    // resp.VerificationResult 包含完整验证结果（TrustLevel + TrustIndex + 各项检查状态）
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
- **Gold 默认** — 完整五阶段验证（DNS + Receipt + Merkle + Producer Sig + Fingerprint）
- **TLS 1.3 最低版本** — 所有 mTLS 连接强制 TLS 1.3
- **开发者体验优先** — 每个决策回答"对调 SDK 的开发者意味着什么"
- **API 表面最小化** — 公开 ~15 个方法（Client 端 + Server 端），注册相关方法收入 internal
- **SDK 不需要 OAuth2** — OAuth2 是控制台后端调 CNNIC 写接口用的；SDK 只调公开只读的 TL 查询接口和 DNS

---

## 架构概览

### 五阶段验证管道

```
Stage 1: DNS Discovery (Parallel)
    ├── _ati TXT → ATI Record (id, ra, version, mode)
    ├── _ati-badge TXT → Badge Record (url, version)
    ├── TLSA → DANE records
    └── HTTPS/SVCB → ALPN, ECH, port

Stage 2: TL Log Fetch
    GET /tl/agents/{agentId}/logs/latest → TLResponse

Stage 3: Cryptographic Verification
    ├── Receipt Signature (ECDSA P-256 over JCS-canonicalized content)
    ├── Merkle Inclusion Proof (RFC 6962)
    └── Producer Signature (ECDSA P-256 over JCS-canonicalized payload)

Stage 4: Identity Binding
    ├── Certificate Fingerprint Match (SHA-256)
    ├── Agent Status Check (ACTIVE/REVOKED/DEPRECATED)
    └── Agent Card Verification (optional)

Stage 5: Trust Assessment
    ├── Trust Index Computation (0-100)
    ├── Trust Level Assignment (NONE/BASIC/VERIFIED/HIGH)
    └── Revocation Status (OCSP dual-channel)
```

### 三层嵌套 TL Response 模型

```
TLResponse
├── Status: "ACTIVE" | "REVOKED" | "DEPRECATED"
├── Receipt (TL 签发的 inclusion receipt)
│   ├── Alg: "ES256"
│   ├── Kid: key identifier
│   ├── Issuer: TL service name
│   ├── MerkleRoot: hex-encoded SHA-256
│   ├── TreeSize: int64
│   ├── InclusionProof: {LeafIndex, AuditPath}
│   ├── Timestamp: time.Time
│   └── Signature: base64(ASN1 DER ECDSA)
├── Envelope (Producer/RA 签名信封)
│   ├── Alg: "ES256"
│   ├── Kid: producer key identifier
│   ├── Producer: RA identifier (e.g. "aliyun")
│   └── Signature: base64(ASN1 DER ECDSA)
└── Payload (EventPayload)
    ├── AnsID: agent identifier
    ├── AnsName: "ati://agent.example.com"
    ├── EventType: "attestation"
    ├── Agent: {Host, Name, Version, ProviderID}
    ├── Attestations:
    │   ├── IdentityCert: {Fingerprint, Type}
    │   ├── ServerCert: {Fingerprint, Type}
    │   ├── TrustCard: {CapabilitiesHash, HashAlg, Canonicalization, TrustCardUrl}
    │   ├── SchemaHashes: []string
    │   ├── DNSRecordsProvisioned: bool
    │   └── DomainValidation: {Method, Timestamp}
    ├── IssuedAt: time.Time
    └── ExpiresAt: time.Time
```

---

## 外部依赖与通信接口

### Go Module 直接依赖

| 依赖 | 用途 | 状态 |
|------|------|------|
| `github.com/miekg/dns` | DNS 查询（TXT / TLSA / HTTPS SVCB / DNSSEC） | 保留 |
| `github.com/fxamacker/cbor/v2` | COSE/CBOR 解析（Agent Card COSE_Sign1） | 保留 |
| `golang.org/x/sync` | errgroup（并行 DNS 查询） | 新增（direct） |
| `golang.org/x/crypto` | OCSP 验证 | 新增（direct） |

### SDK 需要通信的外部服务

| 接口 | 通信对象 | 地址 | 协议 | 认证方式 | SDK 使用场景 |
|------|---------|------|------|---------|-------------|
| CNNIC TL 查询 | CNNIC 透明日志服务 | `https://tl.ansagent.cn:8180/ans/api/v1` | HTTPS | 无（公开只读） | Gold 验证：获取 TL 日志 + Receipt |
| Agent-to-Agent | 目标 Agent 端点 | 动态（按 host） | **mTLS**（TLS 1.3） | Identity Certificate | 核心通信 |
| DNS 递归解析器 | DNS 服务 | `8.8.8.8:53`（可配置） | UDP/TCP | 无（DNSSEC 验证） | _ati / _ati-badge / TLSA / HTTPS 查询 |
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
func VerifyReceiptSignature(resp *models.TLResponse, tlPublicKey *ecdsa.PublicKey) error
```

### 模块二：Merkle Inclusion Proof 验证

验证 EventPayload 确实被包含在 Merkle tree 中。

**算法流程**：
1. JCS 规范化 EventPayload → 计算 leaf hash: `SHA-256(0x00 || canonical_payload)`
2. 从 InclusionProof.AuditPath 按 RFC 6962 算法重建 root hash
3. 比对计算出的 root hash == Receipt.MerkleRoot

```go
func VerifyInclusionProof(resp *models.TLResponse) error
```

**Merkle 节点哈希规则**（RFC 6962）：
- Leaf: `H(0x00 || data)`
- Internal: `H(0x01 || left || right)`
- Audit path 中的哈希值为 hex 编码

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

绑定 TL 记录到 TLS 连接中实际出示的证书。

```go
type CertIdentity struct {
    Fingerprint CertFingerprint  // SHA-256 of DER-encoded certificate
}

type CertFingerprint struct {
    hash [32]byte
}

func CertFingerprintFromDER(der []byte) CertFingerprint
func CertFingerprintFromX509(cert *x509.Certificate) CertFingerprint
```

**验证规则**：
- `TLResponse.Payload.Attestations.IdentityCert.Fingerprint` == `SHA256:<hex>` 格式
- 与 TLS 握手中实际证书的 SHA-256 指纹比对

### 模块五：Agent Status 检查

```go
const (
    StatusActive     = "ACTIVE"      // 验证通过
    StatusRevoked    = "REVOKED"     // 硬失败
    StatusDeprecated = "DEPRECATED"  // 软警告（仍可通过）
)
```

- ACTIVE → 通过
- REVOKED → 失败（ANS-4002）
- DEPRECATED → 通过，附加 Warning

---

## Trust 评估系统

### Trust Level（输出等级）

```go
type TrustLevel string

const (
    TrustLevelNone     TrustLevel = "NONE"     // 验证失败
    TrustLevelBasic    TrustLevel = "BASIC"     // 仅 DNS 发现通过
    TrustLevelVerified TrustLevel = "VERIFIED"  // Receipt + Merkle 通过
    TrustLevelHigh     TrustLevel = "HIGH"      // 全部验证通过（含 Producer + Agent Card）
)
```

### Trust Index（0-100 分）

```go
type TrustIndexParams struct {
    ReceiptVerified  bool
    MerkleVerified   bool
    ProducerVerified bool
    FingerprintMatch bool
    DNSSECValid      bool
    AgentCardValid   bool
    StatusActive     bool
    ClaimsVerified   int
    TotalClaims      int
}

func ComputeTrustIndex(params TrustIndexParams) (int, TrustLevel)
```

**计分规则**：
- Receipt Verified: +25
- Merkle Verified: +20
- Producer Signature: +15
- Fingerprint Match: +15
- DNSSEC Valid: +10
- Agent Card Valid: +10
- Status Active: +5
- Claims Bonus: `(verified/total) * 10` (最多 +10 if AgentCard present)
- Failure Penalty: 任一核心验证失败 → TrustLevel = NONE

**Level 映射**：
- 0-19 → NONE
- 20-49 → BASIC
- 50-79 → VERIFIED
- 80-100 → HIGH

---

## Trust Policy 配置

```go
type TrustPolicy struct {
    DNSSECMode       FailureAction  // REQUIRE / DEGRADE
    TLUnreachable    FailureAction  // FAIL / DEGRADE
    CapHashMismatch  FailureAction  // FAIL / DEGRADE
    StaplingRequired bool
    MinTrustLevel    TrustLevel
    OfflineMode      bool
    LongConnRecheckInterval time.Duration
}

type FailureAction string
const (
    FailureActionFail    FailureAction = "FAIL"
    FailureActionDegrade FailureAction = "DEGRADE"
)

func DefaultTrustPolicy() *TrustPolicy
func HighSecurityTrustPolicy() *TrustPolicy
```

**DefaultTrustPolicy**:
- DNSSECMode: DEGRADE
- TLUnreachable: DEGRADE
- MinTrustLevel: BASIC
- LongConnRecheckInterval: 5m

**HighSecurityTrustPolicy**:
- DNSSECMode: FAIL
- TLUnreachable: FAIL
- StaplingRequired: true
- MinTrustLevel: VERIFIED
- LongConnRecheckInterval: 1m

---

## DNS Discovery（并行）

### Parallel Discovery

```go
type DiscoveryResult struct {
    ATIRecords      []*ATIRecord
    BadgeRecords    []ATIBadgeRecord
    TLSARecords     []*TLSARecord
    SVCBResult      *SVCBResult
    AgentCardURL    string
    TLQueryURL      string
    SelectedVersion *models.Version
    DNSSECStatus    string
}

func ParallelDiscovery(ctx context.Context, fqdn models.Fqdn, resolver DNSResolver) (*DiscoveryResult, error)
```

使用 `errgroup` 并行查询：
- `_ati.{host}` TXT → ATI Records
- `_ati-badge.{host}` TXT → Badge Records
- `_443._tcp.{host}` TLSA → DANE records
- `{host}` HTTPS/SVCB → ALPN, ECH, port

### _ati TXT Record

```
_ati.{host} TXT "v=ati1; id={agentId}; ra=aliyun; version=v1.0.0; mode=direct"
```

| 字段 | 说明 | 必需 |
|------|------|------|
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

### VerifyConnection Callback（TLS 1.3）

Server 和 Client 端均使用 `tls.Config.VerifyConnection` callback（替代旧的 `VerifyPeerCertificate`），在 TLS 握手期间执行完整验证。

**Server 端**（`ati/server.go`）：
```go
func NewServerTLSConfig(opts ...ServerOption) (*tls.Config, error)
```
- TLS 1.3 minimum
- ClientAuth: RequireAndVerifyClientCert
- VerifyConnection callback: DANE → SAN URI → Gold TL → 硬拒绝

**Client 端**（`ati/mtls_client.go`）：
```go
func NewAgentClient(opts ...AgentClientOption) (*AgentClient, error)
```
- VerifyConnection callback: Bronze/Silver/Gold 检查
- 证书有效期警告

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

## Agent Card 验证

### 验证管道

```go
type AgentCardVerifier struct {
    producerKeys ProducerKeyLookup
    httpFetcher  HTTPFetcher
}

type AgentCardResult struct {
    SignatureValid    bool
    CapHashValid     bool
    SchemaHashValid  bool
    ClaimsVerified   int
    TotalClaims      int
    TrustIndex       int
    TrustLevel       TrustLevel
}

func (v *AgentCardVerifier) VerifyAgentCard(ctx context.Context, card *models.TrustCard, attestations models.EventAttestations) (*AgentCardResult, error)
```

**验证步骤**：
1. COSE_Sign1 签名验证
2. capabilitiesHash 完整性: JCS(trust content) → SHA-256 → 比对
3. Schema hash: fetch metadataUrl → SHA-256 → 比对 attestations.schemaHashes
4. verifiableClaims: 逐项验证第三方签名
5. 计算 Trust Index

### Stapling（短期状态凭证）

```go
type StapledCredential struct {
    AnsID     string
    Status    string
    IssuedAt  time.Time
    ExpiresAt time.Time
    Signature []byte
}

func VerifyStapledCredential(cred *StapledCredential, keys ProducerKeyLookup, now time.Time) error
func ParseStapledCredential(raw []byte) (*StapledCredential, error)
```

- 在 VerifyConnection 中优先检查 Stapled Credential
- 过期或缺失时 fallback 到 TL 查询

---

## Session Monitor（长连接周期性重验证）

```go
type SessionMonitor struct {
    interval    time.Duration
    tlogClient  TransparencyLogClient
    dnsResolver DNSResolver
    onRevoked   func(fqdn string)
}

func NewSessionMonitor(interval time.Duration, tlogClient TransparencyLogClient, dnsResolver DNSResolver, onRevoked func(string)) *SessionMonitor
func (m *SessionMonitor) Watch(ctx context.Context, fqdn models.Fqdn, cert *CertIdentity) func()
func (m *SessionMonitor) Stop()
```

**行为**：
- 周期性重新查询 TL 状态
- 如果状态变为 REVOKED/EXPIRED → 调用 onRevoked 回调
- 通过 TrustPolicy.LongConnRecheckInterval 配置间隔

---

## Offline Verification（离线模式）

```go
type OfflineVerifier struct {
    tlPublicKey  *ecdsa.PublicKey
    producerKeys ProducerKeyLookup
}

func NewOfflineVerifier(tlKey *ecdsa.PublicKey, producerKeys ProducerKeyLookup) *OfflineVerifier
func (v *OfflineVerifier) VerifyOffline(ctx context.Context, embeddedStatement []byte, cert *CertIdentity) (*VerificationResult, error)
```

**验证流程**（无网络访问）：
1. 解析 JSON → `*models.TLResponse`
2. 验证 Receipt 签名（使用预置 TL 公钥）
3. 验证 Merkle Inclusion Proof
4. 验证 Producer 签名（如配置了 ProducerKeys）
5. 证书指纹匹配

**限制**：
- RevocationStatusUnknown 标记（无法查询实时状态）
- 结果附加 Warning: "revocation status unknown (offline mode)"

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

## ConnectRequest + Version Policy

### Connect API

```go
type ConnectRequest struct {
    Target        string
    VersionPolicy VersionPolicy
    TrustPolicy   *TrustPolicy
}

type ConnectResult struct {
    *VerificationResult
    AgentID string
    Version *models.Version
}

func (c *AgentClient) Connect(ctx context.Context, req *ConnectRequest) (*ConnectResult, error)
```

### Version Policy

```go
type VersionPolicy string
const (
    VersionPolicyExact            VersionPolicy = "EXACT"
    VersionPolicyLatest           VersionPolicy = "LATEST"
    VersionPolicyLatestCompatible VersionPolicy = "LATEST_COMPATIBLE"
)

func ResolveVersion(records []*ATIRecord, policy VersionPolicy, requested string) (*ATIRecord, error)
```

- EXACT: 精确匹配指定版本
- LATEST: 选择最高 semver 版本
- LATEST_COMPATIBLE: 同 major 版本内选最高

---

## Error Code System

### ANSError 结构体

```go
type ANSError struct {
    Code     string        // "ANS-1001"
    Severity Severity      // HARD / SOFT
    Stage    int           // 1-5
    Message  string
    Evidence string        // 锚定证据
    Cause    error         // 底层错误
}

type Severity string
const (
    SeverityHard Severity = "HARD"  // 验证失败，不可降级
    SeveritySoft Severity = "SOFT"  // 可按 TrustPolicy 降级
)
```

### 错误码清单

| Code | Stage | Severity | 含义 |
|------|-------|----------|------|
| ANS-1001 | 1 | HARD | DNS discovery: no _ati records |
| ANS-1002 | 1 | SOFT | DNSSEC validation failed (bogus) |
| ANS-1003 | 1 | SOFT | DNSSEC insecure (unsigned zone) |
| ANS-2001 | 2 | SOFT | TL service unreachable |
| ANS-2002 | 2 | HARD | TL response invalid/malformed |
| ANS-3001 | 3 | HARD | Receipt signature verification failed |
| ANS-3002 | 3 | HARD | Merkle inclusion proof invalid |
| ANS-3003 | 3 | SOFT | Producer signature verification failed |
| ANS-4001 | 4 | HARD | Certificate fingerprint mismatch |
| ANS-4002 | 4 | HARD | Agent status REVOKED |
| ANS-4003 | 4 | SOFT | Agent status DEPRECATED |
| ANS-5001 | 5 | SOFT | Agent Card hash mismatch |
| ANS-5002 | 5 | SOFT | Trust level below policy minimum |

---

## Unified Verification Result

```go
type VerificationResult struct {
    AnsName          string
    Connected        bool
    TrustLevel       TrustLevel
    TrustIndex       int
    IdentityVerified bool
    TLVerified       bool
    AgentCardResult  *AgentCardResult
    DNSSECStatus     string
    Status           string
    Warnings         []string
    Error            *ANSError
}

func (r *VerificationResult) IsSuccess() bool
func (r *VerificationResult) MeetsTrustLevel(min TrustLevel) bool
func (r *VerificationResult) ToError() error
```

---

## Gold Verification Pipeline（完整流程）

```go
type GoldVerifierConfig struct {
    TLBaseURL    string
    TLPublicKey  *ecdsa.PublicKey
    DNSResolver  DNSResolver
    TLogClient   TransparencyLogClient
    ProducerKeys ProducerKeyLookup
}

func VerifyGold(ctx context.Context, fqdn models.Fqdn, cert *CertIdentity, cfg *GoldVerifierConfig) *VerificationResult
```

**完整流程**：
1. DNS Discovery → 获取 Agent ID
2. Fetch TL Log → `GET /tl/agents/{agentId}/logs/latest`
3. Verify Receipt Signature（TL 公钥）
4. Verify Merkle Inclusion Proof（RFC 6962）
5. Verify Producer Signature（RA 公钥，可选）
6. Certificate Fingerprint Match
7. Status Check（ACTIVE/REVOKED/DEPRECATED）
8. Compute Trust Index → Assign Trust Level

---

## Verifier Configuration（功能选项）

```go
type verifierConfig struct {
    // Core
    tlBaseURL    string
    tlPublicKey  *ecdsa.PublicKey
    dnsResolver  DNSResolver
    tlogClient   TransparencyLogClient
    
    // Extended
    trustPolicy       *TrustPolicy
    producerKeys      ProducerKeyLookup
    agentCardVerifier *AgentCardVerifier
    sessionMonitor    *SessionMonitor
    ocspChecker       *OCSPChecker
    parallelFetch     bool
    offlineMode       bool
}

// Option functions
func WithTrustPolicy(tp *TrustPolicy) Option
func WithProducerKeys(keys ProducerKeyLookup) Option
func WithAgentCardVerifier(v *AgentCardVerifier) Option
func WithSessionMonitor(m *SessionMonitor) Option
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
2. 调用 TL 接口: `GET /tl/agents/{agentId}/logs/latest`
3. 从 TLResponse.Payload 提取 Trust Card 信息

### Trust Card 结构体

```go
type TrustCard struct {
    AgentID          string
    AgentName        string              // ati://agent.example.com
    AgentDisplayName string
    AgentDescription string
    Version          string
    AgentHost        string
    Endpoints        []TrustCardEndpoint
    Capabilities     []string
    VerifiableClaims []VerifiableClaim
}
```

---

## 诊断

```go
func Diagnose(ctx context.Context, host string, opts ...DiagnoseOption) (*DiagnoseResult, error)
```

**9 步诊断**：
1. Host Validation
2. DNS Discovery (_ati TXT)
3. Badge Record (_ati-badge TXT)
4. TL Log Fetch
5. Receipt Signature Verification
6. Merkle Inclusion Proof
7. Producer Signature Verification
8. Agent Card Verification
9. Stapling Check

**输出格式**：
```go
type DiagnoseResult struct {
    Host      string
    Timestamp string
    Steps     []DiagnoseStep
    Summary   string  // "ALL PASS" / "PARTIAL FAIL" / "FAIL (reason)"
}

func (r *DiagnoseResult) String() string  // 人类可读
func (r *DiagnoseResult) JSON() string    // 结构化
```

---

## 公开 API 清单

| API | 角色 | 说明 |
|-----|------|------|
| `NewAgentClient(opts...)` | Client | 创建客户端 |
| `WithMTLSCerts(identity, key, server, ca)` | Client | 证书配置 |
| `AgentClient.Connect(ctx, req)` | Client | Spec-aligned 完整验证连接 |
| `AgentClient.Get/Post/Put/Delete/Do` | Client | HTTP 方法（内置验证） |
| `NewServerTLSConfig(opts...)` | Server | Server 端 TLS 配置 |
| `PeerATIName(tlsState)` | Server | 提取对方 ATI 身份 |
| `GetTrustCard(ctx, host, version)` | 通用 | 获取 Trust Card |
| `Diagnose(ctx, host, opts...)` | 通用 | 诊断 |
| `verify.VerifyGold(ctx, fqdn, cert, cfg)` | 验证 | Gold 完整验证 |
| `verify.NewOfflineVerifier(key, keys)` | 验证 | 离线验证器 |
| `verify.VerifyJWSDetached(sig, payload, keys)` | 验证 | JWS Detached 验证 |
| `verify.CreateJWSDetached(payload, key, kid)` | 签名 | JWS Detached 创建 |
| `verify.NewSessionMonitor(...)` | 监控 | 长连接重验证 |
| `verify.ParallelDiscovery(ctx, fqdn, resolver)` | 发现 | 并行 DNS 查询 |
| `verify.ComputeTrustIndex(params)` | 评估 | Trust 评分 |

---

## Implementation Checklist

| # | Feature | Status | Files |
|---|---------|--------|-------|
| 1 | Three-layer TL Response model | ✅ | `models/tl_log.go` |
| 2 | Unified error code system | ✅ | `verify/error_codes.go` |
| 3 | TrustPolicy configuration | ✅ | `verify/trust_policy.go` |
| 4 | Trust Index computation | ✅ | `verify/trust_index.go` |
| 5 | Producer signature verification | ✅ | `verify/producer.go` |
| 6 | Unified VerificationResult | ✅ | `verify/verification_result.go` |
| 7 | Receipt signature (seal) | ✅ | `verify/seal.go` |
| 8 | Merkle inclusion proof (RFC 6962) | ✅ | `verify/merkle.go` |
| 9 | Gold verification pipeline | ✅ | `verify/gold.go` |
| 10 | Certificate validity check | ✅ | `verify/cert.go` |
| 11 | Agent Card verification | ✅ | `verify/agent_card.go` |
| 12 | Stapling credential | ✅ | `verify/stapling.go` |
| 13 | Session monitor | ✅ | `verify/session_monitor.go` |
| 14 | Parallel DNS discovery | ✅ | `verify/parallel.go` |
| 15 | HTTPS/SVCB records | ✅ | `verify/svcb.go` |
| 16 | Offline verification | ✅ | `verify/offline.go` |
| 17 | JWS Detached signatures | ✅ | `verify/jws_detached.go` |
| 18 | OCSP dual-channel | ✅ | `verify/ocsp.go` |
| 19 | VerifyConnection (Server) | ✅ | `ati/server.go` |
| 20 | VerifyConnection (Client) | ✅ | `ati/mtls_client.go` |
| 21 | ConnectRequest + VersionPolicy | ✅ | `ati/connect.go`, `ati/version_policy.go` |
| 22 | Options expansion | ✅ | `verify/options.go` |
| 23 | Diagnose (9 steps) | ✅ | `ati/diagnose.go` |
| 24 | Trust Card | ✅ | `ati/trust_card.go` |
| 25 | JCS canonicalization | ✅ | `verify/jcs.go` |
| 26 | DNS DANE/TLSA | ✅ | `verify/dane.go` |

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
| `ati` | `diagnose_test.go` | All pass, invalid host, DNS error, TL error, no badge, string/JSON output |
| `ati` | `trust_card_test.go` | Success, invalid host, DNS fail, TL errors, invalid JSON, cancelled ctx |
| `ati` | `server_test.go` | VerifyConnection present, TLS 1.3, client auth required |

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
