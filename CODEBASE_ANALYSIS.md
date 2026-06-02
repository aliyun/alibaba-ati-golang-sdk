# ATI SDK Go — 代码库深度分析文档

## 1. 项目概览

**模块名**: `gitlab.alibaba-inc.com/alibaba-dns/ati-golang-sdk`
**Go 版本**: 1.25.0
**定位**: 阿里云 Agent Trust Infrastructure (ATI) 的 Go SDK，为 AI Agent 提供 mTLS 安全通信、多级信任验证（Bronze/Silver/Gold）、CNNIC 透明日志集成和诊断工具。

### 核心依赖

| 依赖 | 用途 |
|------|------|
| `miekg/dns` | DNS 查询（TXT / TLSA 记录、DNSSEC） |
| `spf13/cobra` + `spf13/viper` | CLI 命令框架 + 配置管理 |
| `fxamacker/cbor/v2` | CBOR 编解码（SCITT 兼容层） |

---

## 2. 整体架构

```
┌─────────────────────────────────────────────────────────────┐
│                     cmd/ati-cli                             │
│  (CLI 入口, cobra commands, viper config)                   │
└───────────────┬──────────────────────┬──────────────────────┘
                │                      │
    ┌───────────▼──────────┐  ┌────────▼──────────────┐
    │      ati/            │  │      verify/           │
    │  ┌─────────────┐     │  │  ┌─────────────────┐   │
    │  │AgentClient  │     │  │  │ ServerVerifier   │   │
    │  │ (mTLS +     │     │  │  │ ClientVerifier   │   │
    │  │  Bronze/    │     │  │  │ AnsVerifier      │   │
    │  │  Silver/    │     │  │  ├─────────────────┤   │
    │  │  Gold)      │     │  │  │ Badge Verify     │   │
    │  ├─────────────┤     │  │  │ Gold Verify      │   │
    │  │ServerTLS    │     │  │  │ DANE Verify      │   │
    │  │ Config      │─────┼──┤  │ Seal Verify      │   │
    │  ├─────────────┤     │  │  │ Merkle Verify    │   │
    │  │TrustCard    │     │  │  │ JCS Canonical    │   │
    │  ├─────────────┤     │  │  │ DNS Resolver     │   │
    │  │Diagnose     │     │  │  │ TLog Client      │   │
    │  └─────────────┘     │  │  │ Badge Cache      │   │
    └──────────────────────┘  │  └─────────────────┘   │
                              │  ┌─────────────────┐   │
    ┌──────────────────────┐  │  │ verify/scitt/    │   │
    │ internal/registry/   │  │  │  COSE_Sign1      │   │
    │  ┌─────────────┐     │  │  │  Receipt         │   │
    │  │ Client      │     │  │  │  StatusToken     │   │
    │  │ (RA API)    │     │  │  │  Root Keys       │   │
    │  ├─────────────┤     │  │  └─────────────────┘   │
    │  │Transparency │     │  └────────────────────────┘
    │  │ Client      │     │
    │  └─────────────┘     │
    └──────────────────────┘
    ┌──────────────────────┐  ┌────────────────────────┐
    │   models/            │  │  internal/httputility/ │
    │  (所有数据结构)       │  │  (HTTP 请求工具)       │
    └──────────────────────┘  └────────────────────────┘
    ┌──────────────────────┐
    │   keygen/            │
    │  (RSA/EC 密钥生成)    │
    └──────────────────────┘
```

---

## 3. 包级详细分析

### 3.1 `ati/` — 公共 SDK API 层

这是 SDK 的主要入口包，提供面向用户的高层 API。

#### 3.1.1 `AgentClient` — mTLS 客户端（`mtls_client.go`）

```go
AgentClient {
    httpClient   *http.Client
    tlsConfig    *tls.Config
    trustLevel   TrustLevel       // Bronze / Silver / Gold
    identityCert tls.Certificate
    caCertPool   *x509.CertPool
    certExpiry   time.Time
    dnsResolver  verify.DNSResolver
    daneResolver verify.DANEResolver    // Silver 级别 DANE 验证
    tlogClient   verify.TransparencyLogClient  // Gold 级别 TL 查询
    tlPublicKey  *ecdsa.PublicKey       // Gold 级别密封验证公钥
}
```

**Options 模式**:
```go
NewAgentClient(
    WithMTLSCerts(identityCert, privateKey, serverCert, caBundle),
    WithTrustLevel(ati.Gold),
    WithClientTimeout(30*time.Second),
    WithDNSResolver(resolver),
    WithAgentDANEResolver(daneResolver),
    WithTLogClient(tlogClient),
    WithTLPublicKey(key),
)
```

**请求生命周期** (`Do` 方法):

```
1. URL 解析 & 校验 (必须 HTTPS)
       │
2. Bronze 验证:
   a) DNS 发现 — 查询 _ati TXT 记录（阻塞检查）
      ├── 未找到 → 返回 error（目标不是 ATI Agent）
      └── 找到 → 记录 AgentID
   b) 构建 HTTP 请求, 发送（mTLS 握手）
   c) 验证对端证书:
      ├── CA 链有效（TLS 握手已验证）
      ├── URI SAN 中 ati:// 前缀
      └── SAN 主机名匹配
       │
3. Silver 验证（可选）:
   └── DANE/TLSA 验证 → 拒绝则返回 error
       │
4. Gold 验证（可选）:
   └── verify.VerifyGold() → 密封 + Merkle + 指纹 + 状态
       ├── 失败 → 返回 error
       └── 成功 → 标记 SealVerified + MerkleVerified
       │
5. 返回 Response + BronzeOutcome
```

**验证结果**:
```go
BronzeOutcome {
    DNSDiscovered  bool      // _ati TXT 发现
    CAChainValid   bool      // CA 链有效
    SANMatches     bool      // URI SAN 匹配
    AgentID        string    // Agent ID
    PeerATIName    string    // 对端 ATI Name
    DANEVerified   bool      // Silver: DANE 通过
    SealVerified   bool      // Gold: 密封验证通过
    MerkleVerified bool      // Gold: Merkle 证明通过
    TrustLevel     TrustLevel // 达到的信任等级
}
```

**便捷方法**: `Get/Post/Put/Delete`, `Prefetch`, `CertStatus`

#### 3.1.2 `ServerTLSConfig` — 服务端 TLS（`server.go`）

```go
NewServerTLSConfig(
    WithServerCert(certFile, keyFile),
    WithClientCA(caBundleFile),
    WithClientVerifier(ati.Bronze), // 客户端验证等级
)
```

通过 `VerifyPeerCertificate` 回调自动验证客户端证书：
- **Bronze**: 验证 `ati://` URI SAN 存在
- **Silver**: Bronze + DANE 验证
- **Gold**: Silver + `verify.VerifyGold()` 全链路验证

`PeerATIName(tls.ConnectionState)` 从 TLS 连接中提取对端 Agent 身份。

#### 3.1.3 `TrustCard` — Trust Card 查询（`trust_card.go`）

```go
GetTrustCard(ctx, host, version, opts...) → *models.TrustCard
```

流程：
1. 查询 `_ati` TXT 获取 agentId
2. 请求 CNNIC TL: `GET {tlBaseURL}/tl/agents/{agentId}/logs/latest`
3. 解析 TL 响应，提取 TrustCard 元数据

#### 3.1.4 `Diagnose` — 诊断工具（`diagnose.go`）

```go
Diagnose(ctx, host, opts...) → *DiagnoseResult
```

运行 7 步诊断链：
1. Host 校验（FQDN 格式）
2. DNS 发现（`_ati` TXT）
3. DNS Badge 查找（`_ati-badge` TXT，非致命）
4. TL 日志获取
5. 密封验证（JCS + ECDSA）
6. Merkle 证明验证
7. 证书指纹检查

输出格式：
- `result.String()` — 人类可读报告
- `result.JSON()` — 结构化 JSON

#### 3.1.5 `TrustLevel` — 信任等级（`trust_level.go`）

```go
const (
    Bronze TrustLevel = iota  // DNS 发现 + PKI
    Silver                     // + DANE/TLSA
    Gold                       // + TL 密封 + Merkle 证明
)
```

---

### 3.2 `verify/` — 验证引擎（核心）

#### 3.2.1 `CertIdentity` & `CertFingerprint` — 证书抽象（`cert.go`）

```go
CertFingerprint { bytes [32]byte }  // SHA-256
  - FromDER(der) / FromBytes([32]byte)
  - Parse("SHA256:<hex>") 或 Parse("SHA-256:<hex>")
  - Matches(other string) bool
  - String() → "SHA256:<hex>"

CertIdentity {
    CommonName  *string
    DNSSANs     []string
    URISANs     []string
    Fingerprint CertFingerprint
}
  - FQDN() → 优先 DNS SAN，回退 CN
  - AtiName() → 从 URI SAN 提取 ati:// 名称
  - Version() → 从 ATI name 提取版本

ATIName { Version, Host, raw }
  - 格式: "ati://v<major>.<minor>.<patch>.<fqdn>"
```

#### 3.2.2 Badge DNS 解析流程（`dns.go`, `dns_resolver.go`）

```
StandardDNSResolver (net.Resolver, timeout=10s)
    │
    ├── LookupATIBadge(fqdn)
    │     1. 查询 "_ati-badge.<fqdn>" TXT 记录
    │     2. 解析失败(SERVFAIL/超时) → 返回 hard error (不回退)
    │     3. NXDOMAIN → 回退查询 "_ra-badge.<fqdn>" (legacy)
    │     4. 解析 TXT → ParseATIBadgeRecord()
    │
    ├── LookupATIDiscovery(fqdn)
    │     → 查询 "_ati.<fqdn>" TXT 记录
    │     → 返回 ATIDiscoveryResult { Found, Records[]*ATIRecord }
    │
    ├── FindPreferredBadge(fqdn)
    │     → 获取所有记录，按版本降序排序，返回最新
    │
    └── FindBadgeForVersion(fqdn, version)
          → 精确匹配 → 无版本记录回退

ATIBadgeRecord 格式: "v=ati-badge1; version=v1.0.0; url=https://..."
ATIRecord { ID, RA, Version, Mode }
```

#### 3.2.3 Gold 验证（`gold.go`）

```go
GoldVerifierConfig {
    TLBaseURL   string            // 默认 "https://tl.ansagent.cn:8180/ans/api/v1"
    TLPublicKey *ecdsa.PublicKey   // 预配置的 CNNIC 公钥
    DNSResolver DNSResolver
    TLogClient  TransparencyLogClient
    Logger      *slog.Logger
}

VerifyGold(ctx, fqdn, cert, cfg) → *VerificationOutcome
```

6 步流程：
1. DNS 发现 — `LookupATIDiscovery` 获取 agentId
2. TL 日志获取 — `FetchTLLog` 请求 CNNIC TL
3. 密封验证 — `VerifySeal` (JCS 规范化 + SHA-256 + ECDSA)
4. Merkle 证明 — `VerifyMerkleProof` (RFC 9162 风格)
5. 指纹匹配 — 证书指纹与 TL 记录比对
6. 状态检查 — ACTIVE/DEPRECATED 允许，REVOKED 拒绝

#### 3.2.4 密封验证（`seal.go` + `jcs.go`）

```go
VerifySeal(tlResp *models.TLLogResponse, trustedKey *ecdsa.PublicKey) error
```

流程：
1. 提取 4 个被密封字段：`status`、`schemaVersion`、`payload`、`evidenceRef`
2. JCS 规范化（RFC 8785）— 键排序、空白移除、ES6 数字格式
3. SHA-256 摘要
4. ECDSA 签名验证（`ecdsa.VerifyASN1`）
5. 公钥来源：优先使用预配置的 `trustedKey`，回退到 `seal.publicKey` PEM

```go
JCSCanonicalize(data []byte) ([]byte, error)
JCSCanonicalizeFields(fields map[string]json.RawMessage) ([]byte, error)
```

#### 3.2.5 Merkle 证明验证（`merkle.go`）

```go
VerifyMerkleProof(proof *models.MerkleProof) error
```

RFC 9162 风格的审计路径遍历：
- 从 leafHash + path 重建根哈希
- 与 rootHash 做 constant-time 比较
- 节点哈希：`SHA-256(left || right)`（无前缀字节）

#### 3.2.6 DANE/TLSA 验证（`dane.go`）

```go
DANEVerifier { resolver DANEResolver }

StandardDANEResolver {
    server  string          // 默认 "8.8.8.8:53"
    timeout time.Duration   // 默认 5s
}

Verify(ctx, fqdn, port, cert) → *DANEOutcome
```

流程：
1. 查询 `_443._tcp.{fqdn}` TLSA 记录
2. 无记录 → Pass（DANE 非强制）
3. DNSSEC 未验证 → Skip
4. Usage=3 (DANE-EE) 记录比对证书指纹
5. 匹配 → DANEVerified / 不匹配 → DANEMismatch (reject)

#### 3.2.7 透明日志客户端（`tlog.go`）

```go
TransparencyLogClient interface {
    FetchBadge(ctx, url) (*Badge, error)
    FetchTLLog(ctx, url) (*models.TLLogResponse, error)
}

HTTPTransparencyLogClient — 1MB 响应限制, JSON 反序列化
```

#### 3.2.8 Badge 缓存（`cache.go`）

```go
BadgeCache {
    entries map[string]*cacheEntry
    mu      sync.RWMutex
    config  CacheConfig { TTL, MaxEntries, BackgroundRefresh }
}
```

#### 3.2.9 Badge 验证器（`verify.go`）

```go
ServerVerifier / ClientVerifier / AnsVerifier (Facade)
```

旧的 badge-based 验证路径，保留兼容。新代码推荐使用 `ati.AgentClient`。

#### 3.2.10 失败策略（`policy.go`）

```go
FailClosed       // DNS/TLog 错误 → 拒绝 (默认)
FailOpenWithCache // 错误 → 尝试 stale cache
FailOpen         // 错误 → 接受 (不推荐)
```

#### 3.2.11 `VerificationOutcome` — 统一验证结果（`outcome.go`）

```go
OutcomeType:
  Verified | NotAtiAgent | InvalidStatus |
  FingerprintMismatch | HostnameMismatch | AtiNameMismatch |
  DNSError | TlogError | CertError | FailOpen |
  URLValidationError | DANERejection | ScittError | GoldError

VerificationTier:
  TierBadgeOnly  // Badge 验证
  TierFullScitt  // SCITT receipt 验证
  TierGold       // Gold (CNNIC TL) 验证
```

---

### 3.3 `verify/scitt/` — SCITT 密码学子系统

SCITT（Supply Chain Integrity, Transparency and Trust）兼容层，保留自 GoDaddy ANS 原始实现。

包含：COSE_Sign1 解析、Receipt 验证、Status Token 验证、RFC 9162 Merkle Tree、C2SP Root Keys 管理。

> 注意：ATI 的 CNNIC 透明日志使用 JSON/JCS/ECDSA 格式（而非 CBOR/COSE），Gold 验证使用 `verify/seal.go` + `verify/merkle.go`。SCITT 子系统保留用于与 GoDaddy ANS 兼容。

---

### 3.4 `models/` — 数据结构层

#### 3.4.1 核心模型

```go
// ATI Name 格式的 FQDN 值对象
Fqdn { value string }
  .AtiBadgeName() → "_ati-badge.<fqdn>"
  .RaBadgeName()  → "_ra-badge.<fqdn>"  (legacy)
  .TlsaName(port) → "_<port>._tcp.<fqdn>"

// 语义化版本
Version { Major, Minor, Patch }

// CNNIC TL 响应
TLLogResponse {
    Status, SchemaVersion string
    Payload       TLPayload        // Agent 元数据
    EvidenceRef   TLEvidenceRef    // 证据引用
    Seal          TLSeal           // 密封签名
    MerkleProof   MerkleProof      // Merkle 包含证明
}

TLPayload {
    AgentID, AgentName, AgentHost, Version, AgentStatus string
    Certificates *TLCertificates  // 证书指纹
}

TLSeal {
    SignatureAlgorithm, Signature, PublicKey string
}

MerkleProof {
    TreeSize int64, LeafIndex *int64
    LeafHash, RootHash string
    Path []string
}

// Trust Card
TrustCard {
    AgentID, AgentName, AgentDisplayName, Version, AgentHost string
    Endpoints []TrustCardEndpoint
}

// Badge（透明度徽章）
Badge { Status, Payload, SchemaVersion, Signature, MerkleProof }
```

---

### 3.5 `internal/registry/` — RA API 客户端

从 `ans/` 迁移至 `internal/registry/`，作为内部实现。

```go
Client { config *clientConfig }

clientConfig {
    baseURL    string
    httpClient *http.Client
    authHeader string
    verbose    bool
}
```

**API 方法**:

| 方法 | HTTP | 路径 | 用途 |
|------|------|------|------|
| `RegisterAgent` | POST | `/v1/agents/register` | 注册 Agent |
| `GetAgentDetails` | GET | `/v1/agents/{id}` | 获取详情 |
| `SearchAgents` | GET | `/v1/agents?filters` | 搜索 Agent |
| `ResolveAgent` | POST | `/v1/agents/resolution` | 解析 Agent |
| `RevokeAgent` | POST | `/v1/agents/{id}/revoke` | 撤销 Agent |
| `SubmitIdentityCSR` | POST | `/v1/agents/{id}/certificates/identity` | 提交身份 CSR |
| `SubmitServerCSR` | POST | `/v1/agents/{id}/certificates/server` | 提交服务器 CSR |
| `GetCSRStatus` | GET | `/v1/agents/{id}/csrs/{csrId}/status` | CSR 状态查询 |
| `VerifyACME` | POST | `/v1/agents/{id}/verify-acme` | ACME 验证 |
| `VerifyDNS` | POST | `/v1/agents/{id}/verify-dns` | DNS 验证 |
| `GetAgentEvents` | GET | `/v1/agents/events` | 事件流 |

---

### 3.6 `internal/httputility/` — HTTP 工具

```go
DoRequest(ctx, cfg, method, path, body, result):
  1. json.Marshal body
  2. http.NewRequestWithContext
  3. 设置 Authorization/Content-Type/Accept
  4. httpClient.Do
  5. io.ReadAll(LimitReader(10MB))
  6. status >= 400 → ResponseError
  7. json.Unmarshal → result
```

---

### 3.7 `keygen/` — 密钥生成工具

```go
GenerateRSAKeyPair(bits) → (privPEM, pubPEM, error)
GenerateECKeyPair(curve) → (privPEM, pubPEM, error)   // P-256, P-384, P-521
SavePrivateKeyToFile(path, pem, password)              // AES-256-CBC 加密
SavePublicKeyToFile(path, pem)
// 文件权限: 0600 (私钥) / 0644 (公钥)
```

---

### 3.8 `cmd/ati-cli/` — CLI 工具

基于 Cobra + Viper 构建。

#### 全局标志 (root.go)
```
--api-key    API key (环境变量 ATI_API_KEY)
--base-url   Base URL (环境变量 ATI_BASE_URL)
--verbose    详细输出
--json       JSON 格式输出
```

#### 命令列表

| 命令 | 用途 |
|------|------|
| `register` | 注册新 Agent |
| `status` | 查询 Agent 状态 |
| `resolve` | 按 host+version 解析 Agent |
| `search` | 搜索 Agent |
| `events` | 获取 Agent 事件 |
| `revoke` | 撤销 Agent |
| `badge` | 获取 Agent Badge |
| `generate-csr` | 生成 CSR |
| `submit-identity-csr` | 提交身份 CSR |
| `submit-server-csr` | 提交服务器 CSR |
| `csr-status` | 查询 CSR 状态 |
| `get-identity-certs` | 获取身份证书 |
| `get-server-certs` | 获取服务器证书 |
| `verify-acme` | 触发 ACME 验证 |
| `verify-dns` | 触发 DNS 验证 |

---

## 4. 核心流程图

### 4.1 Agent 间 mTLS 通信流程（Bronze）

```
Agent A (AgentClient)               DNS (阿里云云解析)        Agent B (服务器)
     │                                    │                        │
     │── 1. DNS 查询 _ati.B ────────────→ │                        │
     │←─ ATIRecord { ID, Version } ──────│                        │
     │                                    │                        │
     │══ 2. mTLS 握手 ═══════════════════════════════════════════►│
     │   (双向证书验证，AgentA 提供 Identity Cert)                 │
     │                                    │                        │
     │── 3. Bronze 验证:                  │                        │
     │   a) CA 链有效 ✓                   │                        │
     │   b) ati:// URI SAN 存在 ✓         │                        │
     │   c) SAN 主机名匹配 ✓             │                        │
     │                                    │                        │
     │══ 4. HTTP 请求 ══════════════════════════════════════════►│
     │◄═ 5. HTTP 响应 ══════════════════════════════════════════│
     │                                    │                        │
     │── 6. 返回 Response + BronzeOutcome │                        │
```

### 4.2 Gold 级别验证流程

```
AgentClient             DNS              CNNIC TL            Target Agent
     │                   │                   │                     │
     │── _ati TXT ─────→│                   │                     │
     │←─ agentId ────────│                   │                     │
     │                   │                   │                     │
     │══ mTLS 握手 ══════════════════════════════════════════════►│
     │   (Bronze 验证通过)                   │                     │
     │                   │                   │                     │
     │── GET /tl/agents/{id}/logs/latest ──→│                     │
     │←─ TLLogResponse { Seal, Merkle } ────│                     │
     │                   │                   │                     │
     │── 密封验证:                           │                     │
     │   JCS(status,schema,payload,evidence) │                     │
     │   → SHA-256 → ECDSA verify            │                     │
     │                   │                   │                     │
     │── Merkle 验证:                        │                     │
     │   leafHash + path → rebuild root      │                     │
     │   compare rootHash ✓                  │                     │
     │                   │                   │                     │
     │── 指纹匹配: cert.fingerprint == TL ✓  │                     │
     │── 状态检查: ACTIVE ✓                  │                     │
     │                   │                   │                     │
     │── Gold 验证通过 → TrustLevel=Gold      │                     │
```

### 4.3 服务端客户端验证流程

```
Client Agent                                        Server (VerifyPeerCertificate)
     │                                                    │
     │══ TLS ClientHello + Certificate ══════════════════►│
     │                                                    │
     │                                              ┌─────┴─────┐
     │                                              │ Bronze:    │
     │                                              │ ati:// URI │
     │                                              │ SAN 存在？ │
     │                                              ├────────────┤
     │                                              │ Silver:    │
     │                                              │ + DANE     │
     │                                              │ 验证       │
     │                                              ├────────────┤
     │                                              │ Gold:      │
     │                                              │ + TL 验证  │
     │                                              │ VerifyGold │
     │                                              └─────┬─────┘
     │                                                    │
     │◄═ TLS Handshake Complete ═════════════════════════│
```

---

## 5. 安全设计要点

### 5.1 传输安全
- mTLS 双向证书验证
- 最低 TLS 1.2
- 仅允许 HTTPS（AgentClient.Do 强制检查）

### 5.2 DNS 发现阻塞
- Bronze 级别 DNS 发现是阻塞检查：未找到 `_ati` 记录则拒绝请求
- 防止绕过 ATI 体系直接通信

### 5.3 密码学
- JCS 规范化（RFC 8785）确保密封签名的确定性
- ECDSA 签名使用 `ecdsa.VerifyASN1`（标准库安全实现）
- 证书指纹使用 SHA-256
- Merkle 根比对使用 `crypto/subtle.ConstantTimeCompare` 防时序攻击

### 5.4 DANE 非强制
- TLSA 记录不存在 → Pass（不拒绝）
- DNSSEC 未验证 → Skip
- 仅在 DANE-EE (Usage=3) 记录存在且指纹不匹配时拒绝

### 5.5 HTTP 响应限制
- API 响应: 10 MB
- TLog 响应: 1 MB
- SCITT 响应: 2 MiB

---

## 6. 设计模式总结

| 模式 | 应用场景 |
|------|---------|
| **Functional Options** | `ati.NewAgentClient(opts...)`, `ati.NewServerTLSConfig(opts...)`, `ati.GetTrustCard(ctx, host, ver, opts...)` |
| **Builder** | `DiagnoseResult` 逐步构建诊断步骤 |
| **Strategy** | `TrustLevel` (Bronze/Silver/Gold) 决定验证深度 |
| **Value Object** | `Fqdn`, `Version`, `CertFingerprint`, `ATIName` |
| **Interface Abstraction** | `DNSResolver`, `DANEResolver`, `TransparencyLogClient` |
| **Mock** | `dns_mock.go`, `dane_mock.go`, `tlog_mock.go` |
| **Facade** | `AnsVerifier` 统一封装 `ServerVerifier` + `ClientVerifier` |

---

## 7. 目录与文件职责速查

```
ati/
  mtls_client.go       mTLS 客户端 (Bronze/Silver/Gold 多级信任验证)
  server.go            服务端 TLS 配置 (VerifyPeerCertificate 回调)
  trust_card.go        Trust Card 查询 (CNNIC TL)
  trust_level.go       Bronze / Silver / Gold 信任等级定义
  diagnose.go          7 步诊断链

models/
  agent.go             Agent 注册/状态/搜索 DTO
  badge.go             Badge 结构 + 状态枚举
  tl_log.go            CNNIC TL 响应模型 (TLLogResponse, TLSeal, TLPayload)
  trust_card.go        TrustCard 模型
  transparency.go      MerkleProof, 透明度日志 DTO (V0/V1)
  fqdn.go              FQDN 值对象
  version.go           语义化版本
  error.go             Sentinel 错误
  response_error.go    API 错误响应

verify/
  cert.go              证书抽象 (CertFingerprint, CertIdentity, ATIName)
  badge_record.go      _ati-badge TXT 记录解析
  dns.go               DNS 接口 (DNSResolver, ATIRecord, ATIDiscoveryResult)
  dns_resolver.go      标准 DNS 解析器
  dane.go              DANE/TLSA 验证
  gold.go              Gold 验证编排 (6 步流程)
  seal.go              CNNIC TL 密封验证 (JCS + SHA-256 + ECDSA)
  jcs.go               RFC 8785 JSON Canonicalization Scheme
  merkle.go            Merkle 包含证明验证 (RFC 9162 风格)
  tlog.go              透明日志客户端 (FetchBadge, FetchTLLog)
  cache.go             Badge 缓存 (TTL + stale fallback)
  verify.go            Badge 级别验证器 (ServerVerifier, ClientVerifier)
  outcome.go           统一验证结果 (VerificationOutcome)
  policy.go            失败策略 (FailClosed/FailOpenWithCache/FailOpen)
  url_validator.go     Badge URL 安全校验
  dns_mock.go          Mock DNS 解析器
  dane_mock.go         Mock DANE 解析器
  tlog_mock.go         Mock 透明日志客户端

verify/scitt/
  cose.go              COSE_Sign1 解析器 (SCITT 兼容)
  receipt.go           SCITT Receipt 验证
  status_token.go      Status Token 验证
  merkle.go            RFC 9162 Merkle Tree (SCITT 版本)
  root_keys.go         C2SP 密钥解析 + KeyStore
  client.go            SCITT HTTP 客户端
  headers.go           SCITT HTTP header 解码

internal/registry/
  client.go            RA API 客户端
  transparency.go      透明度日志 API 客户端
  agent_client.go      Agent 间 HTTP 客户端 (badge-based, legacy)
  options.go           客户端配置 options
  validate.go          参数校验

internal/httputility/
  httputil.go          HTTP 请求封装

keygen/
  keygen.go            RSA/EC 密钥生成 + PEM 编解码

cmd/ati-cli/
  main.go              CLI 入口
  cmd/root.go          全局标志 + 根命令
  cmd/*.go             各子命令
  internal/config/     Viper 配置加载
```
