# ANS SDK Go — 代码库深度分析文档

## 1. 项目概览

**模块名**: `github.com/godaddy/ans-sdk-go`  
**Go 版本**: 1.25.0  
**定位**: GoDaddy Agent Name System (ANS) 的 Go SDK + CLI 工具，用于 AI Agent 的安全注册、验证、透明度日志和 Agent 间 HTTPS 通信。

### 核心依赖

| 依赖 | 用途 |
|------|------|
| `miekg/dns` | DNS 查询（TXT / TLSA 记录、DNSSEC） |
| `spf13/cobra` + `spf13/viper` | CLI 命令框架 + 配置管理 |
| `fxamacker/cbor/v2` | CBOR 编解码（COSE_Sign1、SCITT） |

---

## 2. 整体架构

```
┌─────────────────────────────────────────────────────────────┐
│                     cmd/ans-cli                             │
│  (CLI 入口, cobra commands, viper config)                   │
└───────────────┬──────────────────────┬──────────────────────┘
                │                      │
    ┌───────────▼──────────┐  ┌────────▼──────────────┐
    │      ans/            │  │      verify/           │
    │  ┌─────────────┐     │  │  ┌─────────────────┐   │
    │  │ Client      │     │  │  │ ServerVerifier   │   │
    │  │ (Registry   │     │  │  │ ClientVerifier   │   │
    │  │  API)       │     │  │  │ AnsVerifier      │   │
    │  ├─────────────┤     │  │  ├─────────────────┤   │
    │  │Transparency │     │  │  │ Badge Verify     │   │
    │  │ Client      │     │  │  │ SCITT Verify     │   │
    │  ├─────────────┤     │  │  │ DANE Verify      │   │
    │  │ AgentClient │─────┼──┤  │ DNS Resolver     │   │
    │  │ (A2A HTTP)  │     │  │  │ TLog Client      │   │
    │  └─────────────┘     │  │  │ URL Validator    │   │
    └──────────────────────┘  │  │ Badge Cache      │   │
                              │  └─────────────────┘   │
                              │  ┌─────────────────┐   │
                              │  │ verify/scitt/    │   │
                              │  │  COSE_Sign1      │   │
                              │  │  Receipt         │   │
                              │  │  StatusToken     │   │
                              │  │  Merkle Tree     │   │
                              │  │  Root Keys       │   │
                              │  └─────────────────┘   │
                              └────────────────────────┘
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

### 3.1 `models/` — 数据结构层

所有 API 请求/响应的 DTO、枚举、值对象，无业务逻辑。

#### 3.1.1 Agent 注册与管理

```go
// 注册请求
AgentRegistrationRequest {
    AgentHost, Version, DisplayName, Description,
    ProviderID, Endpoints []AgentEndpoint, BYOC 配置
}

// 注册响应（待验证状态）
RegistrationPending {
    AgentID, AnsName, Status,
    Challenges []ChallengeInfo,   // ACME HTTP / DNS 挑战
    DNSRecords []DNSRecordInfo    // 需要配置的 DNS 记录
}

// Agent 详情
AgentDetails { AgentID, AnsName, Status, Host, Version, ... }

// Agent 搜索
AgentSearchResponse { Results []AgentDetails, Pagination }
```

#### 3.1.2 Badge（徽章）

Badge 是 ANS 透明度日志中记录的代理注册证明。

```go
BadgeStatus = ACTIVE | WARNING | DEPRECATED | EXPIRED | REVOKED
  - IsValidForConnection(): ACTIVE/WARNING/DEPRECATED → true
  - ShouldReject(): EXPIRED/REVOKED → true

Badge {
    Status BadgeStatus
    Payload → Producer → AgentEvent {
        ANSID, ANSName, EventType, Agent{Host,Version},
        Attestations { ServerCert, IdentityCert (fingerprint+type) },
        IssuedAt, ExpiresAt, RAID
    }
    SchemaVersion, Signature, MerkleProof
}

EventType = AGENT_REGISTERED | AGENT_RENEWED | AGENT_DEPRECATED | AGENT_REVOKED
```

#### 3.1.3 Transparency Log Schema（V0/V1 双版本）

```
V0 (旧版):
  TransparencyLogV0 → ProducerV0 → EventV0 {
      AgentFQDN, RABadge { Attestations (string fingerprints) }
  }

V1 (新版):
  TransparencyLogV1 → ProducerV1 → EventV1 {
      Attestations { ServerCert, IdentityCert (结构化),
                     ValidServerCerts[], ValidIdentityCerts[] (多证书) }
      MetadataHashes, RevocationReasonCode
  }

SchemaVersion = "V0" | "V1" | "" (空=V0)
```

#### 3.1.4 其他数据结构

```go
// FQDN 值对象 — RFC 1035 校验
Fqdn { value string }
  .AnsBadgeName() → "_ans-badge.<fqdn>"
  .RaBadgeName()  → "_ra-badge.<fqdn>"  (legacy)
  .TlsaName(port) → "_<port>._tcp.<fqdn>"

// 语义化版本
Version { Major, Minor, Patch }
  ParseVersion("v1.2.3"), Compare(), Equal()

// 证书
CertificateResponse { CertificatePEM, Validity, CsrID }
CsrSubmissionRequest/Response, CsrStatusResponse (PENDING/SIGNED/REJECTED)

// 撤销
RevocationReason = KEY_COMPROMISE | CESSATION_OF_OPERATION | ...
AgentRevocationRequest/Response

// 错误
ErrNotFound, ErrUnauthorized, ErrForbidden, ErrBadRequest, ...
ResponseError { StatusCode, Code, Message, Details }
```

---

### 3.2 `ans/` — API 客户端层

#### 3.2.1 `Client` — ANS Registry API 客户端

```go
Client { config *clientConfig }

clientConfig {
    baseURL    string       // 默认 "https://api.godaddy.com"
    httpClient *http.Client // 默认 timeout=120s
    authHeader string       // "sso-jwt <token>" 或 "sso-key <key>:<secret>"
    verbose    bool
}
```

**Options 模式**:
```go
NewClient(
    WithBaseURL(url),
    WithJWT(token),        // 内部端点
    WithAPIKey(key, sec),  // 公共网关
    WithTimeout(d),
    WithHTTPClient(c),
    WithVerbose(bool),
)
```

**API 方法**（全部通过 `httputility.DoRequest` 发送）：

| 方法 | HTTP | 路径 | 用途 |
|------|------|------|------|
| `RegisterAgent` | POST | `/v1/agents/register` | 注册 Agent |
| `GetAgentDetails` | GET | `/v1/agents/{id}` | 获取详情 |
| `GetChallengeDetails` | GET | `/v1/agents/{id}/challenge` | 获取挑战信息 |
| `VerifyACME` | POST | `/v1/agents/{id}/verify-acme` | 触发 ACME 验证 |
| `VerifyDNS` | POST | `/v1/agents/{id}/verify-dns` | 验证 DNS 配置 |
| `SearchAgents` | GET | `/v1/agents?filters` | 搜索 Agent |
| `GetIdentityCertificates` | GET | `/v1/agents/{id}/certificates/identity` | 获取身份证书 |
| `GetServerCertificates` | GET | `/v1/agents/{id}/certificates/server` | 获取服务器证书 |
| `SubmitIdentityCSR` | POST | `/v1/agents/{id}/certificates/identity` | 提交身份 CSR |
| `SubmitServerCSR` | POST | `/v1/agents/{id}/certificates/server` | 提交服务器 CSR |
| `GetCSRStatus` | GET | `/v1/agents/{id}/csrs/{csrId}/status` | CSR 状态查询 |
| `GetAgentEvents` | GET | `/v1/agents/events` | 分页获取事件 |
| `ResolveAgent` | POST | `/v1/agents/resolution` | 按 host+version 解析 |
| `RevokeAgent` | POST | `/v1/agents/{id}/revoke` | 撤销 Agent |

#### 3.2.2 `TransparencyClient` — 透明度日志客户端

```go
TransparencyClient { config *clientConfig }
// 默认 baseURL = "https://transparency.ans.godaddy.com"
// 公共读取，无需 auth
```

**关键特性**：
- `doRequestWithSchemaVersion()`: 自定义请求处理，捕获 `X-Schema-Version` 响应头
- `parsePayloadBySchema()`: 根据版本动态解析为 V0/V1 结构体

| 方法 | 路径 | 用途 |
|------|------|------|
| `GetAgentTransparencyLog` | `/v1/agents/{id}` | 当前日志条目 |
| `GetAgentTransparencyLogAudit` | `/v1/agents/{id}/audit` | 审计历史（分页） |
| `GetCheckpoint` | `/v1/log/checkpoint` | 当前检查点 |
| `GetCheckpointHistory` | `/v1/log/checkpoint/history` | 检查点历史 |
| `GetLogSchema` | `/v1/log/schema/{version}` | JSON Schema |

#### 3.2.3 `AgentClient` — Agent 间安全 HTTP 客户端

这是最复杂的客户端，封装了 Badge 验证 + TLS 证书校验。

```go
AgentClient {
    httpClient *http.Client
    verifier   *verify.AnsVerifier
    config     *agentClientConfig {
        timeout, verifyServer, tlsConfig,
        failurePolicy, verifierOptions
    }
}
```

**请求生命周期** (`Do` 方法):

```
1. URL 解析 & 校验 (HTTPS required when verifyServer=true)
       │
2. prefetchBadge(host)
   ├── FailClosed: 错误 → 立即返回 error
   ├── FailOpenWithCache: 错误 → 继续（verifier 内部查 stale cache）
   └── FailOpen: 错误 → 继续
       │
3. executeRequest() — 构建 HTTP 请求, JSON body, 发送
       │
4. verifyTLSCert(host, resp)
   ├── 提取 resp.TLS.PeerCertificates[0]
   ├── CertIdentityFromX509() → CertIdentity
   ├── verifier.VerifyServer(ctx, host, certIdentity)
   ├── 成功 → 返回 Response + VerificationOutcome
   ├── 失败 + FailClosed → close body, return error
   └── 失败 + FailOpen → 返回 outcome (warning)
```

**便捷方法**: `Get/Post/Put/Delete`, `GetJSON/PostJSON/PutJSON`, `Prefetch`

---

### 3.3 `verify/` — 验证引擎（核心）

#### 3.3.1 架构总览

```
                    AnsVerifier (Facade)
                   ╱                  ╲
         ServerVerifier          ClientVerifier
              │                        │
    ┌─────────┴─────────┐    ┌────────┴────────┐
    │ Verify(fqdn,cert) │    │ Verify(cert)     │
    │ VerifyWithScitt()  │    │ VerifyWithScitt() │
    │ Prefetch()        │    │                   │
    └───────────────────┘    └───────────────────┘
              │                        │
              └──────── 共享 ──────────┘
                   verifierConfig {
                     dnsResolver, tlogClient, cache,
                     failurePolicy, urlValidator,
                     daneResolver, scittKeyLookup,
                     clockSkewTolerance, logger
                   }
```

#### 3.3.2 `CertIdentity` & `CertFingerprint` — 证书抽象

```go
CertFingerprint { bytes [32]byte }  // SHA-256
  - FromDER(der) / FromBytes([32]byte)
  - Parse("SHA256:<hex>")
  - Matches(other string) bool
  - String() → "SHA256:<hex>"

CertIdentity {
    CommonName *string
    DNSSANs    []string      // DNS Subject Alternative Names
    URISANs    []string      // URI SANs (含 ans:// URI)
    Fingerprint CertFingerprint
}
  - FQDN() → 优先 DNS SAN，回退 CN
  - AnsName() → 从 URI SAN 提取 ans:// 名称
  - Version() → 从 ANS name 提取版本

AnsName { Version, Host, raw }
  - 格式: "ans://v<major>.<minor>.<patch>.<fqdn>"
```

#### 3.3.3 Badge DNS 解析流程

```
StandardDNSResolver (net.Resolver, timeout=10s)
    │
    ├── LookupAnsBadge(fqdn)
    │     1. 查询 "_ans-badge.<fqdn>" TXT 记录
    │     2. 解析失败(SERVFAIL/超时) → 返回 hard error (不回退)
    │     3. NXDOMAIN → 回退查询 "_ra-badge.<fqdn>" (legacy)
    │     4. 解析 TXT → ParseAnsBadgeRecord()
    │
    ├── FindPreferredBadge(fqdn)
    │     → 获取所有记录，按版本降序排序，返回最新
    │
    └── FindBadgeForVersion(fqdn, version)
          → 精确匹配 → 无版本记录回退

AnsBadgeRecord 格式: "v=ans-badge1; version=v1.0.0; url=https://..."
```

#### 3.3.4 Badge URL 安全校验

```go
URLValidator { trustedDomains []string }
// 默认信任域名:
//   - transparency.ans.godaddy.com
//   - transparency.ans.ote-godaddy.com

校验规则:
  1. 必须 HTTPS
  2. 域名必须在信任列表中（不区分大小写）
  3. 禁止非标准端口（仅允许 443 或空）
  4. 禁止路径穿越（..）和查询参数
```

#### 3.3.5 Transparency Log 客户端 (Badge Fetch)

```go
TransparencyLogClient interface {
    FetchBadge(ctx, url) (*Badge, error)
}

HTTPTransparencyLogClient — 1MB 响应限制, JSON 反序列化为 Badge
```

#### 3.3.6 Badge 缓存

```go
BadgeCache {
    entries map[string]*cacheEntry  // key = fqdn 或 fqdn+version
    mu      sync.RWMutex
    config  CacheConfig { TTL, MaxEntries, BackgroundRefresh }
}

操作:
  - GetByFqdn / GetByFqdnVersion → 命中且未过期
  - GetStaleByFqdn / GetStaleByFqdnVersion → 过期但在 MaxStaleness 内
  - Insert / InsertForVersion → 写入
```

#### 3.3.7 ServerVerifier — 服务器证书验证流程

```
Verify(ctx, fqdn, cert):
    │
    1. 缓存查找
    │   ├── 命中 → verifyWithBadge()
    │   │   └── 指纹不匹配 → 可能证书更新，继续刷新
    │   └── 未命中 → 继续
    │
    2. fetchBadge(fqdn):
    │   a) DNS 查找 → FindPreferredBadge()
    │   │   ├── NotFound → NewNotAnsAgentOutcome (不应用 failurePolicy)
    │   │   └── DNS error → applyFailurePolicy()
    │   b) validateBadgeURL()
    │   c) tlogClient.FetchBadge(url)
    │       └── error → applyFailurePolicy()
    │
    3. 写入缓存
    │
    4. verifyWithBadge(badge, cert, fqdn):
    │   a) badge.Status.IsValidForConnection()? → EXPIRED/REVOKED 拒绝
    │   b) 服务器证书指纹匹配 badge.ServerCertFingerprint()
    │   c) badge.AgentHost() == fqdn (大小写不敏感)
    │   d) cert.FQDN() == badge.AgentHost()
    │   e) DEPRECATED → 添加 warning
    │
    5. DANE/TLSA 检查（可选）
    │   └── DANEMismatch / DNSSECFailed → 拒绝（覆盖 badge 结果）
    │
    → VerificationOutcome
```

#### 3.3.8 ClientVerifier — mTLS 客户端证书验证流程

```
Verify(ctx, cert):
    │
    1. 从证书提取 FQDN (DNS SAN → CN)
    2. 从 URI SAN 提取 AnsName (ans://v1.0.0.host)
    3. 从 AnsName 提取 Version
    4. 缓存查找 (fqdn + version)
    5. fetchBadge(fqdn, version) — DNS FindBadgeForVersion()
    6. verifyWithBadge():
    │   a) Status 检查
    │   b) IdentityCert 指纹匹配（注意：是 IdentityCert 不是 ServerCert）
    │   c) Hostname 匹配
    │   d) ANS Name 匹配 (badge.AgentName() == cert.AnsName())
    7. DANE 检查
```

#### 3.3.9 SCITT 验证路径（高安全级别）

`VerifyWithScitt()` 是 Badge 验证的增强路径：

```
VerifyWithScitt(ctx, fqdn, cert, headers):
    │
    1. headers 为空 → 回退到标准 Verify()
    2. 必须同时有 X-SCITT-Receipt + X-ANS-Status-Token
    3. 确认 scittKeyLookup 已配置
    │
    4. scitt.VerifyReceipt(receipt, keys):
    │   a) ParseCoseSign1 → 解析 CBOR COSE_Sign1
    │   b) 验证 VDS=1 (RFC 9162)
    │   c) 通过 kid 查找签名密钥
    │   d) ECDSA 签名验证 (P1363 → DER → VerifyASN1)
    │   e) Issuer Binding 检查
    │   f) 提取 VDP, Walk Merkle Inclusion Path
    │   ⚠ TransportError + ShouldFallbackToBadge → 回退 badge
    │
    5. scitt.VerifyStatusToken(token, keys, clockSkew):
    │   a) ParseCoseSign1 + ECDSA 验证
    │   b) 解码 CBOR payload → StatusTokenPayload
    │   c) 过期检查 (now > exp + skew → 拒绝)
    │   d) 终端状态检查 (EXPIRED/REVOKED → 拒绝)
    │
    6. 状态允许连接? (ACTIVE/WARNING/DEPRECATED)
    │
    7. 指纹匹配:
    │   - roleServer → MatchesServerCert(payload, fingerprint)
    │   - roleIdentity → MatchesIdentityCert(payload, fingerprint)
    │   (全部使用 constant-time 比较)
    │
    8. AnsName host 绑定检查
    9. DANE 检查
    │
    → VerificationOutcome { Tier: TierFullScitt }
```

**关键安全设计**: SCITT 验证失败（签名无效、伪造等）**永不应用 FailOpen 策略**，只有 DNS/TLog 基础设施故障才走 FailurePolicy。

#### 3.3.10 DANE/TLSA 验证

```go
DANEVerifier { resolver DANEResolver }

StandardDANEResolver {
    server  string          // 默认 "8.8.8.8:53"
    timeout time.Duration   // 默认 5s
}

LookupTLSA(fqdn, port):
  1. 构造查询名: "_<port>._tcp.<fqdn>."
  2. 设置 EDNS0 (4096 buf, DO flag) + RD=1
  3. DNS 查询
  4. SERVFAIL → DANEErrorDNSSECFailed
  5. NXDOMAIN / 无应答 → Found=false
  6. 解析 TLSA RR → TLSARecord { Usage, Selector, MatchingType, CertHash }
  7. resp.AuthenticatedData → DNSSECValid

Verify(fqdn, port, cert):
  1. LookupTLSA()
  2. !Found → DANENoRecords (pass)
  3. !DNSSECValid → DANESkipped (pass, 不强制)
  4. 遍历 Usage=3 (DANE-EE) 记录，比对 cert hex fingerprint
  5. 匹配 → DANEVerified / 不匹配 → DANEMismatch (reject)
```

#### 3.3.11 失败策略 (FailurePolicy)

```go
FailClosed       // DNS/TLog 错误 → 拒绝 (默认, 最安全)
FailOpenWithCache // 错误 → 尝试 stale cache (MaxStaleness=10min)
FailOpen         // 错误 → 接受 (不推荐)
```

仅应用于 DNS 和 TLog 基础设施错误；SCITT 签名错误**始终拒绝**。

#### 3.3.12 `VerificationOutcome` — 统一验证结果

```go
OutcomeType:
  Verified | NotAnsAgent | InvalidStatus |
  FingerprintMismatch | HostnameMismatch | AnsNameMismatch |
  DNSError | TlogError | CertError | FailOpen |
  URLValidationError | DANERejection | ScittError

VerificationTier:
  TierBadgeOnly  // 仅 badge 验证
  TierFullScitt  // SCITT receipt + status token 验证

VerificationOutcome {
    Type, Tier, Badge, MatchedFingerprint,
    Expected, Actual (mismatch 诊断),
    Status, Host, Error, Warnings[],
    DANEOutcome
}
```

---

### 3.4 `verify/scitt/` — SCITT 密码学子系统

#### 3.4.1 COSE_Sign1 解析器

**为什么手写而不用 go-cose?**
1. go-cose 不暴露 CBOR 解码选项（MaxNestedLevels 等），无法做 DoS 防护
2. 自定义 header (vds=395, CWT claims) 需要手动解析
3. 必须保留 ProtectedBytes 原始字节用于签名验证

```go
ParsedCoseSign1 {
    ProtectedBytes []byte   // 原样保留, 不重新编码
    Protected ProtectedHeader {
        Alg int64    // 必须是 -7 (ES256)
        Kid [4]byte  // 必须恰好 4 字节
        Vds *int64   // 395: Verifiable Data Structure
        ContentType *string
        CwtIss *string, CwtIat *int64
    }
    Unprotected cbor.RawMessage
    Payload     []byte     // 非空
    Signature   []byte     // 恰好 64 字节 (P1363)
}
```

**安全限制**:
- `MaxCoseInputSize = 1 MiB`
- CBOR: `MaxNestedLevels=16, MaxArrayElements=1024, MaxMapPairs=256`
- Tag 18 自动剥离

#### 3.4.2 Receipt 验证

```
VerifyReceipt(receiptBytes, keys):
  1. ParseCoseSign1
  2. validateVDS(vds == 1)  // RFC 9162
  3. keys.Get(kid) → TrustedKey
  4. verifyECDSA:
     a) BuildSigStructure(["Signature1", protected, "", payload])
     b) SHA-256(sigStructure)
     c) P1363 (64 bytes) → DER (asn1.Marshal {R,S})
     d) ecdsa.VerifyASN1(key, digest, derSig)
  5. verifyIssuerBinding (CWT iss == key.Name)
  6. extractVDP (unprotected header, key 396):
     {-1: tree_size, -2: leaf_index, -3: inclusion_path[]}
  7. WalkInclusionPath → rootHash

→ VerifiedReceipt { TreeSize, LeafIndex, RootHash, EventBytes, KeyID }
```

**⚠ 重要**: `RootHash` **未**与任何受信的 tree head 交叉验证。ECDSA 签名保证叶节点级信任；树头验证需要带外（witness/monitor）。

#### 3.4.3 Status Token 验证

```
VerifyStatusTokenAt(tokenBytes, keys, clockSkew, now):
  1. ParseCoseSign1
  2. keys.Get(kid)
  3. verifyECDSA (同上)
  4. Issuer Binding
  5. decodeStatusPayload (CBOR map):
     支持整数键 (1-8) 和字符串键 ("agent_id" 等) 双模式
     必填: agent_id, status, exp, ans_name
  6. 过期检查: now > exp + clockSkew → TokenErrExpired
  7. 终端状态: EXPIRED/REVOKED → TokenErrTerminalStatus

StatusTokenPayload {
    AgentID, AnsName, Status (AgentStatus),
    Iat, Exp (unix timestamp),
    ValidIdentityCerts []CertEntry,  // 证书指纹+类型
    ValidServerCerts   []CertEntry,
    MetadataHashes map[string]string
}
```

**指纹匹配** (constant-time):
- `MatchesServerCert(payload, [32]byte)` → `subtle.ConstantTimeCompare`
- `MatchesIdentityCert(payload, [32]byte)` → `subtle.ConstantTimeCompare`

#### 3.4.4 Merkle Tree (RFC 9162)

```go
ComputeLeafHash(data)  → SHA-256(0x00 || data)
ComputeNodeHash(l, r)  → SHA-256(0x01 || left || right)

WalkInclusionPath(eventBytes, leafIndex, treeSize, hashPath):
  - leafHash = ComputeLeafHash(eventBytes)
  - 沿 path 逐层向上计算: 奇数/等于 sn → hash(p, current), 否则 → hash(current, p)
  - 消耗完 path 后 sn==0 → 成功
  - MaxHashPathLen = 63 (最大 2^63 叶节点)

VerifyMerkleInclusion → WalkInclusionPath + constant-time root 比较
```

#### 3.4.5 Root Keys (C2SP 格式)

```go
TrustedKey { Name string, Kid [4]byte, Key *ecdsa.PublicKey }

C2SP 格式: "name+hex_kid+base64_spki_der"
  - 解析: name, hex→4字节kid, base64→SPKI DER (可选 0x02 前缀)
  - 验证: P-256 曲线, kid == SHA-256(SPKI DER)[:4]

KeyStore { keys map[[4]byte]TrustedKey }
  - NewKeyStore(strings) — 解析 + 去重
  - Get(kid) → TrustedKey
  - MergeFrom(strings) → 新 KeyStore + MergeResult (不可变合并)
```

#### 3.4.6 SCITT HTTP 客户端

```go
scitt.HTTPClient { baseURL, httpClient, headers, ... }
  - 必须 HTTPS (除非 WithAllowInsecureTransport)
  - 默认 timeout 30s, 最大响应 2 MiB

FetchReceipt(agentID)    → GET /v1/agents/{id}/receipt
FetchStatusToken(agentID) → GET /v1/agents/{id}/status-token
FetchRootKeys()           → GET /root-keys (换行分隔的 C2SP 字符串)

HTTP 状态映射:
  404 → TransportErrNotFound
  410 → TransportErrAgentTerminal
  501 → TransportErrNotSupported
```

#### 3.4.7 SCITT Headers（HTTP 传输）

```go
X-SCITT-Receipt      → base64 encoded COSE_Sign1 receipt
X-ANS-Status-Token   → base64 encoded COSE_Sign1 status token

MaxBase64HeaderSize = ceil(1MiB/3)*4 ≈ 1.33 MiB

ExtractHeaders(http.Header) → Headers { Receipt, StatusToken []byte }
  IsEmpty() / HasBoth()
```

#### 3.4.8 错误体系

```
CoseError   { Type: Oversized|NotCose|CborDecode|InvalidArray|InvalidSig|... }
SignatureError { Type: Invalid|IssuerMismatch|UnknownKeyID|InvalidKeyFormat|... }
MerkleError { Type: InvalidProof|RootMismatch }
TokenError  { Type: Expired|TerminalStatus|PayloadEmpty|MissingField|... }
TransportError { Type: NotFound|AgentTerminal|NotSupported|HTTPError|Base64Decode }
  - ShouldFallbackToBadge(): NotFound|AgentTerminal|NotSupported → true
    (基础设施问题可回退，伪造/签名错误不可回退)
```

#### 3.4.9 RefreshableKeyStore & Supplier

```go
RefreshableKeyStore — 定期从远端刷新 root keys 的包装器
Supplier interface { FetchKeys(ctx) ([]string, error) }
  - 用 scitt.Client.FetchRootKeys() 作为 supplier
  - 周期性刷新 + 失败保留旧 keys
```

---

### 3.5 `internal/httputility/` — HTTP 工具

```go
DoRequest(ctx, cfg, method, path, body, result):
  1. prepareRequestBody → json.Marshal → bytes.Buffer
  2. http.NewRequestWithContext
  3. setRequestHeaders (Authorization, Content-Type, Accept)
  4. httpClient.Do
  5. io.ReadAll(LimitReader(10MB))
  6. status >= 400 → HandleErrorResponse → ResponseError
  7. json.Unmarshal → result
```

---

### 3.6 `keygen/` — 密钥生成工具

```go
GenerateRSAKeyPair(bits) → (privPEM, pubPEM, error)
GenerateECKeyPair(curve) → (privPEM, pubPEM, error)
  - P-256, P-384, P-521

SavePrivateKeyToFile(path, pem, password) — AES-256-CBC 加密 (可选)
SavePublicKeyToFile(path, pem)
LoadPrivateKeyFromFile(path, password)
LoadPublicKeyFromFile(path)
// 文件权限: 0600 (私钥) / 0644 (公钥)
```

---

### 3.7 `cmd/ans-cli/` — CLI 工具

基于 Cobra + Viper 构建。

#### 全局标志 (root.go)
```
--api-key    API key (环境变量 ANS_API_KEY)
--base-url   Base URL (环境变量 ANS_BASE_URL)
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

### 4.1 Agent 注册完整流程

```
客户端                          ANS API                      DNS
  │                               │                           │
  │── RegisterAgent(host,ver) ──→ │                           │
  │                               │── 创建 Agent              │
  │←── RegistrationPending ──────│                           │
  │    {agentID, challenges,      │                           │
  │     dnsRecords}               │                           │
  │                               │                           │
  │── 配置 DNS TXT 记录 ─────────────────────────────────────→│
  │── 配置 ACME HTTP 挑战 ──→ (web server)                    │
  │                               │                           │
  │── VerifyDNS(agentID) ───────→│── 检查 DNS 记录 ─────────→│
  │←── AgentStatus ──────────────│                           │
  │                               │                           │
  │── VerifyACME(agentID) ──────→│── 检查 HTTP 挑战          │
  │←── AgentStatus (ACTIVE) ─────│                           │
  │                               │                           │
  │── SubmitServerCSR() ────────→│── 签发证书                 │
  │── SubmitIdentityCSR() ──────→│── 签发证书                 │
  │                               │                           │
  │── GetCSRStatus(csrId) ──────→│── PENDING → SIGNED        │
  │← GetServerCertificates() ───│                           │
```

### 4.2 Agent 间安全通信流程

```
Agent A (客户端)                                    Agent B (服务器)
     │                                                    │
     │── 1. Prefetch Badge ─→ DNS TXT "_ans-badge.B" ────│
     │←─ badge record { url }                             │
     │── 2. Fetch Badge ───→ Transparency Log             │
     │←─ Badge { status, fingerprint, host }              │
     │                                                    │
     │══ 3. TLS Handshake ═══════════════════════════════►│
     │   (获取 PeerCertificates[0])                       │
     │                                                    │
     │── 4. Verify:                                       │
     │   a) Badge.Status valid?                           │
     │   b) cert.fingerprint == badge.fingerprint?        │
     │   c) hostname match?                               │
     │   d) [可选] DANE/TLSA check                        │
     │                                                    │
     │══ 5. HTTP Request ════════════════════════════════►│
     │◄═ 6. HTTP Response ═══════════════════════════════│
     │                                                    │
     │── 7. Return Response + VerificationOutcome         │
```

### 4.3 SCITT 增强验证流程

```
Agent A                         Agent B              SCITT Service
  │                               │                       │
  │══ TLS + HTTP Request ════════►│                       │
  │◄═ Response ══════════════════│                       │
  │   + X-SCITT-Receipt: <b64>   │                       │
  │   + X-ANS-Status-Token: <b64>│                       │
  │                               │                       │
  │── ExtractHeaders()            │                       │
  │                               │                       │
  │── VerifyReceipt(receipt, keys)│                       │
  │   ├── ParseCoseSign1          │                       │
  │   ├── VDS == 1 (RFC 9162)     │                       │
  │   ├── ECDSA 签名验证          │                       │
  │   ├── Issuer 绑定检查         │                       │
  │   └── Merkle Inclusion Proof  │                       │
  │                               │                       │
  │── VerifyStatusToken(token, keys, skew)                │
  │   ├── ParseCoseSign1          │                       │
  │   ├── ECDSA 签名验证          │                       │
  │   ├── 解码 payload            │                       │
  │   ├── 过期检查                │                       │
  │   ├── 终端状态检查            │                       │
  │   └── cert 指纹匹配          │                       │
  │       (constant-time compare) │                       │
  │                               │                       │
  │── DANE 检查 (可选)            │                       │
  │                               │                       │
  │── Outcome: Tier=FullScitt ✓   │                       │
```

---

## 5. 安全设计要点

### 5.1 防 DoS
- CBOR 解码限制: 嵌套 16 层, 数组 1024, Map 256
- COSE 输入最大 1 MiB, Base64 header 最大 ~1.33 MiB
- HTTP 响应体限制: API 10 MB, TLog 1 MB, SCITT 2 MiB

### 5.2 防伪造
- **SCITT 签名错误永不 FailOpen**: `applyFailurePolicy` 注释明确说明
- `TransportError.ShouldFallbackToBadge()` 只允许基础设施错误回退
- ECDSA 签名使用 `ecdsa.VerifyASN1` (标准库安全实现)
- 指纹比较使用 `crypto/subtle.ConstantTimeCompare` 防时序攻击

### 5.3 防降级
- Badge URL 必须 HTTPS + 可信域名
- Agent 通信要求 HTTPS (verifyServer=true 时)
- DANE 检查可在 badge 验证成功后额外拒绝

### 5.4 密钥管理
- C2SP 格式: kid = SHA-256(SPKI)[:4] — 防止 kid 篡改
- KeyStore 不可变, MergeFrom 返回新实例
- RefreshableKeyStore 周期性远程刷新, 失败保留旧 keys

### 5.5 Clock Skew 容忍
- Status Token 过期检查: `now > exp + clockSkew`
- 默认 120 秒, 最大 10 分钟 (硬限制)
- 负值钳位到 0

---

## 6. 设计模式总结

| 模式 | 应用场景 |
|------|---------|
| **Functional Options** | `ans.NewClient(opts...)`, `verify.NewServerVerifier(opts...)`, `scitt.NewHTTPClient(opts...)` |
| **Facade** | `AnsVerifier` 统一封装 `ServerVerifier` + `ClientVerifier` |
| **Strategy** | `FailurePolicy` (FailClosed/FailOpenWithCache/FailOpen) |
| **Value Object** | `Fqdn`, `Version`, `CertFingerprint`, `AnsName` |
| **Interface Abstraction** | `DNSResolver`, `DANEResolver`, `TransparencyLogClient`, `KeyLookup`, `scitt.Client` |
| **Immutable Data** | `KeyStore.MergeFrom()` 返回新实例 |
| **Mock** | `dns_mock.go`, `dane_mock.go`, `tlog_mock.go`, `scitt/client_mock.go` |
| **Cache-aside** | `BadgeCache` 配合 TTL + stale fallback |

---

## 7. 目录与文件职责速查

```
ans/
  client.go           ANS Registry API 客户端 (RegisterAgent, SearchAgents, ...)
  transparency.go     透明度日志 API 客户端 (GetCheckpoint, Audit, ...)
  agent_client.go     Agent 间安全 HTTP 客户端 (badge 验证 + TLS)
  options.go          客户端配置 options
  validate.go         参数校验工具

models/
  agent.go            Agent 注册/状态/搜索 DTO
  badge.go            Badge 结构 + 状态枚举
  certificate.go      证书/CSR DTO
  transparency.go     透明度日志/检查点 DTO
  transparency_schemas.go  V0/V1 schema 定义
  event.go            事件 DTO
  fqdn.go             FQDN 值对象
  version.go          语义化版本
  resolution.go       Agent 解析 DTO
  revocation.go       撤销 DTO
  error.go            Sentinel 错误
  response_error.go   API 错误响应

verify/
  verify.go           核心验证逻辑 (ServerVerifier, ClientVerifier, AnsVerifier)
  cert.go             证书抽象 (CertFingerprint, CertIdentity, AnsName)
  badge_record.go     Badge TXT 记录解析
  dns.go              DNS 接口
  dns_resolver.go     标准 DNS 解析器
  tlog.go             透明度日志客户端 (badge fetch)
  cache.go            Badge 缓存
  dane.go             DANE/TLSA 验证
  url_validator.go    Badge URL 安全校验
  policy.go           失败策略
  options.go          验证器配置 options
  outcome.go          验证结果
  errors.go           错误类型

verify/scitt/
  cose.go             COSE_Sign1 手写解析器
  receipt.go          SCITT Receipt 验证
  status_token.go     Status Token 验证
  merkle.go           RFC 9162 Merkle Tree
  root_keys.go        C2SP 密钥解析 + KeyStore
  refreshable_key_store.go  自动刷新的密钥存储
  supplier.go         密钥供应商接口
  client.go           SCITT HTTP 客户端
  headers.go          SCITT HTTP header 解码
  types.go            AgentStatus, CertEntry, StatusTokenPayload
  errors.go           SCITT 错误体系

internal/httputility/
  httputil.go         HTTP 请求封装

keygen/
  keygen.go           RSA/EC 密钥生成 + PEM 编解码

cmd/ans-cli/
  main.go             CLI 入口
  cmd/root.go         全局标志 + 根命令
  cmd/*.go            各子命令
  internal/config/    Viper 配置加载
```
