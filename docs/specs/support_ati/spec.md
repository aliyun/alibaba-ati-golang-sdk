# ATI Golang SDK 技术规格文档

v1.2 | 2026-06-01 | 基于 PRD V2.0 + CNNIC 接口文档 v0.3 + GoDaddy ANS SDK v0.1.7

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

    // SDK 提供安全传输层（mTLS + DNS 发现 + Bronze 验证）
    // 用户自己按 MCP/A2A/OpenAPI 协议构造请求
    resp, _ := client.Post(ctx, "https://translate.example.com/mcp",
        map[string]any{"method": "translate", "params": map[string]string{"text": "Hello"}})

    // resp.VerificationOutcome 包含 Bronze 验证结果（DNS 存在 + CA 链 + SAN 匹配）
}
```

### Server 端（被其他 Agent 调用）

```go
package main

import "gitlab.alibaba-inc.com/alibaba-dns/ati-golang-sdk/ati"

func main() {
    // 生成 Server 端 mTLS 配置
    tlsConfig, _ := ati.NewServerTLSConfig(
        ati.WithServerCert("./certs/server.pem", "./certs/key.pem"),
        ati.WithClientCA("./certs/cnnic_ca_bundle.pem"),
    )

    server := &http.Server{
        Addr:      ":443",
        TLSConfig: tlsConfig,
        Handler:   http.HandlerFunc(handler),
    }
    server.ListenAndServeTLS("", "")
}

func handler(w http.ResponseWriter, r *http.Request) {
    // 提取对方 Agent 的 ATI 身份
    peer, _ := ati.PeerATIName(r.TLS)
    fmt.Printf("来访 Agent: %s (v%s)\n", peer.Host, peer.Version)
}
```

## 设计约束

- **SDK 不做注册** — PRD 5.1：注册须通过控制台 GUI 完成，SDK 仅加载证书 + 通信
- **只做安全传输层** — SDK 提供 mTLS + DNS 发现 + 信任验证，不封装应用协议（MCP/A2A/OpenAPI 由用户自行构造请求）
- **Client + Server 双端** — SDK 既支持调用其他 Agent（Client），也支持被其他 Agent 调用时验证对方身份（Server）
- **Bronze 默认且需要 DNS** — MVP Bronze 验证 = DNS 发现（确认已注册）+ PKI（CA 链 + SAN 匹配），不碰 badge/TL
- **开发者体验优先** — 每个决策回答"对调 SDK 的开发者意味着什么"
- **API 表面最小化** — 公开 ~12 个方法（Client 端 + Server 端），注册相关 20+ 方法收入 internal
- **SDK 不需要 OAuth2** — OAuth2 是控制台后端调 CNNIC 写接口用的；SDK 只调公开只读的 TL 查询接口（Gold 级）和 DNS

## 外部依赖与通信接口

### Go Module 直接依赖

| 依赖 | 用途 | 是否保留 |
|------|------|---------|
| `github.com/miekg/dns` | DNS 查询（TXT / TLSA / DNSSEC） | 保留 |
| `github.com/spf13/cobra` | CLI 命令行框架 | 保留（CLI 精简后可能移除） |
| `github.com/spf13/viper` | CLI 配置管理 | 同上 |

### SDK 需要通信的外部服务

| 接口 | 通信对象 | 地址 | 协议 | 认证方式 | SDK 使用场景 |
|------|---------|------|------|---------|-------------|
| CNNIC TL 查询 | CNNIC 透明日志服务 | `https://tl.ansagent.cn:8180/ans/api/v1` | HTTPS | 无（公开只读，透明日志设计原则） | Gold 验证：获取 TL 日志 + Merkle proof |
| CNNIC RA API | CNNIC 注册服务 | `https://ra.ansagent.cn:8180/ans/api/v1` | HTTPS | OAuth2 (Bearer JWT) | **SDK 不调用** — 控制台后端调用 |
| Agent-to-Agent | 目标 Agent 端点 | 动态（按 host） | **mTLS**（双向证书） | Identity Certificate | CallAgent() 核心通信 |
| DNS 递归解析器 | DNS 服务 | `8.8.8.8:53`（可配置） | UDP/TCP DNS 明文 | 无（DNSSEC 验证完整性） | _ati / _ati-badge / TLSA 查询 |
| Agent Card 端点 | Agent 主机 | 动态（从 _ati TXT url） | HTTPS | 无 | mode=card 时获取元数据 |

### 加密传输总结

| 通道 | 加密 | 认证 | 完整性 |
|------|------|------|--------|
| SDK → CNNIC TL（查询） | TLS 1.2+ | 仅服务端证书（公开只读，无需客户端认证） | TLS |
| SDK → Agent（mTLS） | TLS 1.2+ | **双向证书认证**（双方互出 Identity Cert） | TLS |
| SDK → DNS | 明文 | 无 | DNSSEC 签名验证（二期） |

> ⚠️ DNS 查询是唯一无加密通道。DNSSEC 保证数据完整性但不保证隐私。如需 DNS 隐私可考虑 DoH/DoT（PRD 未要求）。

### 认证职责划分

| 角色 | 调用对象 | 认证方式 | 说明 |
|------|---------|---------|------|
| **SDK Client 端** | 目标 Agent 端点 | mTLS（出示自己的 Identity Cert） | 调用其他 Agent |
| **SDK Server 端** | 来访 Agent 的 Identity Cert | mTLS（验证对方 Identity Cert） | 被其他 Agent 调用 |
| **SDK**（Gold 级） | CNNIC TL 查询接口 | 无需认证（公开只读） | 透明日志：第三方可独立审计 |
| **SDK** | DNS | 无 | _ati TXT / TLSA 查询 |
| 控制台后端（非本项目） | CNNIC RA 写接口 | OAuth2 (client_credentials) | 注册/注销/实名 |
| 控制台后端（非本项目） | CNNIC TL 写接口 | OAuth2 (client_credentials) | 添加 TL 日志 |

> SDK 不调用任何需要 OAuth2 的写接口。SDK 的认证能力 = mTLS 双向证书，其他一切（OAuth2、API key）均不在 SDK 范围内。

### CNNIC 接口模式说明（SDK 相关部分）

SDK 只调用 CNNIC 的**同步只读**接口：
- `GET /tl/agents/{agentId}/logs/latest` — 同步返回，公开无认证，SDK Gold 验证使用

CNNIC 的**异步写接口**（注册、注销、实名、TL 写入）由控制台后端调用，与 SDK 无关：
- 调用写入接口 → 返回 `taskId` → 轮询 `GET /tasks/{taskId}` → `passed` / `unpass`
- 需要 OAuth2 认证
- SDK 代码中 `internal/` 下可保留相关方法供控制台后端 Go 服务复用（可选）

### CNNIC 接口协议字段差异

注意 CNNIC 接口中 `endpoint.protocol` 当前仅支持 `A2A`，而 PRD 要求支持 MCP / A2A / OpenAPI。MVP 阶段需确认：
- SDK 侧：protocol 字段作为 string 传递，不做枚举校验（兼容未来扩展）
- 控制台侧：PRD 的 MCP/OpenAPI 选项是否在 CNNIC 联调前可用

## 四大功能模块

### 模块一：证书管理（新增）

```go
// WithMTLSCerts 加载控制台下载的 4 个 PEM 文件
// 强校验：文件存在、格式正确、identity cert SAN 为 ati:// 开头
// 加载时检查证书有效期，30天内到期打 warning 日志
func WithMTLSCerts(identityCert, privateKey, serverCert, caBundle string) AgentClientOption
```

- 构建 tls.Config，配置双向 mTLS
- 错误信息说人话："identity.pem 不是有效的 X.509 证书" 而非 "x509: malformed"
- CertStatus() 方法返回证书剩余有效天数

ATIName 格式校验（PRD 5.5 Step 1）：
- 格式：`ati://v{major}.{minor}.{patch}.{agentHost}`
- 校验规则：scheme 必须为 `ati://`；version 部分须符合 semver；host 部分须为合法 FQDN
- Identity Certificate 的 URI SAN 必须匹配此格式，加载时强校验

### 模块二：Agent 发现（改造 + 新增）

#### _ati TXT 记录解析（PRD 6.4 / 6.6.1）：

```
_ati.{host} TXT "v=ati1; id={agentId}; ra=aliyun; version=v1.0.0; mode=card; url=https://..."
_ati.{host} TXT "v=ati1; id={agentId}; ra=aliyun; version=v1.0.0; p=mcp; mode=direct"
```

新字段（相比 GoDaddy ANS SDK）：
| 字段 | 说明 | 必需 |
|------|------|------|
| id | Agent ID（如 ag-39dd66） | 是 |
| ra | 签发 RA 标识符（如 aliyun） | 是 |
| version | 带 v 前缀的 semver | 是 |
| mode | card（获取元数据）/ direct（直连 FQDN） | 是 |
| p | 通信协议过滤（mcp / a2a / openapi），可选 | 否 |
| url | 元数据端点 URL（mode=card 时必需） | 条件必需 |

解析算法照搬 PRD 6.6.1：
1. 查所有 `_ati` TXT 记录
2. 按协议过滤（匹配 `p` 字段，无 `p` 字段的记录视为通配）
3. semver 排最高版本（或精确匹配客户端指定版本）
4. mode 分支：`card` → 获取 url 指向的元数据；`direct` → 直连 FQDN

MVP 实现 mode=card 和 mode=direct 两种模式（PRD 6.6 zone 示例同时展示两种）。

#### _ati-badge TXT 记录解析（PRD 6.5）：

```
_ati-badge.{host} TXT "v=ati-badge1; version=v1.0.0; url=https://tl.ansagent.cn:8180/ans/api/v1/tl/agents/{agentId}/logs/latest"
```

现有 `badge_record.go` 适配：
- `ans-badge1` → `ati-badge1`
- `version` 字段解析改为**必填**（PRD 6.5.1 明确标注"是"），缺失则返回解析错误
- URL 域名白名单更新为 `tl.ansagent.cn`（联调）/ 正式环境域名待确认

#### Trust Card 获取（PRD 11.2 / 11.3，全新）：

```go
func GetTrustCard(ctx context.Context, host string, version string) (*TrustCard, error)
```

Trust Card 是 Agent 的"可信名片"，由 **CNNIC 在注册时生成并托管**。

**获取路径（基于 CNNIC 接口规范）：**
1. 解析 `_ati` TXT 记录，获取 `id`（agentId）
2. 调用 CNNIC TL 接口：`GET /tl/agents/{agentId}/logs/latest`（需 OAuth2 认证）
3. 从响应的 `payload` 中提取 Trust Card 内容（注册时 CNNIC 根据 `trustCardHosted: true` 生成）

注意区分：
- **Agent Card**（元数据）：从 `_ati` TXT 的 `url` 字段获取，托管在 Agent 主机（如 `/.well-known/agent-card.json`）
- **Trust Card**（可信名片）：注册时由 CNNIC 生成，内容包含在 TL 日志中，通过 TL 查询接口获取

Trust Card 结构体（基于 CNNIC trustCardContent 字段定义）：
```go
type TrustCard struct {
    AgentID          string              `json:"agentId"`
    AgentName        string              `json:"agentName"`          // ati://v{ver}.{host}
    AgentDisplayName string              `json:"agentDisplayName"`
    AgentDescription string              `json:"agentDescription"`
    Version          string              `json:"version"`
    AgentHost        string              `json:"agentHost"`
    Endpoints        []TrustCardEndpoint `json:"endpoints"`
    SecuritySchemes  map[string]any      `json:"securitySchemes,omitempty"`  // CNNIC 暂不支持
    VerifiableClaims []map[string]any    `json:"verifiableClaims,omitempty"` // CNNIC 暂不支持
}

type TrustCardEndpoint struct {
    Protocol    string   `json:"protocol"`
    AgentURL    string   `json:"agentUrl"`
    MetadataURL string   `json:"metadataUrl,omitempty"`
    DocURL      string   `json:"docUrl,omitempty"`
    Transports  []string `json:"transports,omitempty"`
    Functions   []EndpointFunction `json:"functions,omitempty"`
}

type EndpointFunction struct {
    ID   string   `json:"id"`
    Name string   `json:"name"`
    Tags []string `json:"tags,omitempty"`
}
```

### 模块三：信任验证（改造）

三级验证（PRD 9.4）：

| 等级 | 验证内容 | 时间 | 对应现有代码 |
|------|---------|------|-------------|
| Bronze（默认） | DNS 发现（_ati TXT 存在）+ PKI（CA 链 + SAN 匹配） | MVP 7.30 | 全新路径 |
| Silver | Bronze + DANE（双 TLSA：`_443._tcp` + `_ati-identity._tls`） | 二期 9.1 | DANEVerifier 适配新前缀 |
| Gold | Silver + TL Merkle proof + seal 验签 | 二期 9.1 | 重写（SCITT → CNNIC TL） |

```go
// MVP：Bronze 是默认值，开发者无需显式配置
client, _ := ati.NewAgentClient(ati.WithMTLSCerts(...))

// 二期：显式提升验证等级
client, _ := ati.NewAgentClient(
    ati.WithMTLSCerts(...),
    ati.WithTrustLevel(ati.Silver),
)
```

Bronze 验证流程（MVP）：
1. 查询 `_ati.{host}` TXT 记录 → 确认对方是已注册的 ATI Agent（记录存在）
2. mTLS 握手 → 验证对方证书链由 CNNIC Private CA 签发
3. 提取对方 Identity Cert 的 URI SAN → 确认 `ati://v{ver}.{host}` 中的 host 与连接目标一致

> Bronze 不查 badge/TL，但**需要 DNS**——确保对方不仅有合法证书，还是在 ATI 系统中注册过的 Agent。

DANE 双 TLSA 命名（二期实现，但模型层 MVP 预埋）：
- Server TLSA：`_443._tcp.{host}`（现有 `Fqdn.TlsaName(port)` 已支持）
- Identity TLSA：`_ati-identity._tls.{host}`（新增，需扩展 Fqdn 模型）

#### Gold 级 Badge/TL 验证流程（二期，基于 CNNIC TL 接口）

基于 CNNIC `GET /tl/agents/{agentId}/logs/latest` 接口，Gold 验证完整流程如下：

```
Step 1: DNS 发现
    查询 _ati.{host} TXT → 提取 id（agentId）
    查询 _ati-badge.{host} TXT → 提取 url（TL 端点，可选校验用）

Step 2: 获取 TL 日志（公开只读，无需认证）
    GET https://tl.ansagent.cn:8180/ans/api/v1/tl/agents/{agentId}/logs/latest

Step 3: 验证 TL 封存签名（seal）
    3.1 取响应中 seal 对象
    3.2 将 status + schemaVersion + payload + evidenceRef 按 RFC8785-JCS 规范化
    3.3 计算 SHA-256 摘要
    3.4 用 CNNIC TL 公钥（seal.publicKey 或预置）验证 ECDSA 签名（seal.signature）

Step 4: 验证 Merkle Inclusion Proof
    4.1 取 merkleProof 对象
    4.2 从 leafHash + path 重建到 rootHash
    4.3 验证计算出的 rootHash == merkleProof.rootHash

Step 5: 证书指纹匹配
    5.1 取 payload.certificates.identityCertFingerprint（格式 "SHA-256:<hex>"）
    5.2 计算 TLS 握手中对方出示的 Identity Certificate 的 SHA-256 指纹
    5.3 比对一致
    5.4 （可选）比对 payload.certificates.serverCertFingerprint 与 Server Certificate

Step 6: 状态校验
    6.1 确认 payload.agentStatus == "ACTIVE"
    6.2 确认 status == "ACTIVE"（顶层字段）
```

对应 Go 结构体（TL 日志响应）：
```go
type TLLogResponse struct {
    Status        string        `json:"status"`
    SchemaVersion string        `json:"schemaVersion"`
    Payload       TLPayload     `json:"payload"`
    EvidenceRef   TLEvidenceRef `json:"evidenceRef"`
    Seal          TLSeal        `json:"seal"`
    MerkleProof   MerkleProof   `json:"merkleProof"`
}

type TLPayload struct {
    LogID            string          `json:"logId,omitempty"`
    EventType        string          `json:"eventType"`         // AGENT_REGISTERED / AGENT_UPDATED / AGENT_REVOKED
    Timestamp        string          `json:"timestamp"`
    AgentName        string          `json:"agentName"`         // ati://v{ver}.{host}
    AgentDisplayName string          `json:"agentDisplayName"`
    AgentHost        string          `json:"agentHost"`
    Version          string          `json:"version"`
    AgentID          string          `json:"agentId"`
    AgentStatus      string          `json:"agentStatus"`       // ACTIVE / REVOKED
    Certificates     *TLCertificates `json:"certificates,omitempty"`
}

type TLCertificates struct {
    ServerCertFingerprint   string `json:"serverCertFingerprint"`   // "SHA-256:<hex>"
    IdentityCertFingerprint string `json:"identityCertFingerprint"` // "SHA-256:<hex>"
}

type TLEvidenceRef struct {
    EvidenceID    string `json:"evidenceId"`
    SubmitterID   string `json:"submitterId"`
    EvidenceType  string `json:"evidenceType"`
    EvidenceURI   string `json:"evidenceUri"`
    EvidenceHash  string `json:"evidenceHash"`  // "SHA-256:<hex>"
    HashAlgorithm string `json:"hashAlgorithm"`
    HashTarget    string `json:"hashTarget"`
    ContentType   string `json:"contentType"`
}

type TLSeal struct {
    Canonicalization   string `json:"canonicalization"`   // RFC8785-JCS
    DigestAlgorithm    string `json:"digestAlgorithm"`   // SHA-256
    SignatureAlgorithm string `json:"signatureAlgorithm"` // SHA-256withECDSA
    SignatureEncoding  string `json:"signatureEncoding"`  // DER_BASE64
    KeyID              string `json:"keyId"`
    Signature          string `json:"signature"`
    PublicKey          string `json:"publicKey,omitempty"` // PEM 格式
}

type MerkleProof struct {
    LeafHash    string   `json:"leafHash"`
    LeafIndex   int64    `json:"leafIndex"`
    TreeSize    int64    `json:"treeSize"`
    TreeVersion int64    `json:"treeVersion"`
    Path        []string `json:"path"`
    RootHash    string   `json:"rootHash"`
}
```

与现有 GoDaddy SCITT 验证的对比：

| 维度 | GoDaddy ANS（现有） | CNNIC ATI（目标） |
|------|---------------------|-------------------|
| 日志格式 | SCITT Receipt (CBOR/COSE) | JSON + JCS 规范化 |
| 签名算法 | COSE Sign1 | SHA-256withECDSA (DER_BASE64) |
| 包含证明 | SCITT inclusion proof | Merkle path + rootHash |
| 认证方式 | 无（公开） | 预判公开只读（待确认） |
| 证书指纹 | badge.payload.fingerprint | payload.certificates.*Fingerprint |
| 状态字段 | badge.payload.status | payload.agentStatus + 顶层 status |

> 现有 `verify/tlog.go` 中的 SCITT 验证逻辑需要完全重写为 CNNIC TL 验证逻辑。核心差异：SCITT 用 CBOR/COSE，CNNIC 用 JSON/JCS/ECDSA。

### 模块四：安全通信（改造）

SDK 只做安全传输层：mTLS 连接 + DNS 发现 + 信任验证。用户自行按 MCP/A2A/OpenAPI 协议构造请求。

```go
// HTTP 方法（改造：加入 mTLS 客户端证书出示 + Bronze 验证）
func (c *AgentClient) Get(ctx, url string) (*Response, error)
func (c *AgentClient) Post(ctx, url string, body any) (*Response, error)
func (c *AgentClient) Put(ctx, url string, body any) (*Response, error)
func (c *AgentClient) Delete(ctx, url string) (*Response, error)
func (c *AgentClient) Do(ctx, method, url string, body any) (*Response, error)
func (c *AgentClient) Prefetch(ctx, host string) error
```

改造重点（Client 端 — 调用其他 Agent）：
- 现有代码只验服务端证书（badge 指纹比对），不出示客户端证书
- ATI 改造后：`tls.Config.Certificates` 加载 Identity Cert + Private Key → mTLS 客户端认证
- ATI 改造后：`tls.Config.RootCAs` 加载 CNNIC CA bundle → 验证对方 Identity Cert 信任链
- 验证逻辑从 badge 指纹比对改为 Bronze PKI（DNS + CA 链 + SAN 匹配）

#### Server 端能力（新增 — 被其他 Agent 调用时验证对方）

SDK 同时提供 Server 端 mTLS 验证能力，用于 Agent 接收其他 Agent 的调用时验证对方身份。

```go
// 生成 Server 端 tls.Config（配置到 http.Server 或框架中间件）
func NewServerTLSConfig(opts ...ServerOption) (*tls.Config, error)

// Server 端选项
func WithServerCert(serverCert, privateKey string) ServerOption   // 你的 Server Certificate
func WithClientCA(caBundle string) ServerOption                    // CNNIC CA bundle（验证客户端）
func WithClientVerifier(level TrustLevel) ServerOption            // 客户端验证等级

// 验证结果提取（从 TLS 连接状态中提取对方身份）
func PeerATIName(tlsState *tls.ConnectionState) (*AtiName, error)
```

使用示例：
```go
tlsConfig, _ := ati.NewServerTLSConfig(
    ati.WithServerCert("./certs/server.pem", "./certs/key.pem"),
    ati.WithClientCA("./certs/cnnic_ca_bundle.pem"),
)

server := &http.Server{
    Addr:      ":443",
    TLSConfig: tlsConfig,
    Handler:   myHandler,
}
server.ListenAndServeTLS("", "")

// 在 handler 中提取对方身份
func myHandler(w http.ResponseWriter, r *http.Request) {
    peerName, _ := ati.PeerATIName(r.TLS)
    // peerName.Host = "caller.example.com"
    // peerName.Version = "1.0.0"
}
```

Server 端验证逻辑（Bronze）：
1. TLS 握手时要求客户端出示证书（`tls.Config.ClientAuth = tls.RequireAndVerifyClientCert`）
2. 验证客户端 Identity Cert 由 CNNIC CA 签发
3. 提取 URI SAN `ati://v{ver}.{host}` 确认格式合法
4. （可选）查询 `_ati.{host}` TXT 确认对方已注册

现有代码基础：`verify/` 包中已有 `ClientVerifier`（server 验证 client），需改造为 CNNIC CA 信任链验证。

### 诊断（新增，Nice-to-have）

```go
func Diagnose(ctx context.Context, host string, opts ...Option) (*DiagnoseResult, error)
```

- 跑完整验证链路，逐步输出：DNS 解析 → Badge 获取 → 证书匹配 → mTLS 握手
- 默认脱敏（指纹前 8 位，不打印私钥路径）
- .String() 人类可读 / .JSON() 结构化输出

> 注：PRD 中无此需求，属于 SDK 开发者体验自主决策。如工期紧张可延后至二期。

## 公开 API 清单（~10 个入口）

| API | 角色 | 说明 |
|-----|------|------|
| NewAgentClient(opts...) | Client | 创建客户端（加载证书、配置验证等级） |
| WithMTLSCerts(identity, key, server, ca) | Client | 证书配置（mTLS 双向认证） |
| WithTrustLevel(level) | Client | 验证等级（默认 Bronze，二期支持 Silver/Gold） |
| AgentClient.Get/Post/Put/Delete/Do | Client | HTTP 方法（内置 mTLS + 信任验证） |
| AgentClient.Prefetch(host) | Client | 预取 Badge（Gold 验证时有用） |
| AgentClient.CertStatus() | Client | 证书有效期检查 |
| NewServerTLSConfig(opts...) | Server | 生成 Server 端 mTLS tls.Config |
| WithServerCert(cert, key) | Server | 配置 Server Certificate |
| WithClientCA(caBundle) | Server | 配置 CNNIC CA bundle 验证客户端 |
| PeerATIName(tlsState) | Server | 从 TLS 连接中提取对方 ATI 身份 |
| GetTrustCard(ctx, host, version) | 通用 | 获取 Trust Card（从 CNNIC TL） |
| Diagnose(ctx, host, opts...) | 通用 | 诊断（Nice-to-have） |

注册相关方法（RegisterAgent/VerifyACME/SubmitCSR 等 14 个）移入 internal/，不对外暴露。

> 关于 WithProfile / GoDaddyProfile：PRD 无 GoDaddy ANS 兼容性要求。如需保留过渡期双模支持，应作为 internal 实现细节，不暴露为公开 API。MVP 公开 API 仅面向 ATI。

## 硬编码替换清单（10 项）

| # | 项 | 文件 | 当前 → 目标 |
|---|---|------|------------|
| 1 | Module path | go.mod | github.com/godaddy/ans-sdk-go → gitlab.alibaba-inc.com/alibaba-dns/ati-golang-sdk |
| 2 | TL URL | transparency.go:27 | → `https://tl.ansagent.cn:8180/ans/api/v1`（联调） |
| 3 | DNS badge 前缀 | fqdn.go:59 | _ans-badge. → _ati-badge. |
| 4 | DNS discovery 前缀 | 新增 | _ati.（含 id/ra/version/mode/p/url 字段解析） |
| 5 | Badge 版本标识 | badge_record.go:25 | ans-badge1 → ati-badge1 |
| 6 | URL 白名单 | url_validator.go:13-14 | → `tl.ansagent.cn`（联调）/ 正式域名待确认 |
| 7 | URI scheme | cert.go:102 | ans:// → ati:// |
| 8 | Identity TLSA 前缀 | fqdn.go（新增方法） | 新增 `_ati-identity._tls.{host}` 命名生成 |
| 9 | CLI | root.go | ans-cli/ANS_ → ati-cli/ATI_ |
| 10 | Auth | options.go | sso-jwt/sso-key → WithAccessKey() |

## 全量 ANS → ATI 重命名清单

除硬编码替换外，所有源码中的 `ans`/`ANS`/`Ans` 标识符需统一替换为 `ati`/`ATI`/`Ati`。以下为完整清单：

### 目录 / 文件重命名

| 当前路径 | 目标路径 |
|---------|---------|
| `ans/` | `ati/` |
| `cmd/ans-cli/` | `cmd/ati-cli/` |

### Package 声明

| 文件 | 当前 | 目标 |
|------|------|------|
| ati/*.go（原 ans/*.go） | `package ans` | `package ati` |
| cmd/ati-cli/cmd/*.go | import path 含 `ans-cli` | 替换为 `ati-cli` |

### Import Path 全局替换

```
github.com/godaddy/ans-sdk-go  →  gitlab.alibaba-inc.com/alibaba-dns/ati-golang-sdk
```

涉及所有 .go 文件的 import 块（约 60+ 处）。

### 类型 / 结构体重命名

| 包 | 当前 | 目标 | 文件 |
|----|------|------|------|
| verify | `AnsVerifier` | `AtiVerifier` | verify/verify.go |
| verify | `AnsName` | `AtiName` | verify/cert.go |
| verify | `AnsNameParts` | `AtiNameParts` | verify/cert.go |
| verify | `AnsBadgeRecord` | `AtiBadgeRecord` | verify/badge_record.go |
| verify | `AnsAgentOutcome` | `AtiAgentOutcome` | verify/outcome.go |
| verify | `AnsNameMismatch` | `AtiNameMismatch` | verify/outcome.go |
| verify | `AnsNameMismatchOutcome` | `AtiNameMismatchOutcome` | verify/outcome.go |
| models | `AnsAgent` | `AtiAgent` | models/agent.go |

### 常量 / 枚举重命名

| 包 | 当前 | 目标 | 文件 |
|----|------|------|------|
| verify | `BadgeRecordSourceAnsBadge` | `BadgeRecordSourceAtiBadge` | verify/badge_record.go |
| verify | `BadgeRecordSourceRaBadge` | `BadgeRecordSourceRaBadge`（保留，RA 不变） | verify/badge_record.go |

### 函数重命名

| 包 | 当前 | 目标 | 文件 |
|----|------|------|------|
| verify | `ParseAnsBadgeRecord()` | `ParseAtiBadgeRecord()` | verify/badge_record.go |
| verify | `ParseAnsName()` | `ParseAtiName()` | verify/cert.go |
| verify | `NewAnsVerifier()` | `NewAtiVerifier()` | verify/verify.go |
| models | `Fqdn.AnsBadgeName()` | `Fqdn.AtiBadgeName()` | models/fqdn.go |

### 结构体字段 + JSON Tag 重命名

| 包 | 结构体 | 当前字段 | 目标字段 | JSON Tag |
|----|--------|---------|---------|----------|
| models | Agent / AgentDetails / AgentRegistration | `ANSName string` | `ATIName string` | `json:"atiName"` |
| models | Badge Event | `ANSID string` | `ATIID string` | `json:"atiId"` |
| models | Badge Event | `ANSName string` | `ATIName string` | `json:"atiName"` |
| models | TransparencyLogV0 | `ANSID string` | `ATIID string` | `json:"atiId"` |
| models | TransparencyLogV0 | `ANSName string` | `ATIName string` | `json:"atiName"` |
| models | TransparencyLogV1 | `ANSName string` | `ATIName string` | `json:"atiName"` |
| models | TransparencyLogV1 | `ANSCapabilities []string` | `ATICapabilities []string` | `json:"atiCapabilities"` |
| models | TransparencyLogV1 | `ANSCapabilitiesHash *string` | `ATICapabilitiesHash *string` | `json:"atiCapabilitiesHash"` |
| models | RevocationStatus | `AnsName string` | `AtiName string` | `json:"atiName"` |
| models | ResolutionResult | `AnsName string` | `json:"atiName"` |
| models | Event | `AnsName string` | `AtiName string` | `json:"atiName"` |

### 环境变量 / CLI Flag

| 当前 | 目标 | 位置 |
|------|------|------|
| `ANS_API_KEY` | `ATI_API_KEY` | cmd/ati-cli/cmd/root.go |
| `ANS_API_SECRET` | `ATI_API_SECRET` | cmd/ati-cli/cmd/root.go |
| `ANS_BASE_URL` | `ATI_BASE_URL` | cmd/ati-cli/cmd/root.go |
| `ANS_TRANSPARENCY_URL` | `ATI_TRANSPARENCY_URL` | cmd/ati-cli/cmd/badge.go |

### 字符串字面量

| 当前 | 目标 | 位置 |
|------|------|------|
| `"ans://"` | `"ati://"` | verify/cert.go |
| `"ans-badge1"` | `"ati-badge1"` | verify/badge_record.go |
| `"_ans-badge."` | `"_ati-badge."` | models/fqdn.go |
| `"transparency.ans.godaddy.com"` | `"tl.ansagent.cn:8180"` | verify/url_validator.go, ans/transparency.go |
| `"transparency.ans.ote-godaddy.com"` | 删除（联调与正式用同域名，通过 hosts 切换） | verify/url_validator.go |
| `"https://api.godaddy.com"` | `"https://ra.ansagent.cn:8180/ans/api/v1"`（CNNIC RA） | ans/options.go |
| `"https://api.ote-godaddy.com"` | 删除（联调环境通过 hosts 解析 42.83.147.217） | cmd/ati-cli/cmd/root.go |
| `"ANS Name:"` / `"ANSName:"` | `"ATI Name:"` / `"ATIName:"` | cmd 输出 |
| `"API key is required. Set --api-key flag or ANS_API_KEY"` | 替换为 ATI_API_KEY | cmd 多处 |

### 注释 / 文档字符串

所有 .go 文件中的注释里出现的 `ANS`/`ans`/`Ans`（指代 Agent Name Service）统一替换为 `ATI`/`ati`/`Ati`。保留 `Answer` 等普通英文单词不替换。

### 执行策略

建议顺序：
1. 先重命名目录（`ans/` → `ati/`，`cmd/ans-cli/` → `cmd/ati-cli/`）
2. 全局 sed 替换 import path（`github.com/godaddy/ans-sdk-go` → `gitlab.alibaba-inc.com/alibaba-dns/ati-golang-sdk`）
3. 全局 sed 替换标识符（按以下优先级避免误伤）：
   - `ANSName` → `ATIName`（大写缩写）
   - `ANSID` → `ATIID`
   - `ANSCapabilities` → `ATICapabilities`
   - `ANS_` → `ATI_`（环境变量前缀）
   - `AnsVerifier` → `AtiVerifier`（驼峰）
   - `AnsName` → `AtiName`
   - `AnsBadge` → `AtiBadge`
   - `ParseAns` → `ParseAti`
   - `NewAns` → `NewAti`
   - `ans://` → `ati://`（URI scheme）
   - `ans-badge` → `ati-badge`（DNS 前缀 / 版本标识）
   - `ans-sdk` → `ati-sdk`
   - `ans-cli` → `ati-cli`
   - `_ans-` → `_ati-`（DNS TXT 前缀）
   - `package ans` → `package ati`
4. 手动检查：`Answer`、`transport`、`Transparent` 等含 `ans` 子串的单词不应被误替换
5. 运行 `go build ./...` 验证编译通过
6. 运行 `go test ./...` 验证测试通过

### JSON Tag 兼容性说明

> ⚠️ JSON tag 改动（如 `"ansName"` → `"atiName"`）意味着与 CNNIC / 阿里云后端 API 的 JSON 协议变更。需与后端确认接口字段名是否同步改为 `atiName`/`atiId` 等。如后端暂未改动，可先保留 JSON tag 不变，仅改 Go 字段名。

## 执行计划（12-18 天）

| 周 | 工作 | 预估 | 依赖 CNNIC |
|----|------|------|-----------|
| W1 | Module path + 硬编码替换（#1-#10） | 2-3d | 部分（TL URL） |
| W1 | WithMTLSCerts() + CertStatus() + ATIName 校验 | 1-2d | 否 |
| W1 | AK/SK 认证 + API 收窄（internal 化注册方法） | 2d | 否 |
| W2 | Bronze 验证路径（全新） | 2-3d | 否 |
| W2 | _ati 记录解析（含 p 字段）+ _ati-badge 适配 | 2d | 否（格式 PRD 已定义） |
| W2 | Trust Card 获取 + WithTrustLevel() | 1-2d | 否 |
| W3 | Diagnose()（如工期允许）+ CLI 精简 | 1-2d | 否 |
| W3 | 单元测试 + 文档 | 2-3d | 否 |

不依赖 CNNIC 的工作占 80%+，可立即开工。

## 已确认决策（Design Decisions）

| # | 决策 | 来源 |
|---|------|------|
| D1 | Module path = `gitlab.alibaba-inc.com/alibaba-dns/ati-golang-sdk` | 与用户确认 |
| D2 | TL base URL = `https://tl.ansagent.cn:8180/ans/api/v1`（联调 IP 42.83.147.217） | CNNIC 接口文档 v0.3 |
| D3 | TL 查询公开只读，SDK 不需要 OAuth2 | GoDaddy 协议同理 + 透明日志设计原则 |
| D4 | SDK 只做安全传输层，不封装 MCP/A2A/OpenAPI 应用协议（无 CallAgent） | 与用户确认 |
| D5 | SDK 提供 Client + Server 双端能力 | 与用户确认 |
| D6 | Bronze 验证需要查 DNS（_ati TXT 存在）+ PKI（CA 链 + SAN 匹配） | 与用户确认 |
| D7 | Trust Card schema 已确认（CNNIC trustCardContent 字段定义） | CNNIC 接口文档 v0.3 |
| D8 | SDK 不需要 OAuth2 — OAuth2 是控制台后端调 CNNIC 写接口用的 | 架构分析 |
| D9 | 现有代码无 mTLS 客户端证书能力，WithMTLSCerts 为全新实现 | 代码审查 |

## 开放问题（仅剩余未阻塞 MVP 的问题）

| # | 问题 | 紧急度 | 说明 |
|---|------|--------|------|
| 1 | PRD 内部矛盾：2.1 MVP 提及"DNSSEC 验证"，但 2.2/9.4 将 DNSSEC 归入二期(Silver) | 🟡 | 不阻塞 MVP — Bronze 不需要 DNSSEC |
| 2 | _ati TXT `p` 字段取值：CNNIC 接口 endpoint.protocol 目前仅支持 A2A，PRD 要求 MCP/A2A/OpenAPI | 🟡 | SDK 不校验枚举值，string 传递即可 |
| 3 | CNNIC TL 封存签名验证细节：公钥发布渠道、RFC8785-JCS Go 库选型 | 🟢 | 二期 Gold 才需要 |
| 4 | 多语言 SDK 是否同步开发（Go 优先，Java/Rust 排期？） | 🟢 | 不影响 Go SDK 开发 |

## 明确不做

| 项 | 原因 |
|----|------|
| SDK 注册 API | PRD 5.1：控制台注册 |
| CallAgent() 高级 RPC 封装 | SDK 只做传输层，不封装 MCP/A2A/OpenAPI 协议 |
| OAuth2 认证逻辑 | 控制台后端调 CNNIC 写接口才需要，SDK 不调写接口 |
| DNS 写入 / 传播检查 | 控制台/云解析负责 |
| CLI 注册命令 | 控制台做 |
| 双模 Trust Card fallback | 破坏信任模型 |
| GoDaddy Profile 公开 API | PRD 无兼容性要求，如需过渡放 internal |
| 蚂蚁链锚定 | V2 候选 |
| Trust Score API | 用 Diagnose() 替代 |
| SDK WithProxy() | Go stdlib HTTPS_PROXY 已支持 |
| DryRun 模式 | 用 Diagnose() 替代 |

## MVP 联调最小依赖

Bronze 验证（MVP）联调所需外部依赖：

| 依赖项 | 说明 | 如何获取 |
|--------|------|---------|
| CNNIC Private CA 根证书 PEM | 信任锚，验证对方 Identity Cert 签发链 | 找 CNNIC 要 |
| 一套 CNNIC 签发的测试证书 | identity.pem + key.pem（通过控制台注册流程获得） | 控制台注册后下载 |
| 测试域名 | 能控制 DNS 的域名，配好 `_ati` TXT 记录 | 自行准备 |
| 一个 mTLS Agent 端点 | 对端也配了 CNNIC 证书，用于验证双向握手 | 本地自建 or 联调环境 |

不需要：
- ~~OAuth2 账号~~ — SDK 不调写接口
- ~~CNNIC TL 服务~~ — Bronze 不查 TL
- ~~DNSSEC~~ — Bronze 不做 DNSSEC 验证
