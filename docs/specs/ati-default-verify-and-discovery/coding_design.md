# ATI-Golang-SDK 编码方案设计

> 对应需求规格：[ati-golang-sdk-spec.md](specs/ati-golang-sdk-spec.md)

---

## 1. 整体架构

```
ati/                          ← 公共 API 层（新建）
├── client.go                 ← AgentClient：mTLS HTTP 客户端
├── server.go                 ← ServerTLSConfig：服务端 TLS 配置
├── policy.go                 ← VerificationPolicy 枚举 + 默认值
├── discovery.go              ← AgentDiscoverer 接口 + 组合发现器
├── options.go                ← 所有 functional options
└── types.go                  ← AgentInfo, DiscoverySource 等公共类型

internal/registry/            ← RA API 客户端（新建）
├── client.go                 ← RAClient：阿里云 OpenAPI SDK 封装
├── options.go                ← RAClient 配置选项
├── models.go                 ← 请求/响应模型
└── discoverer.go             ← RAAPIDiscoverer：基于 RA API 的发现器

verify/                       ← 已有验证引擎（修改）
├── verify.go                 ← 修改 badge URL 构造逻辑
├── options.go                ← 新增 WithTLBaseURL 等选项
├── url_validator.go          ← 新增 BuildBadgeURL 函数
└── dns_discoverer.go         ← 新建：DNSDiscoverer 适配器
```

---

## 2. 模块详细设计

### 2.1 验证策略（FR-1）

**文件**：`ati/policy.go`

```go
package ati

type VerificationPolicy int

const (
    PolicyNone          VerificationPolicy = iota // 仅 TLS 握手
    PolicyPKIOnly                                 // CA 链 + SAN 匹配（需 ca_bundle）
    PolicyBadgeRequired                           // badge 透明日志指纹验证 + PKI（需 ca_bundle）
    PolicyFull                                    // badge + DANE + PKI（需 ca_bundle）
)
```

**Badge URL 构造逻辑改造**：`verify/url_validator.go`

现有 `RewriteBadgeURLHost()` 直接替换 host。新增 `BuildBadgeURL()` 函数实现 path+port 提取拼接：

```go
// BuildBadgeURL 从 badge TXT 的 URL 中提取 path 和 port，
// 与配置的 TL base_url 拼接，构造最终查询地址。
func BuildBadgeURL(badgeRawURL string, tlBaseURL string) (string, error) {
    badgeURL, err := url.Parse(badgeRawURL)
    if err != nil { return "", err }

    baseURL, err := url.Parse(tlBaseURL)
    if err != nil { return "", err }

    // 提取 badge URL 的 port
    port := badgeURL.Port()
    if port == "" { port = "443" }

    // 构造：base_host:badge_port + badge_path
    host := baseURL.Hostname()
    result := &url.URL{
        Scheme: "https",
        Host:   net.JoinHostPort(host, port),
        Path:   badgeURL.Path,
    }
    return result.String(), nil
}
```

**对 `verify/verify.go` 的改造点**：

`ServerVerifier.Verify()` 和 `ClientVerifier.Verify()` 中获取 badge URL 后，调用 `BuildBadgeURL()` 替代原来的 `RewriteBadgeURLHost()`。改造位于：
- `ServerVerifier.Verify()` 第 ~120 行：badge URL 获取后的重写逻辑
- `ClientVerifier.Verify()` 第 ~280 行：同上

`verifierConfig` 新增字段：

```go
type verifierConfig struct {
    // ... 现有字段 ...
    tlBaseURL           string // TL 基础 URL，默认 "https://tl.ansagent.cn"
    verificationPolicy  VerificationPolicy // 验证策略，默认 PolicyBadgeRequired
}
```

`defaultConfig()` 新增默认值：
```go
func defaultConfig() *verifierConfig {
    return &verifierConfig{
        // ... 现有默认值 ...
        tlBaseURL:          "https://tl.ansagent.cn",
        verificationPolicy: PolicyBadgeRequired,
    }
}
```

新增 Option：
```go
func WithTLBaseURL(url string) Option {
    return func(c *verifierConfig) { c.tlBaseURL = url }
}

func WithVerificationPolicy(p VerificationPolicy) Option {
    return func(c *verifierConfig) { c.verificationPolicy = p }
}
```

---

### 2.2 统一 Agent 发现接口（FR-2）

**文件**：`ati/discovery.go`

```go
package ati

type DiscoverySource int
const (
    SourceDNS   DiscoverySource = iota
    SourceRAAPI
)

type AgentInfo struct {
    FQDN       string
    AgentID    string
    BadgeURL   string
    RAEndpoint string
    Endpoints  []AgentEndpoint    // 从 DescribeAgentMarketPopResult 获取
    TrustLevel string             // 从 DescribeAgentMarketPopResult 获取
    Categories []string           // 从 DescribeAgentMarketPopResult 获取
    Version    string
    Protocol   string
    Mode       string
    Source     DiscoverySource
}

type AgentDiscoverer interface {
    Discover(ctx context.Context, fqdn string) (*AgentInfo, error)
    DiscoverWithOptions(ctx context.Context, fqdn string, opts ...DiscoverOption) (*AgentInfo, error)
}
```

**DNS 发现器适配**：`verify/dns_discoverer.go`

将现有 `DNSResolver` 适配为 `AgentDiscoverer` 接口：

```go
type DNSDiscoverer struct {
    resolver DNSResolver
}

func NewDNSDiscoverer(resolver DNSResolver) *DNSDiscoverer {
    return &DNSDiscoverer{resolver: resolver}
}

func (d *DNSDiscoverer) Discover(ctx context.Context, fqdn string) (*AgentInfo, error) {
    // 1. 查询 _ati TXT 获取 agent ID, ra endpoint, version, protocol, mode
    // 2. 查询 _ati-badge TXT 获取 badge URL
    // 3. 组装 AgentInfo 返回
}
```

**RA API 发现器**：`internal/registry/discoverer.go`

```go
type RAAPIDiscoverer struct {
    client *RAClient
}

func NewRAAPIDiscoverer(client *RAClient) *RAAPIDiscoverer {
    return &RAAPIDiscoverer{client: client}
}

func (d *RAAPIDiscoverer) Discover(ctx context.Context, fqdn string) (*AgentInfo, error) {
    // 通过 RA API 按 FQDN 查询 Agent 信息
}
```

**组合发现器**：`ati/discovery.go`

```go
type CompositeDiscoverer struct {
    primary  AgentDiscoverer // 默认 DNS
    fallback AgentDiscoverer // 可选 RA API
}

func NewCompositeDiscoverer(primary AgentDiscoverer, fallback AgentDiscoverer) *CompositeDiscoverer {
    return &CompositeDiscoverer{primary: primary, fallback: fallback}
}

func (c *CompositeDiscoverer) Discover(ctx context.Context, fqdn string) (*AgentInfo, error) {
    info, err := c.primary.Discover(ctx, fqdn)
    if err != nil && c.fallback != nil {
        return c.fallback.Discover(ctx, fqdn)
    }
    return info, err
}
```

---

### 2.3 阿里云 OpenAPI SDK 集成（FR-3）

**文件**：`internal/registry/ra_client.go`

```go
package registry

import (
    openapi "github.com/alibabacloud-go/darabonba-openapi/v2/client"
    openapiutil "github.com/alibabacloud-go/openapi-util/service"
    "github.com/alibabacloud-go/tea/dara"
    "github.com/aliyun/credentials-go/credentials"
)

type RAClient struct {
    client   *openapi.Client
    endpoint string
}

func NewRAClient(opts ...RAClientOption) (*RAClient, error) {
    // ... AK/SK 凭证创建和 OpenAPI 客户端初始化 ...
}
```

**API 方法**：POP RPC 泛化调用 `DescribeAgentRegisterInfoMarket`

```go
func (c *RAClient) DescribeAgentRegisterInfoMarket(ctx context.Context, agentHost string, agentVersion string) (*DescribeAgentMarketPopResult, error) {
    params := &openapi.Params{
        Action:      dara.String("DescribeAgentRegisterInfoMarket"),
        Version:     dara.String("2015-01-09"),
        Protocol:    dara.String("HTTPS"),
        Pathname:    dara.String("/"),
        Method:      dara.String("POST"),
        AuthType:    dara.String("AK"),
        Style:       dara.String("RPC"),
        ReqBodyType: dara.String("formData"),
        BodyType:    dara.String("json"),
    }

    queries := map[string]interface{}{
        "AgentHost": agentHost,
    }
    if agentVersion != "" {
        queries["AgentVersion"] = agentVersion
    }

    request := &openapi.OpenApiRequest{
        Query: openapiutil.Query(queries),
    }

    // callApiWithContext 传播 context deadline
    resp, err := c.callApiWithContext(ctx, params, request, runtime)
    // ...
}
```

**配置选项**：`internal/registry/ra_options.go`

```go
type raConfig struct {
    accessKeyID     string
    accessKeySecret string
    endpoint        string
}

func defaultRAConfig() *raConfig {
    return &raConfig{
        endpoint: "alidns.aliyuncs.com",
    }
}
```

**响应模型**：`internal/registry/ra_models.go`

```go
type DescribeAgentMarketPopResult struct {
    RequestId  string                `json:"RequestId"`
    AgentHost  string                `json:"AgentHost"`
    AgentId    string                `json:"AgentId"`
    Version    string                `json:"Version"`
    TrustLevel string                `json:"TrustLevel"`
    Categories []string              `json:"Categories"`
    Endpoints  []MarketAgentEndpoint `json:"Endpoints"`
    BadgeUrl   string                `json:"BadgeUrl"`
    Mode       string                `json:"Mode"`
    Status     string                `json:"Status"`
}

type MarketAgentEndpoint struct {
    Host     string `json:"Host"`
    Port     int    `json:"Port"`
    Protocol string `json:"Protocol"`
    Weight   int    `json:"Weight"`
}
```

**go.mod 依赖**（已为 direct）：
- `github.com/alibabacloud-go/darabonba-openapi/v2`
- `github.com/alibabacloud-go/openapi-util`
- `github.com/aliyun/credentials-go`

---

### 2.4 客户端/服务端默认验证行为（FR-4）

**文件**：`ati/client.go`

```go
package ati

type AgentClient struct {
    httpClient *http.Client
    verifier   *verify.AnsVerifier
    policy     VerificationPolicy
    discoverer AgentDiscoverer
    tlBaseURL  string
}

func NewAgentClient(opts ...ClientOption) (*AgentClient, error) {
    cfg := defaultClientConfig()
    for _, opt := range opts {
        opt(cfg)
    }

    // 默认 policy = PolicyBadgeRequired
    // 构建 TLS 配置
    tlsConfig := &tls.Config{
        MinVersion:   tls.VersionTLS13,
        Certificates: []tls.Certificate{cfg.identity},
        RootCAs:      cfg.caPool,
    }

    // 配置 VerifyConnection 回调
    tlsConfig.VerifyConnection = func(state tls.ConnectionState) error {
        switch cfg.policy {
        case PolicyNone:
            return nil
        case PolicyPKIOnly:
            return verifyPKI(state)
        case PolicyBadgeRequired:
            return verifyPKIAndBadge(state, cfg)
        case PolicyFull:
            return verifyFull(state, cfg)
        }
        return nil
    }

    return &AgentClient{
        httpClient: &http.Client{Transport: &http.Transport{TLSClientConfig: tlsConfig}},
        policy:     cfg.policy,
        discoverer: cfg.discoverer,
        tlBaseURL:  cfg.tlBaseURL,
    }, nil
}
```

**文件**：`ati/server.go`

```go
package ati

func NewServerTLSConfig(opts ...ServerOption) (*tls.Config, error) {
    cfg := defaultServerConfig()
    for _, opt := range opts {
        opt(cfg)
    }

    tlsConfig := &tls.Config{
        MinVersion:   tls.VersionTLS13,
        Certificates: []tls.Certificate{cfg.serverCert},
    }

    // ignore_check_client 开关：跳过 server 对 client 证书的校验
    if cfg.ignoreCheckClient {
        tlsConfig.ClientAuth = tls.NoClientCert
        return tlsConfig, nil
    }

    // 默认 PolicyNone → 不要求客户端证书
    switch cfg.clientPolicy {
    case PolicyNone:
        tlsConfig.ClientAuth = tls.NoClientCert
    case PolicyPKIOnly:
        // PKI 验证必须有 ca_bundle
        if cfg.clientCAPool == nil {
            return nil, fmt.Errorf("PolicyPKIOnly requires ca_bundle (clientCAPool)")
        }
        tlsConfig.ClientAuth = tls.RequireAndVerifyClientCert
        tlsConfig.ClientCAs = cfg.clientCAPool
        if cfg.verifyConn != nil {
            tlsConfig.VerifyConnection = cfg.verifyConn
        }
    case PolicyBadgeRequired, PolicyFull:
        // ca_bundle 为必传，用于 PKI 验证
        if cfg.clientCAPool == nil {
            return nil, fmt.Errorf("... requires ca_bundle (clientCAPool)")
        }
        tlsConfig.ClientAuth = tls.RequireAndVerifyClientCert
        tlsConfig.ClientCAs = cfg.clientCAPool
        if cfg.verifyConn != nil {
            tlsConfig.VerifyConnection = cfg.verifyConn
        }
    }

    return tlsConfig, nil
}
```

**默认配置**：

```go
func defaultClientConfig() *clientConfig {
    return &clientConfig{
        policy:    PolicyBadgeRequired, // 客户端默认 badge 验证
        tlBaseURL: "https://tl.ansagent.cn",
    }
}

func defaultServerConfig() *serverConfig {
    return &serverConfig{
        clientPolicy: PolicyNone, // 服务端默认不验证客户端
    }
}
```

---

## 3. 依赖关系

```
ati/client.go    → verify/verify.go (AnsVerifier)
                 → ati/discovery.go (AgentDiscoverer)
                 → ati/policy.go (VerificationPolicy)

ati/server.go    → verify/verify.go (ClientVerifier)
                 → ati/policy.go (VerificationPolicy)

ati/discovery.go → verify/dns_discoverer.go (DNSDiscoverer)
                 → internal/registry/discoverer.go (RAAPIDiscoverer)

internal/registry/client.go → alibabacloud-go/darabonba-openapi
                             → aliyun/credentials-go

verify/verify.go → verify/url_validator.go (BuildBadgeURL)
verify/url_validator.go → verify/options.go (tlBaseURL)
```

---

## 4. 测试策略

| 模块 | 测试类型 | 要点 |
|------|---------|------|
| `ati/policy.go` | 单元测试 | 枚举值正确性、默认策略验证 |
| `verify/url_validator.go` | 单元测试 | `BuildBadgeURL` 各种输入组合（含 port/无 port、特殊 path） |
| `verify/verify.go` | 单元测试 | badge URL 构造调用 `BuildBadgeURL` 而非 `RewriteBadgeURLHost` |
| `ati/client.go` | 单元测试 + Mock | 默认 PolicyBadgeRequired 生效、不同策略的 TLS 配置 |
| `ati/server.go` | 单元测试 + Mock | 默认 PolicyNone → NoClientCert；PolicyBadgeRequired/PolicyFull + 有 ca_bundle → RequireAndVerifyClientCert；PolicyBadgeRequired/PolicyFull + 无 ca_bundle → 返回错误；PolicyPKIOnly + 无 ca_bundle → 返回错误；WithIgnoreCheckClient() → NoClientCert（无论 policy/ca_bundle） |
| `ati/discovery.go` | 单元测试 + Mock | DNS 发现、RA API 发现、组合发现器降级 |
| `internal/registry/client.go` | 单元测试 + Mock | AK/SK 凭证创建、API 调用参数、错误处理 |
| `verify/dns_discoverer.go` | 单元测试 | 适配器正确转换 DNSResolver 结果到 AgentInfo |

**Mock 策略**：
- DNS/TL/DANE 使用现有 Mock（`dns_mock.go`, `tlog_mock.go`, `dane_mock.go`）
- RA API 使用 `httptest.Server` 模拟
- 阿里云 SDK 通过接口抽象进行 Mock

---

## 5. 风险与注意事项

1. **`_ati` TXT 记录解析**：`ATIRecord` 类型在代码中被引用但未定义。需确认 `_ati` TXT 记录的精确格式并实现 `ParseATIRecord()`。现有 `LookupATIDiscovery()` 已调用该函数但无实现。
2. **`models.TLResponse` 缺失**：多处引用但无定义，属于编码阶段需解决的前置问题。
3. **阿里云 OpenAPI SDK 的 API 契约**：RA API 的具体 endpoint path、请求/响应 schema 需从 RA 服务文档确认。当前设计基于 examples 推断。
4. **`ati/` 包与 `verify/` 包的边界**：`ati/` 是面向用户的高层 API，`verify/` 是底层验证引擎。策略配置在 `ati/` 层设定，传递到 `verify/` 层执行。避免 `verify/` 反向依赖 `ati/`。
