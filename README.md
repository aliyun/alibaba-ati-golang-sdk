# ATI Go SDK

Agent Trust Infrastructure (ATI) 的 Go SDK，为 AI Agent 提供安全身份注册、mTLS 通信、多级信任验证和透明度日志集成。

ATI 是阿里云与 CNNIC 联合建设的 Agent 信任基础设施，基于 DNS + PKI + 透明日志三重机制，为 Agent 间通信提供可验证的身份保障。

## 安装

```bash
go get gitlab.alibaba-inc.com/alibaba-dns/ati-golang-sdk
```

## 快速开始

### Agent 间 mTLS 通信（客户端）

```go
package main

import (
    "context"
    "fmt"
    "io"
    "log"

    "gitlab.alibaba-inc.com/alibaba-dns/ati-golang-sdk/ati"
)

func main() {
    client, err := ati.NewAgentClient(
        ati.WithMTLSCerts(
            "certs/identity-cert.pem",
            "certs/private-key.pem",
            "certs/server-cert.pem",
            "certs/ca-bundle.pem",
        ),
        ati.WithTrustLevel(ati.Bronze), // 默认 Bronze，可选 Silver / Gold
    )
    if err != nil {
        log.Fatal(err)
    }

    // 检查证书到期状态
    status := client.CertStatus()
    fmt.Printf("证书剩余有效天数: %d\n", status.DaysRemaining)

    // 发起 mTLS 请求（自动执行 Bronze 验证）
    resp, err := client.Get(context.Background(), "https://target-agent.example.com/api/data")
    if err != nil {
        log.Fatal(err)
    }
    defer resp.Body.Close()

    // 查看验证结果
    outcome := resp.VerificationOutcome
    fmt.Printf("DNS 发现: %v, CA 链有效: %v, SAN 匹配: %v\n",
        outcome.DNSDiscovered, outcome.CAChainValid, outcome.SANMatches)
    fmt.Printf("信任等级: %s\n", outcome.TrustLevel)

    body, _ := io.ReadAll(resp.Body)
    fmt.Printf("响应: %s\n", body)
}
```

### Agent 服务端（mTLS 配置）

```go
package main

import (
    "crypto/tls"
    "log"
    "net/http"

    "gitlab.alibaba-inc.com/alibaba-dns/ati-golang-sdk/ati"
)

func main() {
    tlsConfig, err := ati.NewServerTLSConfig(
        ati.WithServerCert("certs/server-cert.pem", "certs/private-key.pem"),
        ati.WithClientCA("certs/ca-bundle.pem"),
        ati.WithClientVerifier(ati.Bronze), // 自动验证客户端 ati:// URI SAN
    )
    if err != nil {
        log.Fatal(err)
    }

    server := &http.Server{
        Addr:      ":8443",
        TLSConfig: tlsConfig,
        Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
            // 提取对方 Agent 身份
            peer, err := ati.PeerATIName(r.TLS)
            if err != nil {
                http.Error(w, "unknown peer", 403)
                return
            }
            w.Write([]byte("Hello, " + peer.Host))
        }),
    }

    log.Fatal(server.ListenAndServeTLS("", ""))
}
```

### Trust Card 查询

```go
package main

import (
    "context"
    "fmt"
    "log"

    "gitlab.alibaba-inc.com/alibaba-dns/ati-golang-sdk/ati"
)

func main() {
    card, err := ati.GetTrustCard(context.Background(), "agent.example.com", "1.0.0")
    if err != nil {
        log.Fatal(err)
    }
    fmt.Printf("Agent: %s (ID: %s, 版本: %s)\n", card.AgentName, card.AgentID, card.Version)
}
```

### 诊断工具

```go
package main

import (
    "context"
    "fmt"
    "log"

    "gitlab.alibaba-inc.com/alibaba-dns/ati-golang-sdk/ati"
)

func main() {
    result, err := ati.Diagnose(context.Background(), "agent.example.com")
    if err != nil {
        log.Fatal(err)
    }
    fmt.Println(result.String()) // 人类可读报告
    // 或 result.JSON() 获取 JSON 格式
}
```

## 功能概览

### `ati` 包 — Agent 通信与信任验证

| 功能 | 说明 |
|------|------|
| `NewAgentClient` | 创建 mTLS 客户端，支持 Bronze/Silver/Gold 三级信任验证 |
| `NewServerTLSConfig` | 创建服务端 TLS 配置，自动验证客户端 ATI 身份证书 |
| `GetTrustCard` | 从 CNNIC 透明日志查询 Agent 元数据 |
| `Diagnose` | 运行 7 步诊断链（DNS 发现 → TL 查询 → 密封验证 → Merkle 证明） |
| `PeerATIName` | 从 TLS 连接中提取对端 Agent 的 ATI 身份 |

### 三级信任验证

| 等级 | 验证内容 | 说明 |
|------|---------|------|
| **Bronze** | DNS 发现 + CA 链 + SAN 匹配 | 默认等级。验证 `_ati` TXT 记录、CA 签名链、证书 URI SAN 与目标主机匹配 |
| **Silver** | Bronze + DANE/TLSA | 额外验证 DNS TLSA 记录，提供双通道信任锚定 |
| **Gold** | Silver + TL 密封 + Merkle 证明 | 最高等级。验证 CNNIC 透明日志的 ECDSA 密封签名和 Merkle 包含证明 |

### `verify` 包 — 底层验证引擎

| 模块 | 说明 |
|------|------|
| `dns.go` / `dns_resolver.go` | DNS 接口和标准解析器（`_ati` / `_ati-badge` TXT 查询） |
| `badge_record.go` | `_ati-badge` TXT 记录解析 |
| `dane.go` | DANE/TLSA 验证（RFC 6698） |
| `cert.go` | 证书抽象（`CertIdentity`、`CertFingerprint`、ATI Name 解析） |
| `seal.go` | CNNIC TL 密封验证（RFC 8785 JCS + SHA-256 + ECDSA） |
| `jcs.go` | RFC 8785 JSON Canonicalization Scheme 实现 |
| `merkle.go` | Merkle 包含证明验证（RFC 9162 风格） |
| `gold.go` | Gold 级别验证编排（6 步流程） |
| `tlog.go` | 透明日志客户端接口 |
| `cache.go` | Badge 缓存（TTL + stale fallback） |
| `verify.go` | Badge 级别验证器（`ServerVerifier` / `ClientVerifier`） |
| `scitt/` | SCITT 密码学子系统（COSE_Sign1、Receipt、Merkle Tree、Root Keys） |

### `internal/registry` 包 — RA API 客户端

| 方法 | 说明 |
|------|------|
| `RegisterAgent` | 注册新 Agent |
| `GetAgentDetails` | 获取 Agent 详情 |
| `SearchAgents` | 搜索 Agent |
| `ResolveAgent` | 按 host + version 解析 Agent |
| `RevokeAgent` | 撤销 Agent 注册 |
| `SubmitIdentityCSR` / `SubmitServerCSR` | 提交证书签名请求 |
| `GetCSRStatus` | 查询 CSR 状态 |
| `VerifyACME` / `VerifyDNS` | 触发 ACME / DNS 验证 |
| `GetAgentEvents` | 分页获取 Agent 事件 |

### `keygen` 包 — 密钥生成

```go
import "gitlab.alibaba-inc.com/alibaba-dns/ati-golang-sdk/keygen"

// 生成 EC 密钥对 (P-256)
ecKeyPair, err := keygen.GenerateECKeyPairWithPEM(keygen.CurveP256(), nil)

// 生成 RSA 密钥对 (2048+)
rsaKeyPair, err := keygen.GenerateRSAKeyPairWithPEM(2048, nil)

// 保存到文件
err = ecKeyPair.WriteKeyPairToFiles("private.key", "public.pem")
```

## ATI Name 格式

ATI Name 是 Agent 身份的全局唯一标识，嵌入在身份证书的 URI SAN 中：

```
ati://v{major}.{minor}.{patch}.{agentHost}
```

例如：`ati://v1.0.0.agent.example.com`

## DNS 记录

| 记录名 | 类型 | 用途 |
|--------|------|------|
| `_ati.{host}` | TXT | 协议发现（Agent ID、版本、模式） |
| `_ati-badge.{host}` | TXT | Badge URL（指向 CNNIC 透明日志） |
| `_443._tcp.{host}` | TLSA | DANE 证书绑定（Silver 级别验证） |

## 项目结构

```
ati-golang-sdk/
├── ati/                          # 公共 SDK API
│   ├── mtls_client.go           # mTLS 客户端（Bronze/Silver/Gold）
│   ├── server.go                # 服务端 TLS 配置
│   ├── trust_card.go            # Trust Card 查询
│   ├── trust_level.go           # 信任等级定义
│   └── diagnose.go              # 诊断工具
├── verify/                       # 验证引擎
│   ├── dns.go, dns_resolver.go  # DNS 解析
│   ├── badge_record.go          # Badge 记录解析
│   ├── dane.go                  # DANE/TLSA 验证
│   ├── cert.go                  # 证书抽象
│   ├── seal.go                  # TL 密封验证（JCS + ECDSA）
│   ├── jcs.go                   # RFC 8785 JCS
│   ├── merkle.go                # Merkle 证明验证
│   ├── gold.go                  # Gold 验证编排
│   ├── tlog.go                  # 透明日志客户端
│   ├── cache.go                 # Badge 缓存
│   ├── verify.go                # Badge 验证器
│   └── scitt/                   # SCITT 密码学子系统
├── models/                       # 数据模型
├── internal/
│   ├── registry/                # RA API 客户端
│   └── httputility/             # HTTP 工具
├── keygen/                       # 密钥生成
├── cmd/ati-cli/                  # CLI 工具
└── examples/                     # 使用示例
```

## CNNIC 透明日志

ATI 使用 CNNIC 运营的透明日志（TL）记录 Agent 生命周期事件：

- **API 端点**: `https://tl.ansagent.cn:8180/ans/api/v1`
- **密封格式**: JSON/JCS + SHA-256 + ECDSA（非 CBOR/COSE）
- **Merkle 树**: RFC 9162 风格的包含证明
- **查询接口**: `GET /tl/agents/{agentId}/logs/latest`

### Gold 验证流程

```
1. DNS 发现    → 查询 _ati TXT 获取 agentId
2. TL 日志获取  → GET /tl/agents/{agentId}/logs/latest
3. 密封验证    → JCS 规范化 → SHA-256 → ECDSA 签名验证
4. Merkle 验证 → 重建根哈希，与期望值比对
5. 指纹匹配    → 证书指纹与 TL 记录比对
6. 状态检查    → ACTIVE / DEPRECATED 允许，REVOKED 拒绝
```

## 测试

```bash
# 运行所有测试
go test ./... -count=1

# 运行特定包测试
go test ./ati/ -v
go test ./verify/ -v

# 覆盖率
go test -cover -coverprofile=coverage.out ./...
go tool cover -html=coverage.out
```

## 错误处理

API 错误返回 `*models.ResponseError`，包含 HTTP 状态码、错误码和详细信息：

```go
import (
    "errors"
    "net/http"
    "gitlab.alibaba-inc.com/alibaba-dns/ati-golang-sdk/models"
)

result, err := client.GetAgentDetails(ctx, agentID)
if err != nil {
    var respErr *models.ResponseError
    if errors.As(err, &respErr) {
        switch respErr.StatusCode {
        case http.StatusNotFound:
            fmt.Println("Agent 不存在")
        case http.StatusUnauthorized:
            fmt.Println("认证失败")
        default:
            fmt.Printf("API 错误 %d: %s\n", respErr.StatusCode, respErr.Message)
        }
    }
}
```

## 基础设施角色

| 角色 | 负责方 | SDK 交互方式 |
|------|--------|-------------|
| RA (注册机构) | 阿里云 ATI API | HTTPS REST API |
| DNS | 阿里云云解析 | DNS UDP/TCP |
| 透明日志 (TL) | CNNIC | HTTPS REST API |
| Trust Card 托管 | CNNIC | HTTPS GET |
| Private CA | CNNIC | 不直接通信（RA 代为） |
| Public CA | 阿里云证书服务 | 不直接通信（RA 代为） |

## License

MIT License
