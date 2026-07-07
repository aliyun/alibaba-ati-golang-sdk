# ATI Go SDK

Agent Trust Infrastructure (ATI) 的 Go SDK，为 AI Agent 提供基于 mTLS 的安全通信和多级信任验证。

## 安装

```bash
go get gitlab.alibaba-inc.com/alibaba-dns/ati-golang-sdk
```

## 信任等级

SDK 支持三级递增的信任验证：

| 等级 | 常量 | 验证内容 |
|------|------|---------|
| **PKI_ONLY** | `ati.PKIOnly` | 证书有效性（CA链 + SAN匹配 + 有效期） |
| **BADGE_REQUIRED** | `ati.BadgeRequired` | PKI + Badge 验证（_ati-badge DNS → 透明日志 → 证书指纹比对） |
| **DANE_AND_BADGE** | `ati.DANEAndBadge` | Badge + DANE/TLSA 双重验证 |

**默认值**：
- Client 验证 Server：`BadgeRequired`
- Server 验证 Client：`PKIOnly`

## Client 用法

### 最简示例

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
    // 创建客户端，提供身份证书（需包含 ati:// URI SAN）
    client, err := ati.NewAgentClient(
        ati.WithIdentityCert("certs/client.crt", "certs/client.key"),
    )
    if err != nil {
        log.Fatal(err)
    }

    // 发起请求（自动执行 Badge 验证）
    resp, err := client.Get(context.Background(), "https://target-agent.example.com/api/data")
    if err != nil {
        log.Fatal(err) // 验证不通过时返回 error
    }
    defer resp.Body.Close()

    // 查看验证结果
    o := resp.VerificationOutcome
    fmt.Printf("Badge验证: %v, 达成等级: %s\n", o.BadgeVerified, o.AchievedLevel)

    body, _ := io.ReadAll(resp.Body)
    fmt.Println(string(body))
}
```

### 指定信任等级

```go
client, err := ati.NewAgentClient(
    ati.WithIdentityCert("client.crt", "client.key"),
    ati.WithTrustLevel(ati.DANEAndBadge), // 要求最高等级
    ati.WithAgentDANEResolver(verify.NewStandardDANEResolver()), // DANE 需要 DANE resolver
)
```

### 使用阿里云 API 做服务发现

默认的 Agent 发现通过 DNS `_ati` TXT 记录。如果使用阿里云 DescribeAgentRegisterInfoMarket API：

```go
import "gitlab.alibaba-inc.com/alibaba-dns/ati-golang-sdk/verify"

client, err := ati.NewAgentClient(
    ati.WithIdentityCert("client.crt", "client.key"),
    ati.WithAliyunDiscovery(verify.AliyunATIConfig{
        AccessKeyID:     os.Getenv("ATI_AK"),
        AccessKeySecret: os.Getenv("ATI_SK"),
        Endpoint:        "alidns.aliyuncs.com",
    }),
)
```

### 自定义 CA Bundle

当服务端使用私有 CA 签发证书时：

```go
client, err := ati.NewAgentClient(
    ati.WithMTLSCerts("client.crt", "client.key", "", "ca-bundle.pem"),
)
```

### 验证结果

每次请求的响应中包含 `VerificationOutcome`：

```go
resp, err := client.Get(ctx, url)
o := resp.VerificationOutcome

o.DNSDiscovered   // Agent 发现成功（_ati 记录或 API）
o.CAChainValid    // CA 链验证通过
o.SANMatches      // 证书 SAN 匹配目标主机
o.BadgeVerified   // Badge 验证通过
o.DANEVerified    // DANE/TLSA 验证通过
o.AchievedLevel   // 实际达成的信任等级
o.PeerATIName     // 对端 ATI 身份（如 "ati://v1.0.0.agent.example.com"）
o.AgentID         // 对端 Agent ID
```

### 证书状态检查

```go
status := client.CertStatus()
fmt.Printf("证书到期: %s（剩余 %d 天）\n", status.ExpiresAt.Format("2006-01-02"), status.DaysRemaining)
if status.IsExpired {
    log.Fatal("证书已过期")
}
```

## Server 用法

### 配置 mTLS 服务端

```go
package main

import (
    "log"
    "net/http"

    "gitlab.alibaba-inc.com/alibaba-dns/ati-golang-sdk/ati"
)

func main() {
    tlsConfig, err := ati.NewServerTLSConfig(
        ati.WithServerCert("server.crt", "server.key"),
    )
    if err != nil {
        log.Fatal(err)
    }

    server := &http.Server{
        Addr:      ":8443",
        TLSConfig: tlsConfig,
        Handler:   http.HandlerFunc(handler),
    }
    // 证书已加载到 tlsConfig，传空字符串
    log.Fatal(server.ListenAndServeTLS("", ""))
}

func handler(w http.ResponseWriter, r *http.Request) {
    peer, err := ati.PeerATIName(r.TLS)
    if err != nil {
        http.Error(w, "unknown peer", 403)
        return
    }
    fmt.Fprintf(w, "Hello, %s", peer.Host)
}
```

### Server 验证 Client

```go
// 要求客户端通过 Badge 验证
tlsConfig, err := ati.NewServerTLSConfig(
    ati.WithServerCert("server.crt", "server.key"),
    ati.WithClientVerifier(ati.BadgeRequired),
)

// 要求 DANE + Badge 双重验证
tlsConfig, err := ati.NewServerTLSConfig(
    ati.WithServerCert("server.crt", "server.key"),
    ati.WithClientVerifier(ati.DANEAndBadge),
    ati.WithServerDANEResolver(verify.NewStandardDANEResolver()),
)
```

### 使用自定义 Client CA

当客户端证书由特定 CA 签发时，可指定 CA Bundle 进行 CA 链验证：

```go
tlsConfig, err := ati.NewServerTLSConfig(
    ati.WithServerCert("server.crt", "server.key"),
    ati.WithClientCA("client-ca-bundle.pem"), // 不设则接受任意客户端证书（通过 Badge/TLog 建立信任）
    ati.WithClientVerifier(ati.BadgeRequired),
)
```

### 读取对端身份

```go
func handler(w http.ResponseWriter, r *http.Request) {
    // 获取对端 ATI Name
    peer, err := ati.PeerATIName(r.TLS)
    if err == nil {
        fmt.Println(peer.Host)    // "ats-client.asia"
        fmt.Println(peer.Version) // "1.2.0"
        fmt.Println(peer.Raw)     // "ati://v1.2.0.ats-client.asia"
    }
}
```

## 证书要求

### 身份证书（Client）

- **必须** 包含 `ati://` URI SAN，格式：`ati://v{major}.{minor}.{patch}.{host}`
- 可以是自签证书（信任通过 Badge/TLog 指纹验证建立）
- 示例 SAN：`ati://v1.0.0.my-agent.example.com`

### 服务端证书（Server）

- 必须由公有 CA 签发
- DNS SAN 必须包含服务主机名
- 建议同时包含 `ati://` URI SAN

## 全局配置（可选）

适用于需要集中管理 Aliyun 凭证的场景：

```go
err := ati.Init(ati.Config{
    AK:               os.Getenv("ATI_AK"),
    SK:               os.Getenv("ATI_SK"),
    LocalHostname:    "my-agent.example.com",
    IdentityCertFile: "certs/identity.crt",
    IdentityKeyFile:  "certs/identity.key",
    TrustLevel:       ati.BadgeRequired,
})
```

## DNS 记录

| 记录名 | 类型 | 用途 |
|--------|------|------|
| `_ati.{host}` | TXT | Agent 发现（ID、版本、模式） |
| `_ati-badge.{host}` | TXT | Badge URL（指向透明日志） |
| `_443._tcp.{host}` | TLSA | 服务端 DANE 证书绑定 |
| `_ati-identity._tls.{host}` | TLSA | 客户端身份 DANE 证书绑定 |

## ATI Name 格式

ATI Name 是 Agent 身份的全局唯一标识，嵌入在证书 URI SAN 中：

```
ati://v{major}.{minor}.{patch}.{agentHost}
```

示例：`ati://v1.0.0.agent.example.com`

## 验证缓存

Client 对同一服务端的验证结果会按 `(host, cert fingerprint)` 缓存。同一连接上的后续请求不会重复验证。

## 测试

```bash
go test ./... -count=1
go test ./ati/ -v
go test ./verify/ -v
```
