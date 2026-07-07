# ATI SDK 使用指南

## Client 端（Agent 作为调用方）

```go
import (
    "gitlab.alibaba-inc.com/alibaba-dns/ati-golang-sdk/ati"
    "gitlab.alibaba-inc.com/alibaba-dns/ati-golang-sdk/verify"
)

client, err := ati.NewAgentClient(
    ati.WithIdentityCert("client.crt", "client.key"),       // 必填：身份证书 + 私钥
    ati.WithTrustLevel(ati.BadgeRequired),                  // 可选：信任等级（默认 BadgeRequired）
    ati.WithAliyunDiscovery(verify.AliyunATIConfig{...}),   // 可选：阿里云 API 发现
    ati.WithAgentDANEResolver(verify.NewStandardDANEResolver()), // 可选：DANE 验证（DANEAndBadge 等级必填）
    ati.WithClientTimeout(30 * time.Second),                // 可选：请求超时（默认 30s）
)
```

### 参数说明

#### WithIdentityCert(certFile, keyFile string) — 必填

客户端的身份证书和私钥。证书需包含 `ati://` URI SAN。

```go
ati.WithIdentityCert("certs/client.crt", "certs/client.key")
```

证书可以是自签证书，对端通过透明日志指纹验证建立信任。

#### WithMTLSCerts(certFile, keyFile, serverCert, caBundle string) — 替代 WithIdentityCert

当需要指定自定义 CA Bundle 验证服务端证书时使用。`serverCert` 传空字符串即可。

```go
ati.WithMTLSCerts("client.crt", "client.key", "", "ca-bundle.pem")
```

不传 `caBundle`（空字符串）时使用系统 CA 池。

#### WithTrustLevel(level TrustLevel) — 可选

Client 验证 Server 的信任等级。不传时默认 `BadgeRequired`。

| 值 | 含义 |
|----|------|
| `ati.PKIOnly` | 仅验证证书有效性（CA链 + SAN 匹配） |
| `ati.BadgeRequired` | PKI + Badge 验证（默认） |
| `ati.DANEAndBadge` | Badge + DANE/TLSA 验证 |

验证不通过时 `client.Get/Post` 返回 error，请求不会成功。

#### WithAliyunDiscovery(cfg AliyunATIConfig) — 可选

用阿里云 DescribeAgentRegisterInfoMarket API 替代 DNS `_ati` TXT 记录做 Agent 发现。

```go
ati.WithAliyunDiscovery(verify.AliyunATIConfig{
    AccessKeyID:     os.Getenv("ATI_AK"),      // 必填
    AccessKeySecret: os.Getenv("ATI_SK"),      // 必填
    Endpoint:        "alidns.aliyuncs.com",    // 可选，默认 "alidns.aliyuncs.com"
    TLBaseURL:       "https://tl.atiagent.cn:8180", // 可选，默认此值
})
```

不传此 option 时，使用 DNS `_ati` TXT 记录做发现。

#### WithAgentDANEResolver(r DANEResolver) — 条件必填

`TrustLevel` 为 `DANEAndBadge` 时必须设置，否则报错。

```go
// 使用默认 DANE resolver（读取本地 /etc/resolv.conf，兜底 8.8.8.8）
ati.WithAgentDANEResolver(verify.NewStandardDANEResolver())

// 指定 DNS 服务器
ati.WithAgentDANEResolver(verify.NewStandardDANEResolver(
    verify.WithDANEServer("8.8.8.8:53"),
))
```

#### WithClientTimeout(d time.Duration) — 可选

HTTP 请求超时时间，默认 30 秒。

---

### 发起请求

```go
resp, err := client.Get(ctx, "https://target-agent.example.com/api")
resp, err := client.Post(ctx, "https://target-agent.example.com/api", body)
resp, err := client.Put(ctx, "https://target-agent.example.com/api", body)
resp, err := client.Delete(ctx, "https://target-agent.example.com/api")
```

- `body` 为任意可 JSON 序列化的值，SDK 自动 `json.Marshal` 并设 `Content-Type: application/json`
- 验证不通过时返回 error
- 同一 (host, cert fingerprint) 的验证结果会缓存，后续请求不重复验证

### 读取验证结果

```go
resp, err := client.Get(ctx, url)
o := resp.VerificationOutcome

o.DNSDiscovered   // bool - Agent 发现是否成功
o.CAChainValid    // bool - CA 链是否有效
o.SANMatches      // bool - SAN 是否匹配目标主机
o.BadgeVerified   // bool - Badge 是否验证通过
o.DANEVerified    // bool - DANE 是否验证通过
o.AchievedLevel   // TrustLevel - 实际达成等级
o.PeerATIName     // string - 对端 ATI Name（如 "ati://v1.0.0.agent.example.com"）
o.AgentID         // string - 对端 Agent ID
```

---

## Server 端（Agent 作为服务方）

```go
import (
    "gitlab.alibaba-inc.com/alibaba-dns/ati-golang-sdk/ati"
    "gitlab.alibaba-inc.com/alibaba-dns/ati-golang-sdk/verify"
)

tlsConfig, err := ati.NewServerTLSConfig(
    ati.WithServerCert("server.crt", "server.key"),         // 必填：服务端证书 + 私钥
    ati.WithClientCA("ca-bundle.pem"),                      // 可选：Client CA
    ati.WithClientVerifier(ati.PKIOnly),                    // 可选：验证 Client 的等级（默认 PKIOnly）
    ati.WithServerDANEResolver(verify.NewStandardDANEResolver()), // 可选：DANE（DANEAndBadge 等级必填）
    ati.WithServerAliyunDiscovery(verify.AliyunATIConfig{...}),   // 可选：阿里云 API 发现
)

server := &http.Server{
    Addr:      ":8443",
    TLSConfig: tlsConfig,
    Handler:   mux,
}
server.ListenAndServeTLS("", "") // 证书已在 tlsConfig 中，传空字符串
```

### 参数说明

#### WithServerCert(certFile, keyFile string) — 必填

服务端 TLS 证书和私钥。证书需由公有 CA 签发，DNS SAN 包含服务主机名。

```go
ati.WithServerCert("server.crt", "server.key")
```

#### WithClientCA(caBundle string) — 可选

用于验证客户端证书 CA 链的 CA Bundle。

- **设置时**：Go TLS 层验证客户端证书的 CA 链（`RequireAndVerifyClientCert`）
- **不设置时**：接受任意客户端证书（`RequireAnyClientCert`），信任通过 Badge/TLog 建立

```go
ati.WithClientCA("client-ca-bundle.pem")
```

#### WithClientVerifier(level TrustLevel) — 可选

Server 验证 Client 的信任等级。不传时默认 `PKIOnly`。

| 值 | 含义 |
|----|------|
| `ati.PKIOnly` | 仅证书有效性验证（默认） |
| `ati.BadgeRequired` | PKI + Badge 验证 |
| `ati.DANEAndBadge` | Badge + DANE/TLSA 验证 |

验证不通过时 TLS 握手失败，客户端收到错误。

#### WithServerDANEResolver(r DANEResolver) — 条件必填

`WithClientVerifier` 为 `DANEAndBadge` 时必须设置。

```go
ati.WithServerDANEResolver(verify.NewStandardDANEResolver())
```

#### WithServerAliyunDiscovery(cfg AliyunATIConfig) — 可选

Server 端用阿里云 API 替代 DNS 做客户端 Agent 发现。参数同 Client 端。

---

### 读取对端 Agent 身份

```go
func handler(w http.ResponseWriter, r *http.Request) {
    peer, err := ati.PeerATIName(r.TLS)
    if err != nil {
        // 对端证书没有 ati:// URI SAN
        return
    }
    peer.Host    // "ats-client.asia"
    peer.Version // "1.2.0"
    peer.Raw     // "ati://v1.2.0.ats-client.asia"
}
```

---

## 完整示例：两个 Agent 互相通信

### Agent A（Server）

```go
tlsConfig, _ := ati.NewServerTLSConfig(
    ati.WithServerCert("server.crt", "server.key"),
    ati.WithClientVerifier(ati.BadgeRequired),
)

mux := http.NewServeMux()
mux.HandleFunc("/hello", func(w http.ResponseWriter, r *http.Request) {
    peer, _ := ati.PeerATIName(r.TLS)
    json.NewEncoder(w).Encode(map[string]string{
        "message": "hello from Agent A",
        "peer":    peer.Raw,
    })
})

server := &http.Server{Addr: ":8443", TLSConfig: tlsConfig, Handler: mux}
server.ListenAndServeTLS("", "")
```

### Agent B（Client）

```go
client, _ := ati.NewAgentClient(
    ati.WithIdentityCert("client.crt", "client.key"),
    ati.WithTrustLevel(ati.BadgeRequired),
    ati.WithAliyunDiscovery(verify.AliyunATIConfig{
        AccessKeyID:     os.Getenv("ATI_AK"),
        AccessKeySecret: os.Getenv("ATI_SK"),
    }),
)

resp, err := client.Get(context.Background(), "https://agent-a.example.com:8443/hello")
if err != nil {
    log.Fatal(err) // 信任验证不通过
}
defer resp.Body.Close()

fmt.Println(resp.VerificationOutcome.AchievedLevel) // "BADGE_REQUIRED"
```

---

## 证书要求

| 证书类型 | ati:// URI SAN | CA 签发 | 用途 |
|---------|---------------|---------|------|
| 客户端身份证书 | 必须 | 可自签 | 标识 Agent 身份，通过 TLog 指纹验证 |
| 服务端证书 | 建议 | 必须公有CA | TLS 服务端认证，DNS SAN 匹配主机名 |

ATI Name 格式：`ati://v{major}.{minor}.{patch}.{host}`

示例：`ati://v1.0.0.my-agent.example.com`

---

## DNS 记录（当不使用阿里云 API 发现时需要）

| 记录 | 用途 | 等级要求 |
|------|------|---------|
| `_ati.{host}` TXT | Agent 发现 | 所有等级 |
| `_ati-badge.{host}` TXT | Badge URL（指向透明日志） | BadgeRequired 及以上 |
| `_443._tcp.{host}` TLSA | 服务端证书 DANE 绑定 | DANEAndBadge（Client 验 Server） |
| `_ati-identity._tls.{host}` TLSA | 客户端身份证书 DANE 绑定 | DANEAndBadge（Server 验 Client） |

使用 `WithAliyunDiscovery` 时，`_ati` TXT 记录由 API 替代，但 `_ati-badge` 和 TLSA 记录仍通过 DNS 查询。
