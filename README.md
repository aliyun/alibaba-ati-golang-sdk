# Alibaba ATI Go SDK

[![Go Reference](https://pkg.go.dev/badge/github.com/aliyun/alibaba-ati-golang-sdk.svg)](https://pkg.go.dev/github.com/aliyun/alibaba-ati-golang-sdk)

Agent Trust Infrastructure (ATI) 的 Go SDK,为 AI Agent 之间提供基于 **mTLS 传输 + 服务发现 + 多级信任验证** 的安全通信能力。

- **Client**(`ati.AgentClient`)—— Agent 作为调用方,发起经过验证的 HTTPS 请求。
- **Server**(`ati.NewServerTLSConfig`)—— Agent 作为服务方,在 TLS 握手阶段验证对端身份。

> 模块路径:`github.com/aliyun/alibaba-ati-golang-sdk`

---

## 目录

- [安装](#安装)
- [信任等级原理](#信任等级原理)
- [快速开始](#快速开始)
- [全局配置(ati.Init)](#全局配置atiinit)
- [Client 端详解](#client-端详解)
- [Server 端详解](#server-端详解)
- [服务发现](#服务发现)
- [指定 DNS 服务器](#指定-dns-服务器)
- [完整示例:两个 Agent 互相通信](#完整示例两个-agent-互相通信)
- [证书要求与 ATI Name](#证书要求与-ati-name)
- [DNS 记录清单](#dns-记录清单)
- [验证缓存与失败语义](#验证缓存与失败语义)
- [示例代码](#示例代码)

---

## 安装

```bash
go get github.com/aliyun/alibaba-ati-golang-sdk
```

导入常用的两个包:

```go
import (
    "github.com/aliyun/alibaba-ati-golang-sdk/ati"    // 客户端 / 服务端入口
    "github.com/aliyun/alibaba-ati-golang-sdk/verify" // resolver / 验证器等
)
```

---

## 信任等级原理

SDK 提供三级**递增**的信任验证。每一级都在前一级的基础上叠加更强的身份保证,常量定义在 `ati` 包:

| 等级 | 常量 | 验证内容 | 回答的问题 |
|------|------|---------|-----------|
| **PKI_ONLY** | `ati.PKIOnly` | 证书有效性:有效期、CA 链(仅当配置了私有根证书时)、SAN 与目标主机匹配 | "这是一张时间与结构都合法的证书吗?" |
| **BADGE_REQUIRED** | `ati.BadgeRequired` | 在 PKI 之上,再做 Badge 验证 | "这个 Agent 身份被权威登记过、且证书指纹与登记记录一致吗?" |
| **DANE_AND_BADGE** | `ati.DANEAndBadge` | 在 Badge 之上,再做 DANE/TLSA 验证 | "证书指纹还被域名所有者通过 DNSSEC 保护的 TLSA 记录额外背书了吗?" |

### 每一级具体在做什么

**① PKI_ONLY —— 基础证书校验**
沿用标准 TLS 的证书检查:证书是否在有效期内、证书 SAN 是否与你要访问的主机名一致。CA 链校验是**有条件**的——**只有当你配置了私有根证书(CA bundle)时才会做 CA 链校验**;不配置时不校验 CA 链(接受任意证书),信任交由更高等级(Badge/TLog)建立。身份证书允许自签。

**② BADGE_REQUIRED —— 身份徽章验证**
在 PKI 通过后,SDK 会:

1. 查询 DNS `_ati-badge.<host>` TXT 记录,拿到该 Agent 的 **Badge URL**(指向透明日志 Transparency Log);
2. 从透明日志取回该 Agent 的登记记录(含权威签发的证书指纹、Merkle 证明等);
3. 把**对端实际出示的证书指纹**与透明日志中登记的指纹做比对。

只有指纹一致才算通过。这一步回答的是"对端是不是它声称的那个已登记 Agent",防止拿一张合法但身份不符的证书冒充。

**③ DANE_AND_BADGE —— DANE/TLSA 双重绑定**
在 Badge 通过后,再查询 DNSSEC 保护下的 TLSA 记录,把证书指纹与**域名所有者在 DNS 中发布的指纹**再绑定一次:

- Client 验 Server:查 `_443._tcp.<host>` 的 TLSA(`Verify`)。
- Server 验 Client:查 `_ati-identity._tls.<host>` 的 TLSA(`VerifyIdentity`)。

这一步把"信任锚"从透明日志扩展到"域名所有者 + DNSSEC 信任链",即使透明日志被绕过,攻击者仍需同时控制目标域名的 DNSSEC 签名才能伪造。

### 默认等级

- **Client 验 Server**:不调用 `WithTrustLevel` 时,默认使用 **`BadgeRequired`**;调用 `WithTrustLevel(X)` 则使用你指定的等级 `X`。两种情况都是**强制模式**——达不到目标等级时请求返回 error。
- **Server 验 Client**:**不调用 `WithClientVerifier` 时,什么都不验**——不请求客户端证书,等同于普通 TLS 直连;调用 `WithClientVerifier(X)` 则按等级 `X` 验证,达不到时 TLS 握手失败。
- **PKI 与私有根证书**:是否做 CA 链校验取决于你有没有配置私有根证书(CA bundle)。**没传私有根证书 → 不验 PKI 的 CA 链**(接受任意证书);**传了私有根证书 → 需要验 PKI 的 CA 链**,且即使没调用 `WithClientVerifier` 也会隐含按 `PKIOnly` 验证。

> **DANE resolver 会自动创建**:当等级为 `DANEAndBadge` 时,若未显式提供 DANE resolver,SDK 会自动构造一个默认的 `StandardDANEResolver`(默认走 DNSSEC 可用的公共解析器 `8.8.8.8:53`,也可通过 [`ati.Init` 的 `DNSServer`](#指定-dns-服务器) 覆盖)。因此 `WithAgentDANEResolver` / `WithServerDANEResolver` 属于**可选覆盖**,而非必填。

---

## 快速开始

> **前提**:Agent 服务发现只能走阿里云 API(见[服务发现](#服务发现)),因此在创建 Client / 需要 Badge 验证的 Server 之前,必须先提供阿里云凭证——推荐用 [`ati.Init`](#全局配置atiinit) 集中配置,或设置 `ATI_AK` / `ATI_SK` 环境变量。缺少凭证会直接返回 error。

### Client 最简示例

```go
package main

import (
    "context"
    "fmt"
    "io"
    "log"
    "os"

    "github.com/aliyun/alibaba-ati-golang-sdk/ati"
)

func main() {
    // 集中配置阿里云凭证 + 身份证书(服务发现所必需)
    if err := ati.Init(ati.Config{
        AK:               os.Getenv("ATI_AK"),
        SK:               os.Getenv("ATI_SK"),
        LocalHostname:    "my-agent.example.com",
        IdentityCertFile: "certs/client.crt",
        IdentityKeyFile:  "certs/client.key",
    }); err != nil {
        log.Fatal(err)
    }

    // 身份证书需包含 ati:// URI SAN,可自签
    client, err := ati.NewAgentClient(
        ati.WithIdentityCert("certs/client.crt", "certs/client.key"),
        // 不传 WithTrustLevel → 默认 BadgeRequired
    )
    if err != nil {
        log.Fatal(err)
    }

    resp, err := client.Get(context.Background(), "https://target-agent.example.com/api/data")
    if err != nil {
        log.Fatal(err) // 达不到 BadgeRequired 会返回 error
    }
    defer resp.Body.Close()

    o := resp.VerificationOutcome
    fmt.Printf("达成等级=%s  Badge=%v  DANE=%v\n", o.AchievedLevel, o.BadgeVerified, o.DANEVerified)

    body, _ := io.ReadAll(resp.Body)
    fmt.Println(string(body))
}
```

### Server 最简示例

```go
package main

import (
    "fmt"
    "log"
    "net/http"

    "github.com/aliyun/alibaba-ati-golang-sdk/ati"
)

func main() {
    tlsConfig, err := ati.NewServerTLSConfig(
        ati.WithServerCert("certs/server.crt", "certs/server.key"),
        ati.WithClientVerifier(ati.BadgeRequired), // 要求调用方通过 Badge 验证
    )
    if err != nil {
        log.Fatal(err)
    }

    mux := http.NewServeMux()
    mux.HandleFunc("/hello", func(w http.ResponseWriter, r *http.Request) {
        peer, _ := ati.PeerATIName(r.TLS)
        fmt.Fprintf(w, "hello, %s", peer.Host)
    })

    server := &http.Server{Addr: ":8443", TLSConfig: tlsConfig, Handler: mux}
    log.Fatal(server.ListenAndServeTLS("", "")) // 证书已在 tlsConfig 中,传空字符串
}
```

> Server 不调用 `WithClientVerifier` 时什么都不验(普通 TLS 直连),自然不需要服务发现凭证;一旦要求 `BadgeRequired` 及以上,才需要阿里云凭证。

---

## 全局配置(ati.Init)

`ati.Init` 用于在启动时集中管理阿里云凭证、默认身份和 DNS 服务器等全局配置:

```go
err := ati.Init(ati.Config{
    AK:               os.Getenv("ATI_AK"),    // 必填:阿里云 AccessKey ID(服务发现所需)
    SK:               os.Getenv("ATI_SK"),    // 必填:阿里云 AccessKey Secret
    LocalHostname:    "my-agent.example.com", // 必填:本 Agent 主机名
    IdentityCertFile: "certs/identity.crt",   // 必填:身份证书
    IdentityKeyFile:  "certs/identity.key",   // 必填:身份私钥
    CARootFile:       "certs/root-ca.pem",    // 可选:私有根证书,配置后才做 PKI 的 CA 链校验
    TrustLevel:       ati.BadgeRequired,      // 可选,默认 BadgeRequired
    DNSServer:        "8.8.8.8:53",           // 可选,仅 DANE/TLSA 用
})
```

调用后,未显式传 `WithAliyunDiscovery` 的 Client / Server 会自动使用全局配置(或环境变量 `ATI_AK` / `ATI_SK`)里的阿里云凭证做服务发现。**若既没有全局配置也没有环境变量,创建 Client(或需要发现的 Server)时会直接返回 error。**

---

## Client 端详解

### 创建客户端

```go
client, err := ati.NewAgentClient(
    ati.WithIdentityCert("client.crt", "client.key"), // 必填
    ati.WithTrustLevel(ati.BadgeRequired),            // 可选,不传默认 BadgeRequired
    ati.WithClientTimeout(30 * time.Second),          // 可选,默认 30s
)
```

### 配置项

| Option | 是否必填 | 说明 |
|--------|---------|------|
| `WithIdentityCert(certFile, keyFile string)` | **必填** | 客户端身份证书 + 私钥。证书必须含 `ati://` URI SAN,可自签。 |
| `WithMTLSCerts(id, key, serverCert, caBundle string)` | 替代上一项 | 需要用私有根证书(CA Bundle)校验服务端证书时使用;`serverCert` 传空即可。传了 CA Bundle 才会做 PKI 的 CA 链校验。 |
| `WithTrustLevel(level TrustLevel)` | 可选 | 目标信任等级。不传默认 `BadgeRequired`。 |
| `WithClientTimeout(d time.Duration)` | 可选 | HTTP 请求超时,默认 30s。 |
| `WithAgentDANEResolver(r verify.DANEResolver)` | 可选 | 覆盖默认 DANE resolver(`DANEAndBadge` 下会自动创建)。 |
| `WithTLogClient(t verify.TransparencyLogClient)` | 可选 | 自定义透明日志客户端(测试或私有部署)。 |
| `WithAliyunDiscovery(cfg verify.AliyunATIConfig)` | 可选 | 显式提供本客户端专用的阿里云发现凭证(等价于用全局配置里的凭证)。 |
| `WithTargetVersion(version string)` | 可选 | 发现时指定目标版本,支持 `1.0.0` / `^1.0.0` / `~1.2.3` / `>=1.0.0`。 |
| `WithDNSResolver(r verify.DNSResolver)` | 可选 | 注入自定义发现 resolver(主要用于测试)。 |
| `WithTLPublicKey(key *ecdsa.PublicKey)` | 可选 | 预置 TL 公钥用于 Gold 级封条验证。 |

### 发起请求

```go
resp, err := client.Get(ctx, "https://target/api")
resp, err := client.Post(ctx, "https://target/api", body)   // body 为任意可 JSON 序列化的值
resp, err := client.Put(ctx, "https://target/api", body)
resp, err := client.Delete(ctx, "https://target/api")
```

- URL 必须是 `https`,否则返回 error;
- `body != nil` 时,SDK 自动 `json.Marshal` 并设置 `Content-Type: application/json`;
- 达不到目标等级时返回 error(此时响应体已关闭)。

### 读取验证结果

每个 `*ati.Response` 都带有 `VerificationOutcome`:

```go
o := resp.VerificationOutcome

o.DNSDiscovered  // bool        服务发现成功(阿里云 API)
o.CAChainValid   // bool        CA 链有效(未配置私有根证书时视为 true)
o.SANMatches     // bool        证书 SAN 与目标主机匹配
o.BadgeVerified  // bool        Badge 验证通过
o.DANEVerified   // bool        DANE/TLSA 验证通过
o.AchievedLevel  // TrustLevel  实际达成的最高等级
o.RequestedLevel // *TrustLevel 请求的等级
o.PeerATIName    // string      对端 ATI Name,如 "ati://v1.0.0.agent.example.com"
o.AgentID        // string      对端 Agent ID
o.BadgeOutcome   // *verify.VerificationOutcome  Badge 详细结果
o.DANEDetails    // *verify.DANEOutcome          DANE 详细结果
```

### 证书状态检查

```go
st := client.CertStatus()
fmt.Printf("到期 %s,剩余 %d 天\n", st.ExpiresAt.Format("2006-01-02"), st.DaysRemaining)
if st.IsExpired {
    log.Fatal("身份证书已过期")
}
```

---

## Server 端详解

### 创建 TLS 配置

```go
tlsConfig, err := ati.NewServerTLSConfig(
    ati.WithServerCert("server.crt", "server.key"),  // 必填
    ati.WithClientCA("client-ca-bundle.pem"),        // 可选:私有根证书
    ati.WithClientVerifier(ati.BadgeRequired),       // 可选,不传则什么都不验
)
```

### 配置项

| Option | 是否必填 | 说明 |
|--------|---------|------|
| `WithServerCert(certFile, keyFile string)` | **必填** | 服务端证书 + 私钥。建议由公有 CA 签发,DNS SAN 含服务主机名。 |
| `WithClientCA(caBundle string)` | 可选 | 设置(私有根证书)后,Go TLS 层对客户端证书做 CA 链校验(`RequireAndVerifyClientCert`);不设则接受任意客户端证书(`RequireAnyClientCert`),信任交由 Badge/TLog 建立。 |
| `WithClientVerifier(level TrustLevel)` | 可选 | Server 对 Client 的信任等级。**不传则什么都不验**(不请求客户端证书,等同普通 TLS 直连);传了则达不到时握手失败。 |
| `WithServerDANEResolver(r verify.DANEResolver)` | 可选 | 覆盖默认 DANE resolver(`DANEAndBadge` 下会自动创建)。 |
| `WithServerAliyunDiscovery(cfg verify.AliyunATIConfig)` | 可选 | 显式提供本服务端专用的阿里云发现凭证(等价于用全局配置里的凭证)。 |
| `WithPeerLevelStore(store *sync.Map)` | 可选 | 注入共享的 `sync.Map` 记录每个对端达成的等级,配合 `PeerTrustLevel` 在业务层查询。 |

### 验证行为矩阵

`WithClientVerifier` 与 `WithClientCA` 的组合决定了 server 验 client 的最终行为:

| `WithClientVerifier` | `WithClientCA` | TLS ClientAuth | 验证行为 |
|:---:|:---:|---|---|
| 不传 | 不传 | `NoClientCert` | **什么都不验**,不请求客户端证书,等同普通 TLS 直连 |
| 不传 | 传 | `RequireAndVerifyClientCert` | 隐含按 `PKIOnly` 验证 + CA 链校验 |
| 传 | 不传 | `RequireAnyClientCert` | 按指定等级验证;自签证书靠 Badge/TLog 建立信任 |
| 传 | 传 | `RequireAndVerifyClientCert` | 按指定等级验证 + CA 链校验 |

> 传了私有根证书(`WithClientCA`)即视为"要认证客户端",因此即便没调用 `WithClientVerifier` 也会隐含按 `PKIOnly` 走,不会静默忽略。

### 读取对端身份

```go
func handler(w http.ResponseWriter, r *http.Request) {
    peer, err := ati.PeerATIName(r.TLS)
    if err != nil {
        http.Error(w, "unknown peer", http.StatusForbidden) // 对端证书无 ati:// URI SAN
        return
    }
    _ = peer.Host    // "ats-client.asia"
    _ = peer.Version // "1.2.0"
    _ = peer.Raw     // "ati://v1.2.0.ats-client.asia"
}
```

### 查询对端达成的等级

```go
var peerLevels sync.Map
tlsConfig, _ := ati.NewServerTLSConfig(
    ati.WithServerCert("server.crt", "server.key"),
    ati.WithPeerLevelStore(&peerLevels),
)

func handler(w http.ResponseWriter, r *http.Request) {
    if lvl := ati.PeerTrustLevel(r.TLS, &peerLevels); lvl != nil {
        fmt.Printf("对端达成等级:%s\n", lvl) // 例如 BADGE_REQUIRED
    }
}
```

---

## 服务发现

Agent 服务发现**只能**通过阿里云 `DescribeAtiAgentRegisterInfoMarket` API 完成——**不支持** DNS `_ati` TXT 记录方式的发现。

凭证(AK/SK)可以通过三种途径提供,任选其一即可:

1. **全局配置**([`ati.Init`](#全局配置atiinit) 的 `AK` / `SK`)—— 推荐;
2. **环境变量** `ATI_AK` / `ATI_SK`;
3. **每个 Client / Server 单独指定** —— `WithAliyunDiscovery` / `WithServerAliyunDiscovery`:

```go
client, err := ati.NewAgentClient(
    ati.WithIdentityCert("client.crt", "client.key"),
    ati.WithAliyunDiscovery(verify.AliyunATIConfig{
        AccessKeyID:     os.Getenv("ATI_AK"), // 必填
        AccessKeySecret: os.Getenv("ATI_SK"), // 必填
    }),
)
```

> **没有任何凭证 → 直接报错,不做兜底。** 创建 Client(或需要发现的 Server)时会返回:
> `agent discovery requires Aliyun credentials: set them via ati.Init(Config{AK, SK}) or the ATI_AK/ATI_SK environment variables`。

`AliyunATIConfig` **只接受** `AccessKeyID` / `AccessKeySecret` 两个字段;API 端点(`alidns.aliyuncs.com`)与透明日志基址均为固定平台常量,不对外开放配置。

> 服务发现虽走 API,但 `_ati-badge` TXT 与 TLSA 记录**仍通过 DNS 查询**。

---

## 指定 DNS 服务器

DANE/TLSA 依赖上游返回 DNSSEC 记录(RRSIG),而系统默认解析器(`/etc/resolv.conf`)常是不做 DNSSEC 的企业解析器。可以通过[全局配置 `ati.Init`](#全局配置atiinit) 的 `DNSServer` 字段,把自动创建的 DANE resolver 指向一个 DNSSEC 可用的解析器:

```go
ati.Init(ati.Config{
    // ... 其他必填项 ...
    DNSServer: "8.8.8.8:53", // 也可只写 "8.8.8.8",端口默认 53
})
```

行为说明:

- `DNSServer` 只作用于**自动创建的 DANE resolver**(即等级为 `DANEAndBadge` 且未显式提供 DANE resolver 时);
- 不配置时,DANE 兜底到公共解析器 `8.8.8.8:53`;
- 若你通过 `WithAgentDANEResolver` / `WithServerDANEResolver` 显式提供了 DANE resolver,则该字段不生效。

---

## 完整示例:两个 Agent 互相通信

### Agent A(Server)

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
log.Fatal(server.ListenAndServeTLS("", ""))
```

### Agent B(Client)

```go
client, _ := ati.NewAgentClient(
    ati.WithIdentityCert("client.crt", "client.key"),
    ati.WithTrustLevel(ati.BadgeRequired),
)

resp, err := client.Get(context.Background(), "https://agent-a.example.com:8443/hello")
if err != nil {
    log.Fatal(err) // 信任验证不通过
}
defer resp.Body.Close()

fmt.Println(resp.VerificationOutcome.AchievedLevel) // "BADGE_REQUIRED"
```

---

## 证书要求与 ATI Name

| 证书类型 | `ati://` URI SAN | CA 签发 | 用途 |
|---------|-----------------|---------|------|
| 客户端身份证书 | **必须** | 可自签 | 标识 Agent 身份,通过 Badge/TLog 指纹验证建立信任 |
| 服务端证书 | 建议 | 建议公有 CA | TLS 服务端认证,DNS SAN 需匹配主机名 |

**ATI Name 格式**(嵌入证书 URI SAN,是 Agent 身份的全局唯一标识):

```
ati://v{major}.{minor}.{patch}.{host}
```

示例:`ati://v1.0.0.my-agent.example.com`

---

## DNS 记录清单

服务发现走阿里云 API,不使用 DNS;以下 DNS 记录用于 Badge 与 DANE 验证:

| 记录 | 类型 | 用途 | 等级要求 |
|------|------|------|---------|
| `_ati-badge.<host>` | TXT | Badge URL(指向透明日志) | BadgeRequired 及以上 |
| `_443._tcp.<host>` | TLSA | 服务端证书 DANE 绑定 | DANEAndBadge(Client 验 Server) |
| `_ati-identity._tls.<host>` | TLSA | 客户端身份证书 DANE 绑定 | DANEAndBadge(Server 验 Client) |

---

## 验证缓存与失败语义

- **缓存**:Client 对同一服务端的验证结果按 `(host, 证书指纹)` 缓存;相同主机 + 相同证书的后续请求跳过重复验证。
- **DANE 失败开放(fail-open)语义**:DANE 只有在做出**明确的否定判断**时才拒绝连接——即 DNSSEC 保护下存在 TLSA 记录但与出示证书不匹配(`DANEMismatch`),或 DNSSEC 校验显式失败(`DANEDNSSECFailed`)。以下良性情况**不拒绝**:未发布 TLSA 记录(`DANENoRecords`)、有记录但无 DNSSEC 链(`DANESkipped`)。单纯的 DNS 查询错误交由调用方的失败策略处理。

---

## 示例代码

SDK 自带两个可运行的示例,位于 [`examples/`](examples/) 目录:

### Agent Server ([examples/agent-server](examples/agent-server))

一个 ATI Agent 服务端,启动 HTTPS 服务并对调用方进行信任验证。

```bash
cd examples/agent-server
go run main.go \
  -cert server.crt \
  -key server.key \
  -addr :8443 \
  -trust badge
```

### Agent Client ([examples/agent-client](examples/agent-client))

一个 ATI Agent 客户端,向目标 Agent 发起经过信任验证的 HTTPS 请求。

```bash
cd examples/agent-client
go run main.go \
  -cert client.crt \
  -key client.key \
  -url https://target-agent.example.com:8443/hello \
  -trust badge
```
