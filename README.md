# Alibaba ATI Go SDK

[![Go Reference](https://pkg.go.dev/badge/github.com/aliyun/alibaba-ati-golang-sdk.svg)](https://pkg.go.dev/github.com/aliyun/alibaba-ati-golang-sdk)

Agent Trust Infrastructure (ATI) 的 Go SDK,为 AI Agent 之间提供基于 **mTLS 传输 + 服务发现 + 多级信任验证** 的安全通信能力。

- **Client**(`ati.AgentClient`)—— Agent 作为调用方,发起经过验证的 HTTPS 请求。
- **Server**(`ati.NewServerTLSConfig`)—— Agent 作为服务方,在 TLS 握手阶段验证对端身份。

> 模块路径:`github.com/aliyun/alibaba-ati-golang-sdk`

---

## 目录

- [安装](#安装)
- [验证策略(VerificationPolicy)](#验证策略verificationpolicy)
- [快速开始](#快速开始)
- [全局配置(ati.Init)](#全局配置atiinit)
- [Client 端详解](#client-端详解)
- [Server 端详解](#server-端详解)
- [服务发现(DNS TXT)](#服务发现dns-txt)
- [版本匹配(Semver Range)](#版本匹配semver-range)
- [Dual-hostname 模型](#dual-hostname-模型)
- [CRL 证书吊销检查](#crl-证书吊销检查)
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

## 验证策略(VerificationPolicy)

SDK 提供四级验证策略,对齐 ATI Console 的分级标签。类型为 `ati.VerificationPolicy`:

| 常量 | Console 标签 | 验证内容 | 适用场景 |
|------|-------------|---------|---------|
| **`PolicyNone`** | L0 无认证 | 跳过 TLS 证书验证和 ATI 验证 | 仅限 dev/test 环境 |
| **`PolicyBasic`** | L1 基础认证 | 标准 PKI 证书校验(有效期、CA 链、SAN) | 基础安全需求 |
| **`PolicyEnhanced`** | L2 增强认证 | PKI + Badge 验证(透明日志指纹比对) | 身份可信要求 |
| **`PolicyAdvanced`** | L3 高级认证 | PKI + Badge + DANE/TLSA 验证 | 最高安全等级 |

### 向后兼容

旧常量仍可使用,但标记为 Deprecated:

| 旧名称 | 新名称 |
|--------|--------|
| `TrustLevel` | `VerificationPolicy` |
| `PKIOnly` | `PolicyBasic` |
| `BadgeRequired` | `PolicyEnhanced` |
| `DANEAndBadge` | `PolicyAdvanced` |

### PolicyNone 行为

**客户端**:设置 `PolicyNone` 后跳过所有 TLS 证书验证(`InsecureSkipVerify: true`),不执行 Badge/DANE,日志输出安全警告。仅在显式配置时启用,不作为默认值。

**服务端**:设置 `WithClientVerifier(PolicyNone)` 后不请求客户端证书(`NoClientCert`)。`PolicyNone` 不可与 `WithClientCA()` 同时使用。

### 每一级具体在做什么

**① PolicyBasic — 基础证书校验**
沿用标准 TLS 的证书检查:证书是否在有效期内、证书 SAN 是否与你要访问的主机名一致。CA 链校验是**有条件**的——**只有当你配置了私有根证书(CA bundle)时才会做 CA 链校验**;不配置时不校验 CA 链(接受任意证书),信任交由更高等级(Badge/TLog)建立。身份证书允许自签。

**② PolicyEnhanced — 身份徽章验证**
在 PKI 通过后,SDK 会:

1. 查询 DNS `_ati-badge.<host>` TXT 记录,拿到该 Agent 的 **Badge URL**(指向透明日志 Transparency Log);
2. 从透明日志取回该 Agent 的登记记录(含权威签发的证书指纹、Merkle 证明等);
3. 把**对端实际出示的证书指纹**与透明日志中登记的指纹做比对。

只有指纹一致才算通过。这一步回答的是"对端是不是它声称的那个已登记 Agent",防止拿一张合法但身份不符的证书冒充。

**③ PolicyAdvanced — DANE/TLSA 双重绑定**
在 Badge 通过后,再查询 DNSSEC 保护下的 TLSA 记录,把证书指纹与**域名所有者在 DNS 中发布的指纹**再绑定一次:

- Client 验 Server:查 `_443._tcp.<host>` 的 TLSA(`Verify`)。
- Server 验 Client:查 `_ati-identity._tls.<host>` 的 TLSA(`VerifyIdentity`)。

这一步把"信任锚"从透明日志扩展到"域名所有者 + DNSSEC 信任链",即使透明日志被绕过,攻击者仍需同时控制目标域名的 DNSSEC 签名才能伪造。

### 默认等级

- **Client 验 Server**:不调用 `WithTrustLevel` 时,默认使用 **`PolicyEnhanced`**;调用 `WithTrustLevel(X)` 则使用你指定的等级 `X`。两种情况都是**强制模式**——达不到目标等级时请求返回 error。
- **Server 验 Client**:**不调用 `WithClientVerifier` 时,什么都不验**——不请求客户端证书,等同于普通 TLS 直连;调用 `WithClientVerifier(X)` 则按等级 `X` 验证,达不到时 TLS 握手失败。
- **PKI 与私有根证书**:是否做 CA 链校验取决于你有没有配置私有根证书(CA bundle)。**没传私有根证书 → 不验 PKI 的 CA 链**(接受任意证书);**传了私有根证书 → 需要验 PKI 的 CA 链**,且即使没调用 `WithClientVerifier` 也会隐含按 `PolicyBasic` 验证。

> **DANE resolver 会自动创建**:当等级为 `PolicyAdvanced` 时,若未显式提供 DANE resolver,SDK 会自动构造一个默认的 `StandardDANEResolver`(默认走 DNSSEC 可用的公共解析器 `8.8.8.8:53`,也可通过 [`ati.Init` 的 `DNSServer`](#指定-dns-服务器) 覆盖)。因此 `WithAgentDANEResolver` / `WithServerDANEResolver` 属于**可选覆盖**,而非必填。

---

## 快速开始

### Client 最简示例

```go
package main

import (
    "context"
    "fmt"
    "io"
    "log"

    "github.com/aliyun/alibaba-ati-golang-sdk/ati"
)

func main() {
    // 全局配置身份证书
    if err := ati.Init(ati.Config{
        LocalHostname:    "my-agent.example.com",
        IdentityCertFile: "certs/client.crt",
        IdentityKeyFile:  "certs/client.key",
    }); err != nil {
        log.Fatal(err)
    }

    // 身份证书需包含 ati:// URI SAN,可自签
    client, err := ati.NewAgentClient(
        ati.WithIdentityCert("certs/client.crt", "certs/client.key"),
        // 不传 WithTrustLevel → 默认 PolicyEnhanced (Badge 验证)
    )
    if err != nil {
        log.Fatal(err)
    }

    resp, err := client.Get(context.Background(), "https://target-agent.example.com/api/data")
    if err != nil {
        log.Fatal(err) // 达不到 PolicyEnhanced 会返回 error
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
        ati.WithClientVerifier(ati.PolicyEnhanced), // 要求调用方通过 Badge 验证
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

---

## 全局配置(ati.Init)

`ati.Init` 用于在启动时集中管理默认身份和 DNS 服务器等全局配置:

```go
err := ati.Init(ati.Config{
    LocalHostname:    "my-agent.example.com", // 必填:本 Agent 主机名
    IdentityCertFile: "certs/identity.crt",   // 必填:身份证书
    IdentityKeyFile:  "certs/identity.key",   // 必填:身份私钥
    CARootFile:       "certs/root-ca.pem",    // 可选:私有根证书,配置后才做 PKI 的 CA 链校验
    TrustLevel:       ati.PolicyEnhanced,     // 可选,默认 PolicyEnhanced
    DNSServer:        "8.8.8.8:53",           // 可选,仅 DANE/TLSA 用
})
```

---

## Client 端详解

### 创建客户端

```go
client, err := ati.NewAgentClient(
    ati.WithIdentityCert("client.crt", "client.key"),   // 必填
    ati.WithTrustLevel(ati.PolicyEnhanced),             // 可选,不传默认 PolicyEnhanced
    ati.WithClientTimeout(30 * time.Second),            // 可选,默认 30s
)
```

### 配置项

| Option | 是否必填 | 说明 |
|--------|---------|------|
| `WithIdentityCert(certFile, keyFile string)` | **必填** | 客户端身份证书 + 私钥。证书必须含 `ati://` URI SAN,可自签。 |
| `WithMTLSCerts(id, key, serverCert, caBundle string)` | 替代上一项 | 需要用私有根证书(CA Bundle)校验服务端证书时使用;`serverCert` 传空即可。传了 CA Bundle 才会做 PKI 的 CA 链校验。 |
| `WithTrustLevel(level VerificationPolicy)` | 可选 | 目标验证策略。不传默认 `PolicyEnhanced`。 |
| `WithClientTimeout(d time.Duration)` | 可选 | HTTP 请求超时,默认 30s。 |
| `WithIdentityHost(host string)` | 可选 | Badge 和 identity DANE 查询使用的主机名,不设则使用连接 URL host。见 [Dual-hostname 模型](#dual-hostname-模型)。 |
| `WithAccessHost(host string)` | 可选 | Transport DANE (`_443._tcp`) 查询使用的主机名,不设则使用连接 URL host。见 [Dual-hostname 模型](#dual-hostname-模型)。 |
| `WithTargetVersion(version string)` | 可选 | 发现时指定目标版本,支持完整 semver range 表达式。见 [版本匹配](#版本匹配semver-range)。 |
| `WithAgentDANEResolver(r verify.DANEResolver)` | 可选 | 覆盖默认 DANE resolver(`PolicyAdvanced` 下会自动创建)。 |
| `WithTLogClient(t verify.TransparencyLogClient)` | 可选 | 自定义透明日志客户端(测试或私有部署)。 |
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

o.DNSDiscovered  // bool        服务发现成功(DNS TXT _ati 记录)
o.CAChainValid   // bool        CA 链有效(未配置私有根证书时视为 true)
o.SANMatches     // bool        证书 SAN 与目标主机匹配
o.BadgeVerified  // bool        Badge 验证通过
o.DANEVerified   // bool        DANE/TLSA 验证通过
o.AchievedLevel  // VerificationPolicy  实际达成的最高等级
o.RequestedLevel // *VerificationPolicy 请求的等级
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
    ati.WithClientVerifier(ati.PolicyEnhanced),      // 可选,不传则什么都不验
    ati.WithCRLCheck(),                              // 可选:启用 CRL 吊销检查
)
```

### 配置项

| Option | 是否必填 | 说明 |
|--------|---------|------|
| `WithServerCert(certFile, keyFile string)` | **必填** | 服务端证书 + 私钥。建议由公有 CA 签发,DNS SAN 含服务主机名。 |
| `WithClientCA(caBundle string)` | 可选 | 设置(私有根证书)后,Go TLS 层对客户端证书做 CA 链校验(`RequireAndVerifyClientCert`);不设则接受任意客户端证书(`RequireAnyClientCert`),信任交由 Badge/TLog 建立。 |
| `WithClientVerifier(level VerificationPolicy)` | 可选 | Server 对 Client 的验证策略。**不传则什么都不验**(不请求客户端证书,等同普通 TLS 直连);传了则达不到时握手失败。 |
| `WithCRLCheck()` | 可选 | 显式启用 CRL 证书吊销检查。有 CA bundle + trustLevel 时自动启用。见 [CRL 证书吊销检查](#crl-证书吊销检查)。 |
| `WithCRLCheckDisabled()` | 可选 | 显式关闭 CRL 检查(即使有 CA bundle 也不检查)。 |
| `WithCRLHTTPClient(client *http.Client)` | 可选 | 自定义 CRL 下载使用的 HTTP 客户端。 |
| `WithServerDANEResolver(r verify.DANEResolver)` | 可选 | 覆盖默认 DANE resolver(`PolicyAdvanced` 下会自动创建)。 |
| `WithPeerLevelStore(store *sync.Map)` | 可选 | 注入共享的 `sync.Map` 记录每个对端达成的等级,配合 `PeerTrustLevel` 在业务层查询。 |

### 验证行为矩阵

`WithClientVerifier` 与 `WithClientCA` 的组合决定了 server 验 client 的最终行为:

| `WithClientVerifier` | `WithClientCA` | TLS ClientAuth | 验证行为 |
|:---:|:---:|---|---|
| 不传 | 不传 | `NoClientCert` | **什么都不验**,不请求客户端证书,等同普通 TLS 直连 |
| `PolicyNone` | 不传 | `NoClientCert` | 显式不验证,不请求客户端证书 |
| 不传 | 传 | `RequireAndVerifyClientCert` | 隐含按 `PolicyBasic` 验证 + CA 链校验 |
| 传 | 不传 | `RequireAnyClientCert` | 按指定等级验证;自签证书靠 Badge/TLog 建立信任 |
| 传 | 传 | `RequireAndVerifyClientCert` | 按指定等级验证 + CA 链校验 + CRL 检查(自动启用) |

> 传了私有根证书(`WithClientCA`)即视为"要认证客户端",因此即便没调用 `WithClientVerifier` 也会隐含按 `PolicyBasic` 走,不会静默忽略。

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
        fmt.Printf("对端达成等级:%s\n", lvl) // 例如 "ENHANCED"
    }
}
```

---

## 服务发现(DNS TXT)

Agent 服务发现通过 DNS `_ati` TXT 记录完成。SDK 使用 `StandardDNSResolver.LookupATIDiscovery` 查询目标 Agent 的 TXT 记录,从中解析端点地址和版本信息。

**不再支持** OpenAPI 方式(`AliyunATIDiscovery` 已移除)。

### TXT 记录格式

```
_ati.<host>  TXT  "av=1.2.0;ep=https://target:8443;..."
```

- `av` — Agent 版本号(semver 格式)
- `ep` — Agent 端点地址

### 使用方式

服务发现在 Client 创建和请求时自动进行,无需额外配置凭证。可通过 `WithDNSResolver` 注入自定义 resolver(主要用于测试)。

---

## 版本匹配(Semver Range)

通过 `WithTargetVersion` 指定目标 Agent 版本约束。当 DNS TXT `_ati` 响应中包含多条记录时,SDK 按 semver 约束过滤并选取最新版本。

### 支持的约束格式

| 格式 | 含义 | 示例 |
|------|------|------|
| `1.2.3` 或 `v1.2.3` | 精确匹配 | 只匹配 1.2.3 |
| `^1.2.0` | 同 major 且 >= 指定版本 | >=1.2.0, <2.0.0 |
| `~1.2.0` | 同 major.minor 且 >= 指定版本 | >=1.2.0, <1.3.0 |
| `>=1.0.0` | >= 指定版本 | 所有 1.0.0 及以上 |
| `>=1.0.0 <2.0.0` | 范围表达式 | 指定区间内 |
| 不指定 | 返回所有记录中的最新版本 | — |

### 示例

```go
client, err := ati.NewAgentClient(
    ati.WithIdentityCert("client.crt", "client.key"),
    ati.WithTargetVersion("^1.2.0"), // 匹配 1.x.y (>=1.2.0, <2.0.0) 中最新版本
)
```

匹配逻辑:

1. 从 DNS TXT 响应中解析所有 `_ati` 记录的 `av` 字段
2. 按 semver constraint 过滤满足条件的记录
3. 在满足条件的记录中选取版本最高的
4. 无匹配时返回错误

依赖库:`github.com/Masterminds/semver/v3`

---

## Dual-hostname 模型

支持分离 Identity Hostname 和 Access Hostname,适用于代理网关场景下身份与访问地址不同的部署拓扑。

| 选项 | 用途 | 默认值 |
|------|------|--------|
| `WithIdentityHost(host)` | Badge 查询和 identity DANE 查询使用的主机名 | 连接 URL host |
| `WithAccessHost(host)` | Transport DANE (`_443._tcp`) 查询使用的主机名 | 连接 URL host |

### 使用场景

当 Agent 通过代理网关暴露服务时,实际访问地址(gateway.example.com)与 Agent 身份标识(my-agent.internal)不同:

```go
client, err := ati.NewAgentClient(
    ati.WithIdentityCert("client.crt", "client.key"),
    ati.WithTrustLevel(ati.PolicyAdvanced),
    ati.WithIdentityHost("my-agent.internal"),   // Badge/_ati-identity DANE 查此主机
    ati.WithAccessHost("gateway.example.com"),   // _443._tcp DANE 查此主机
)

// 请求发往 gateway,但身份验证查 my-agent.internal
resp, err := client.Get(ctx, "https://gateway.example.com/api")
```

不指定时两者均默认使用连接 URL 中的 host,行为与之前一致。

---

## CRL 证书吊销检查

服务端 mTLS 场景下,SDK 支持通过 PKIX CRL(Certificate Revocation List)验证客户端身份证书是否已被吊销。

### 工作原理

1. **CDP Discovery** — 从客户端 leaf cert 的 `CRLDistributionPoints` 扩展读取 CDP URL;leaf 无 CDP 时从 issuing CA cert 读取;链上均无 CDP 则跳过 CRL(debug 日志)
2. **CRL Fetch** — HTTP(S) GET 从 CDP URI 获取 CRL,并使用 issuing CA 公钥验证签名
3. **Revocation Check** — 若客户端证书序列号在 CRL 中,拒绝连接

### Fail-closed 语义

CDP 存在时采用 fail-closed 策略:

- CRL fetch 失败 → 拒绝 mTLS
- CRL 签名无效 → 拒绝 mTLS
- CRL 解析失败 → 拒绝 mTLS
- CDP 存在但无有效 HTTP(S) URI → 拒绝 mTLS

### 配置方式

```go
tlsConfig, err := ati.NewServerTLSConfig(
    ati.WithServerCert("server.crt", "server.key"),
    ati.WithClientCA("ca-bundle.pem"),
    ati.WithClientVerifier(ati.PolicyEnhanced),
    ati.WithCRLCheck(),                              // 显式启用(有 CA bundle + trustLevel 时自动启用)
    // ati.WithCRLCheckDisabled(),                   // 显式关闭
    // ati.WithCRLHTTPClient(customHTTPClient),      // 自定义 HTTP 客户端
)
```

### 适用范围

- 适用策略:`PolicyBasic` / `PolicyEnhanced` / `PolicyAdvanced`
- 不适用:`PolicyNone`
- CRL 与 Badge revocation 独立运行,任一失败即拒绝

### 缓存策略

- 按 CDP URI 缓存 CRL
- `nextUpdate` 到达时刷新;CRL 已过期(nextUpdate 已过)时强制立即重新拉取
- 最大缓存时间 12h

### 安全防护

- SSRF 防护:CDP URI 解析到内网/回环/link-local/元数据地址时拒绝请求
- 内存防护:CRL 响应体限制最大 10MiB

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

- `DNSServer` 只作用于**自动创建的 DANE resolver**(即等级为 `PolicyAdvanced` 且未显式提供 DANE resolver 时);
- 不配置时,DANE 兜底到公共解析器 `8.8.8.8:53`;
- 若你通过 `WithAgentDANEResolver` / `WithServerDANEResolver` 显式提供了 DANE resolver,则该字段不生效。

---

## 完整示例:两个 Agent 互相通信

### Agent A(Server)

```go
tlsConfig, _ := ati.NewServerTLSConfig(
    ati.WithServerCert("server.crt", "server.key"),
    ati.WithClientVerifier(ati.PolicyEnhanced),
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
    ati.WithTrustLevel(ati.PolicyEnhanced),
)

resp, err := client.Get(context.Background(), "https://agent-a.example.com:8443/hello")
if err != nil {
    log.Fatal(err) // 信任验证不通过
}
defer resp.Body.Close()

fmt.Println(resp.VerificationOutcome.AchievedLevel) // "ENHANCED"
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

服务发现使用 DNS TXT `_ati` 记录;以下 DNS 记录用于 Badge 与 DANE 验证:

| 记录 | 类型 | 用途 | 等级要求 |
|------|------|------|---------|
| `_ati.<host>` | TXT | Agent 服务发现(端点 + 版本) | 所有等级 |
| `_ati-badge.<host>` | TXT | Badge URL(指向透明日志) | PolicyEnhanced 及以上 |
| `_443._tcp.<host>` | TLSA | 服务端证书 DANE 绑定 | PolicyAdvanced(Client 验 Server) |
| `_ati-identity._tls.<host>` | TLSA | 客户端身份证书 DANE 绑定 | PolicyAdvanced(Server 验 Client) |

---

## 验证缓存与失败语义

- **缓存**:Client 对同一服务端的验证结果按 `(host, 证书指纹)` 缓存;相同主机 + 相同证书的后续请求跳过重复验证。
- **DANE 失败开放(fail-open)语义**:DANE 只有在做出**明确的否定判断**时才拒绝连接——即 DNSSEC 保护下存在 TLSA 记录但与出示证书不匹配(`DANEMismatch`),或 DNSSEC 校验显式失败(`DANEDNSSECFailed`)。以下良性情况**不拒绝**:未发布 TLSA 记录(`DANENoRecords`)、有记录但无 DNSSEC 链(`DANESkipped`)。单纯的 DNS 查询错误交由调用方的失败策略处理。
- **CRL fail-closed 语义**:与 DANE 不同,CRL 在 CDP 存在的前提下采用 fail-closed——fetch 失败、签名无效、解析错误均拒绝 mTLS 连接。

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
  -trust enhanced
```

### Agent Client ([examples/agent-client](examples/agent-client))

一个 ATI Agent 客户端,向目标 Agent 发起经过信任验证的 HTTPS 请求。

```bash
cd examples/agent-client
go run main.go \
  -cert client.crt \
  -key client.key \
  -url https://target-agent.example.com:8443/hello \
  -trust enhanced
```
