# ATI 全流程配置指南（含私签服务端证书测试方案）

v1.0 | 2026-06-22

本文档基于 ATI MVP PRD v2.0 的证书申请流程，结合**服务端证书使用私签**的测试需求，提供完整的端到端配置说明。

---

## 1. 总览：文件清单

完成本指南后，你的目录结构如下：

```
certs/
├── ca/
│   ├── root-ca.key           # 根 CA 私钥（测试用，生产不存在这个）
│   ├── root-ca.pem           # 根 CA 证书（= ca_bundle.pem 的内容）
│   └── root-ca.srl           # 序列号文件（自动生成）
├── server/
│   ├── server.key            # 服务端私钥
│   ├── server.csr            # 服务端 CSR
│   └── server-cert.pem       # 服务端证书（根 CA 签发，dNSName SAN）
├── client/
│   ├── identity.key          # 客户端私钥
│   ├── identity.csr          # 客户端 CSR
│   └── identity-cert.pem     # 客户端身份证书（根 CA 签发，URI SAN: ati://）
└── ca_bundle.pem             # → 就是 root-ca.pem 的拷贝
```

**与生产环境的差异：**

| 项目 | 生产环境 | 测试环境（本文档） |
|------|---------|-----------------|
| Server Certificate 签发方 | Public CA（如 DigiCert、Let's Encrypt） | 自建 Private CA |
| Identity Certificate 签发方 | CNNIC Private CA（通过 RA） | 同一个自建 Private CA |
| ca_bundle.pem 内容 | CNNIC Private CA 根证书 | 自建 Private CA 根证书 |
| DNS `_ati` 记录 | 真实 DNS 配置 | Mock DNS resolver |
| TL Badge 验证 | 真实 TL 服务 | Mock TL client |

---

## 2. 第一步：创建自签根 CA

```bash
# 生成根 CA 私钥（ECDSA P-256，与 ATI 体系一致）
openssl ecparam -genkey -name prime256v1 -noout -out certs/ca/root-ca.key

# 生成根 CA 自签证书（有效期 10 年）
openssl req -new -x509 -key certs/ca/root-ca.key \
  -out certs/ca/root-ca.pem \
  -days 3650 \
  -subj "/CN=ATI Test Root CA/O=Test/C=CN"

# 创建 ca_bundle.pem（两个角色共用）
cp certs/ca/root-ca.pem certs/ca_bundle.pem
```

这个根 CA 在测试中同时承担：
- Public CA 的角色 → 签发 Server Certificate
- Private CA 的角色 → 签发 Identity Certificate

---

## 3. 第二步：生成服务端证书（Server Certificate）

### 3.1 创建 OpenSSL 扩展配置

```bash
cat > certs/server/server-ext.cnf << 'EOF'
[req]
distinguished_name = dn
req_extensions = v3_req

[dn]

[v3_req]
subjectAltName = @alt_names
keyUsage = digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth

[alt_names]
DNS.1 = agent-b.example.com
DNS.2 = localhost
IP.1 = 127.0.0.1
EOF
```

> **说明**：Server Certificate 使用 **dNSName** SAN，绑定服务端的 FQDN。
> 生产环境中这张证书来自 Public CA，SAN 只有域名。测试时加 localhost/127.0.0.1 方便本地调试。

### 3.2 生成密钥和 CSR

```bash
# 生成服务端私钥
openssl ecparam -genkey -name prime256v1 -noout -out certs/server/server.key

# 生成 CSR
openssl req -new -key certs/server/server.key \
  -out certs/server/server.csr \
  -subj "/CN=agent-b.example.com/O=Test Agent B" \
  -config certs/server/server-ext.cnf
```

### 3.3 用根 CA 签发

```bash
openssl x509 -req -in certs/server/server.csr \
  -CA certs/ca/root-ca.pem \
  -CAkey certs/ca/root-ca.key \
  -CAcreateserial \
  -out certs/server/server-cert.pem \
  -days 365 \
  -extfile certs/server/server-ext.cnf \
  -extensions v3_req
```

### 3.4 验证

```bash
openssl x509 -in certs/server/server-cert.pem -text -noout | grep -A2 "Subject Alternative Name"
# 应看到: DNS:agent-b.example.com, DNS:localhost, IP:127.0.0.1
```

---

## 4. 第三步：生成客户端身份证书（Identity Certificate）

### 4.1 创建 OpenSSL 扩展配置

```bash
cat > certs/client/identity-ext.cnf << 'EOF'
[req]
distinguished_name = dn
req_extensions = v3_req

[dn]

[v3_req]
subjectAltName = @alt_names
keyUsage = digitalSignature
extendedKeyUsage = clientAuth

[alt_names]
URI.1 = ati://v1.0.0.agent-a.example.com
EOF
```

> **关键**：Identity Certificate 使用 **URI SAN**，格式为 `ati://{version}.{fqdn}`。
> SDK 在加载时会检查 URI SAN 必须以 `ati://` 开头（见 `mtls_client.go:163-169`）。

### 4.2 生成密钥和 CSR

```bash
# 生成客户端私钥
openssl ecparam -genkey -name prime256v1 -noout -out certs/client/identity.key

# 生成 CSR
openssl req -new -key certs/client/identity.key \
  -out certs/client/identity.csr \
  -subj "/CN=agent-a.example.com/O=Test Agent A" \
  -config certs/client/identity-ext.cnf
```

### 4.3 用根 CA 签发

```bash
openssl x509 -req -in certs/client/identity.csr \
  -CA certs/ca/root-ca.pem \
  -CAkey certs/ca/root-ca.key \
  -CAcreateserial \
  -out certs/client/identity-cert.pem \
  -days 365 \
  -extfile certs/client/identity-ext.cnf \
  -extensions v3_req
```

### 4.4 验证

```bash
openssl x509 -in certs/client/identity-cert.pem -text -noout | grep -A2 "Subject Alternative Name"
# 应看到: URI:ati://v1.0.0.agent-a.example.com
```

---

## 5. 第四步：配置服务端（Agent B）

### 5.1 SDK 调用

```go
import "gitlab.alibaba-inc.com/alibaba-dns/ati-golang-sdk/ati"

tlsConfig, err := ati.NewServerTLSConfig(
    // 服务端证书 + 私钥：TLS 握手时发给 client
    ati.WithServerCert("certs/server/server-cert.pem", "certs/server/server.key"),

    // CA bundle：验证 client 发来的 Identity Certificate
    // 因为 Identity Cert 是我们的根 CA 签的，所以这里放根 CA 证书
    ati.WithClientCA("certs/ca_bundle.pem"),
)
```

### 5.2 参数说明

| 参数 | 文件 | 作用 |
|------|------|------|
| `serverCert` | `server-cert.pem` | TLS 握手时服务端出示的证书（含 dNSName SAN） |
| `privateKey` | `server.key` | 服务端私钥，用于 TLS CertificateVerify 签名 |
| `caBundle` | `ca_bundle.pem` | 验证 client Identity Certificate 的 CA 根（设为 `ClientCAs`） |

### 5.3 验证行为

| 配置 | ClientAuth 模式 | 行为 |
|------|----------------|------|
| 有 `WithClientCA` | `RequireAndVerifyClientCert` | CA 链验证 + Badge 指纹验证 |
| 无 `WithClientCA` | `RequireAnyClientCert` | 仅 Badge 指纹验证（自签证书可通过） |

Badge 验证流程（server 侧）：
1. 从 client Identity Cert 的 URI SAN 提取 FQDN
2. 查询 `_ati-badge.{client_fqdn}` TXT 记录 → 获取 TL URL
3. 从 TL 拉取 badge → 比对 client Identity Cert 指纹
4. 通过 = 确认这是经过 RA 注册的合法 agent

### 5.4 启动 HTTPS 服务

```go
import (
    "net/http"
    "crypto/tls"
)

server := &http.Server{
    Addr:      ":8443",
    TLSConfig: tlsConfig,
    Handler:   yourHandler,
}

// 因为 TLS 配置已经包含证书，传空字符串
server.ListenAndServeTLS("", "")
```

---

## 6. 第五步：配置客户端（Agent A）

### 6.1 SDK 调用

```go
import "gitlab.alibaba-inc.com/alibaba-dns/ati-golang-sdk/ati"

client, err := ati.NewAgentClient(
    // 客户端身份证书 + 私钥：mTLS 握手时发给 server
    ati.WithIdentityCert("certs/client/identity-cert.pem", "certs/client/identity.key"),

    // CA bundle：验证 server 的 Server Certificate
    // 因为 Server Cert 是我们的根 CA 签的（私签），必须指定
    ati.WithMTLSCerts(
        "certs/client/identity-cert.pem",
        "certs/client/identity.key",
        "",                      // serverCert：客户端不需要额外 server cert 文件
        "certs/ca_bundle.pem",   // caBundle：验证对方 Server Certificate 的 CA 根
    ),
)
```

> **注意**：`WithMTLSCerts` 和 `WithIdentityCert` 二选一。`WithMTLSCerts` 是完整版，
> 第四个参数 `caBundle` 设置 TLS RootCAs，用于验证 server 的 Server Certificate。

### 6.2 参数说明

| 参数 | 文件 | 作用 |
|------|------|------|
| `identityCert` | `identity-cert.pem` | mTLS 握手时客户端出示的身份证书（含 URI SAN） |
| `privateKey` | `identity.key` | 客户端私钥，用于 TLS CertificateVerify 签名 |
| `serverCert` | （空） | 客户端角色不需要 |
| `caBundle` | `ca_bundle.pem` | 验证 server 的 Server Certificate（设为 TLS `RootCAs`） |

### 6.3 ca_bundle.pem 是否必须？

| 场景 | 是否必须 | 原因 |
|------|---------|------|
| Server Cert 来自 Public CA | 不必须 | `RootCAs = nil` 时 Go 自动使用系统 CA 信任库 |
| Server Cert 来自私签 CA（本文档） | **必须** | 系统信任库里没有你的私签 CA 根证书 |

SDK 代码逻辑（`mtls_client.go:178-188`）：
```go
if cfg.caBundleFile != "" {
    // 读取 CA bundle，创建新的 CertPool
    caCertPool = x509.NewCertPool()
    caCertPool.AppendCertsFromPEM(caBundlePEM)
}
// caCertPool == nil → tls.Config.RootCAs uses system CA pool
```

### 6.4 发起请求

```go
resp, err := client.Get(ctx, "https://agent-b.example.com:8443/api/v1/hello")
if err != nil {
    log.Fatal(err)
}
defer resp.Body.Close()

// 查看验证结果
outcome := resp.VerificationOutcome
fmt.Printf("DNS discovered: %v\n", outcome.DNSDiscovered)
fmt.Printf("CA chain valid: %v\n", outcome.CAChainValid)
fmt.Printf("SAN matches: %v\n", outcome.SANMatches)
fmt.Printf("Achieved level: %s\n", outcome.AchievedLevel)
```

---

## 7. 第六步：DNS 记录配置（或 Mock）

### 7.1 生产环境需要的 DNS 记录

ATI 体系需要以下 DNS 记录（PRD §4.4）：

| 记录类型 | 名称 | 用途 | 对应验证级别 |
|---------|------|------|------------|
| TXT | `_ati.{fqdn}` | Agent 发现（含 agentID） | PKI (Level 1) |
| TXT | `_ati-badge.{fqdn}` | Badge/TL URL 指向 | Badge (Level 2) |
| TLSA | `_443._tcp.{fqdn}` | Server Cert 指纹 | Full/DANE (Level 3) |
| TLSA | `_ati-identity._tls.{fqdn}` | Identity Cert 指纹 | Full/DANE (Level 3) |
| HTTPS | `{fqdn}` | 端口/协议绑定 | 可选 |

### 7.2 测试环境 Mock 配置

本地测试不需要真实 DNS。SDK 支持注入自定义 resolver：

```go
// 客户端 mock DNS
client, err := ati.NewAgentClient(
    ati.WithIdentityCert("certs/client/identity-cert.pem", "certs/client/identity.key"),
    ati.WithMTLSCerts("certs/client/identity-cert.pem", "certs/client/identity.key", "", "certs/ca_bundle.pem"),
    ati.WithDNSResolver(mockResolver),  // 注入 mock
    ati.WithTLogClient(mockTLog),       // 注入 mock TL
)
```

Mock DNS resolver 示例：

```go
type MockDNSResolver struct{}

func (m *MockDNSResolver) LookupATIDiscovery(ctx context.Context, fqdn models.Fqdn) (*verify.ATIDiscoveryResult, error) {
    return &verify.ATIDiscoveryResult{
        Found: true,
        Records: []verify.ATIRecord{
            {ID: "test-agent-b-001"},
        },
    }, nil
}

func (m *MockDNSResolver) LookupATIBadge(ctx context.Context, fqdn models.Fqdn) (*verify.ATIBadgeResult, error) {
    return &verify.ATIBadgeResult{
        Found: true,
        URL:   "https://tl.ansagent.cn:8180/ans/api/v1/tl/agents/test-agent-b-001/logs/latest",
    }, nil
}
```

Mock TL client 示例：

```go
type MockTLogClient struct {
    // 预设的 badge 响应，包含 server 的 Identity Cert 指纹
    expectedFingerprint string
}

func (m *MockTLogClient) FetchTLResponse(ctx context.Context, url string) (*verify.TLResponse, error) {
    return &verify.TLResponse{
        Fingerprint: m.expectedFingerprint,
        Hostname:    "agent-b.example.com",
        ATIName:     "ati://v1.0.0.agent-b.example.com",
        Status:      "ACTIVE",
    }, nil
}
```

---

## 8. 验证级别与测试可达性

| 验证级别 | 生产环境 | 本地测试（私签 + Mock） | 说明 |
|---------|---------|----------------------|------|
| **TrustPKI** | ✅ | ✅ | CA 链验证（ca_bundle.pem）+ DNS 发现（mock）+ SAN 匹配 |
| **TrustBadge** | ✅ | ✅ | PKI + Badge 指纹比对（mock TL 返回匹配的指纹） |
| **TrustFull** | ✅ | ✅ | Badge + DANE TLSA 验证（需 mock DANEResolver） |

全部三个级别在测试环境都可以通过 Mock 达到。

---

## 9. 完整测试示例

### 9.1 一键生成所有证书

```bash
#!/bin/bash
set -e

CERT_DIR="./certs"
mkdir -p $CERT_DIR/{ca,server,client}

# === 根 CA ===
openssl ecparam -genkey -name prime256v1 -noout -out $CERT_DIR/ca/root-ca.key
openssl req -new -x509 -key $CERT_DIR/ca/root-ca.key \
  -out $CERT_DIR/ca/root-ca.pem -days 3650 \
  -subj "/CN=ATI Test Root CA/O=Test/C=CN"
cp $CERT_DIR/ca/root-ca.pem $CERT_DIR/ca_bundle.pem

# === Server Certificate ===
cat > /tmp/server-ext.cnf << 'EOF'
[v3_req]
subjectAltName = DNS:agent-b.example.com,DNS:localhost,IP:127.0.0.1
keyUsage = digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
EOF

openssl ecparam -genkey -name prime256v1 -noout -out $CERT_DIR/server/server.key
openssl req -new -key $CERT_DIR/server/server.key \
  -out $CERT_DIR/server/server.csr \
  -subj "/CN=agent-b.example.com/O=Test Agent B"
openssl x509 -req -in $CERT_DIR/server/server.csr \
  -CA $CERT_DIR/ca/root-ca.pem -CAkey $CERT_DIR/ca/root-ca.key -CAcreateserial \
  -out $CERT_DIR/server/server-cert.pem -days 365 \
  -extfile /tmp/server-ext.cnf -extensions v3_req

# === Identity Certificate (Client) ===
cat > /tmp/identity-ext.cnf << 'EOF'
[v3_req]
subjectAltName = URI:ati://v1.0.0.agent-a.example.com
keyUsage = digitalSignature
extendedKeyUsage = clientAuth
EOF

openssl ecparam -genkey -name prime256v1 -noout -out $CERT_DIR/client/identity.key
openssl req -new -key $CERT_DIR/client/identity.key \
  -out $CERT_DIR/client/identity.csr \
  -subj "/CN=agent-a.example.com/O=Test Agent A"
openssl x509 -req -in $CERT_DIR/client/identity.csr \
  -CA $CERT_DIR/ca/root-ca.pem -CAkey $CERT_DIR/ca/root-ca.key -CAcreateserial \
  -out $CERT_DIR/client/identity-cert.pem -days 365 \
  -extfile /tmp/identity-ext.cnf -extensions v3_req

echo "=== 证书生成完毕 ==="
echo "Server cert SAN:"
openssl x509 -in $CERT_DIR/server/server-cert.pem -text -noout | grep -A1 "Subject Alternative"
echo ""
echo "Identity cert SAN:"
openssl x509 -in $CERT_DIR/client/identity-cert.pem -text -noout | grep -A1 "Subject Alternative"
```

### 9.2 Go 集成测试代码

```go
package main

import (
    "context"
    "fmt"
    "io"
    "log"
    "net/http"
    "time"

    "gitlab.alibaba-inc.com/alibaba-dns/ati-golang-sdk/ati"
)

func main() {
    // --- 启动 Server ---
    tlsConfig, err := ati.NewServerTLSConfig(
        ati.WithServerCert("certs/server/server-cert.pem", "certs/server/server.key"),
        ati.WithClientCA("certs/ca_bundle.pem"),
    )
    if err != nil {
        log.Fatal("Server TLS config error:", err)
    }

    mux := http.NewServeMux()
    mux.HandleFunc("/hello", func(w http.ResponseWriter, r *http.Request) {
        // 读取 peer ATI Name
        atiName, _ := ati.PeerATIName(r.TLS)
        fmt.Fprintf(w, "Hello, %s!", atiName.Raw)
    })

    server := &http.Server{
        Addr:      ":8443",
        Handler:   mux,
        TLSConfig: tlsConfig,
    }
    go server.ListenAndServeTLS("", "")
    time.Sleep(100 * time.Millisecond)

    // --- 启动 Client ---
    client, err := ati.NewAgentClient(
        ati.WithMTLSCerts(
            "certs/client/identity-cert.pem",
            "certs/client/identity.key",
            "",
            "certs/ca_bundle.pem",
        ),
        ati.WithDNSResolver(&MockDNSResolver{}),
        ati.WithTLogClient(&MockTLogClient{}),
    )
    if err != nil {
        log.Fatal("Client error:", err)
    }

    // --- 发起请求 ---
    resp, err := client.Get(context.Background(), "https://localhost:8443/hello")
    if err != nil {
        log.Fatal("Request error:", err)
    }
    defer resp.Body.Close()

    body, _ := io.ReadAll(resp.Body)
    fmt.Println("Response:", string(body))
    fmt.Printf("Verification: DNS=%v CA=%v SAN=%v Level=%s\n",
        resp.VerificationOutcome.DNSDiscovered,
        resp.VerificationOutcome.CAChainValid,
        resp.VerificationOutcome.SANMatches,
        resp.VerificationOutcome.AchievedLevel,
    )
}
```

---

## 10. 常见问题

### Q1: 为什么 Client 和 Server 用不同类型的证书？

| | Client（Agent A） | Server（Agent B） |
|---|---|---|
| 证书类型 | Identity Certificate | Server Certificate |
| SAN 类型 | URI (`ati://v1.0.0.agent-a.com`) | dNSName (`agent-b.example.com`) |
| 签发方（生产） | CNNIC Private CA | Public CA |
| 签发方（测试） | 自建根 CA | 自建根 CA |

原因：Server 需要被非 ATI 客户端（浏览器等）访问，必须用 Public CA 签发的 dNSName 证书。Identity Certificate 绑定版本号，使用 URI SAN（CA/B Forum 禁止 Public CA 发 URI SAN）。

### Q2: ca_bundle.pem 在 Client 和 Server 里分别验证什么？

| 角色 | ca_bundle.pem 验证对象 | TLS 字段 |
|------|----------------------|---------|
| Client | Server 的 Server Certificate | `tls.Config.RootCAs` |
| Server | Client 的 Identity Certificate | `tls.Config.ClientCAs` |

测试环境中两边用同一个 ca_bundle.pem（都是自建根 CA），生产环境中：
- Client 端不需要 ca_bundle（Server Cert 来自 Public CA，系统信任库自带）
- Server 端需要 CNNIC Private CA 根证书（Identity Cert 来自 Private CA）

### Q3: 不配 ca_bundle 可以吗？

- **Client 侧**：不配 `caBundle` → `RootCAs = nil` → 用系统 CA 信任库。如果 Server Cert 是私签的，验证会失败（`x509: certificate signed by unknown authority`）。
- **Server 侧**：不配 `WithClientCA` → `ClientAuth = RequireAnyClientCert`。不做 CA 链验证，仅靠 Badge 指纹验证 client 身份。自签 Identity Cert 也能通过。

### Q4: 同一个 agent 既是 Client 又是 Server 怎么配？

需要两套证书：
- 作为 Server：`server-cert.pem` + `server.key`（dNSName SAN）
- 作为 Client：`identity-cert.pem` + `identity.key`（URI SAN `ati://`）

两个角色的私钥不同，证书不同，SAN 类型不同。但可以由同一个 CA 签发。

### Q5: 测试环境要怎么做 Badge 验证？

Badge 验证流程：DNS lookup `_ati-badge.{fqdn}` → 获取 TL URL → 从 TL 拉取 badge → 比对指纹。

测试时通过 `WithDNSResolver` 和 `WithTLogClient` 注入 mock 实现。Mock TL 返回的指纹必须与对方证书的实际指纹一致。

获取证书指纹：
```bash
openssl x509 -in certs/client/identity-cert.pem -outform DER | openssl dgst -sha256
# 或
openssl x509 -in certs/server/server-cert.pem -outform DER | openssl dgst -sha256
```

---

## 11. 与 ATI PRD 注册流程的对应关系

PRD 描述的生产注册流程 → 本测试方案的对应：

| PRD 步骤 | 生产操作 | 测试替代 |
|---------|---------|---------|
| 步骤一：填写 Agent 基本信息 | Console 录入 FQDN、类型等 | 直接在 openssl 命令中指定 |
| 步骤二：域名预检（ACME） | Console 校验域名控制权 | 跳过（私签不需要） |
| 步骤三：生成密钥对 + CSR | AHP 本地生成，提交 CSR | `openssl ecparam -genkey` + `openssl req -new` |
| RA 签发 Identity Certificate | CNNIC Private CA 签发 | `openssl x509 -req -CA root-ca.pem` |
| RA 返回 CA 证书链 | CNNIC CA chain | 就是 `root-ca.pem` |
| Server Certificate 签发 | Public CA（ACME/Console） | `openssl x509 -req -CA root-ca.pem`（私签） |
| DNS 记录配置 | 在 DNS provider 添加 5 条记录 | Mock DNSResolver |
| Badge 上链 | RA 调 TL API seal 注册事件 | Mock TLogClient |

---

## 12. 安全注意事项

1. **私钥永远不离开生成它的机器**：`identity.key` 和 `server.key` 不应出现在 Git 仓库、日志、传输通道中。
2. **测试根 CA 私钥是生产 zero-trust 的破窗**：`root-ca.key` 只用于测试。如果有人拿到这个文件，可以签发任意证书。
3. **生产环境不应使用本文档的根 CA**：生产的 Identity Cert 由 CNNIC 签发，Server Cert 由 Public CA 签发。
4. **TLS 1.3 最低版本**：SDK 强制 `MinVersion: tls.VersionTLS13`，不支持降级。

---

## 附录 A：证书文件和 SDK 参数映射

```
┌─────────────────────────────────────────────────────────────────┐
│                        CLIENT (Agent A)                          │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  WithMTLSCerts(                                                  │
│    identityCert: "identity-cert.pem"  ←─ mTLS 出示给 server     │
│    privateKey:   "identity.key"       ←─ CertificateVerify 签名  │
│    serverCert:   ""                   ←─ client 不需要           │
│    caBundle:     "ca_bundle.pem"      ←─ 验证 server 的证书      │
│  )                                       (设为 tls.RootCAs)      │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────┐
│                        SERVER (Agent B)                          │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  NewServerTLSConfig(                                             │
│    WithServerCert(                                               │
│      serverCert: "server-cert.pem"    ←─ TLS 出示给 client       │
│      privateKey: "server.key"         ←─ CertificateVerify 签名  │
│    ),                                                            │
│    WithClientCA(                                                  │
│      caBundle:   "ca_bundle.pem"      ←─ 验证 client 的身份证书   │
│    ),                                    (设为 tls.ClientCAs)     │
│  )                                                               │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

---

## 附录 B：mTLS 握手中证书的流向

```
Agent A (Client)                              Agent B (Server)
     │                                              │
     │  ── ClientHello ──────────────────────→      │
     │                                              │
     │  ←─ ServerHello                              │
     │  ←─ server-cert.pem (dNSName SAN)           │  从 keystore 取出
     │  ←─ CertificateRequest                       │  "请也给我你的证书"
     │  ←─ CertificateVerify (server.key 签名)      │
     │                                              │
     │  A 用 ca_bundle.pem 验证 server-cert.pem:    │
     │  ✓ 证书链 → 根 CA                            │
     │  ✓ dNSName == 连接的 hostname                 │
     │  ✓ 没过期                                    │
     │  ✓ CertificateVerify 签名正确                 │
     │                                              │
     │  ── identity-cert.pem (URI SAN) ─────→       │
     │  ── CertificateVerify (identity.key 签名) →  │
     │                                              │
     │                          B 用 ca_bundle.pem 验证 identity-cert.pem:
     │                          ✓ 证书链 → 根 CA
     │                          ✓ URI SAN: ati://v1.0.0.agent-a.example.com
     │                          ✓ 没过期
     │                          ✓ CertificateVerify 签名正确
     │                                              │
     │  ←──── mTLS 通道建立 ────────────────→       │
     │                                              │
     │  (后续 Badge/DANE 验证在应用层进行)            │
```
