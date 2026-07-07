# mTLS 验证原理：证书从哪来、怎么验、为什么能信

v1.0 | 2026-06-16

本文档解释 ANS/ATI 体系中 mTLS 的完整信任链：密钥对如何生成、证书如何签发、mTLS 握手中双方如何验证对方、以及每一步的密码学原理。

---

## 1. 非对称加密基础

整个 PKI 体系建立在一个数学事实上：

```
私钥签名的数据 ──→ 只有对应的公钥能验证
公钥加密的数据 ──→ 只有对应的私钥能解密
```

私钥和公钥是数学上配对的。持有私钥 = 拥有身份。

---

## 2. 证书是什么

证书 = **公钥 + 身份信息 + CA 的签名**

CA（Certificate Authority）用自己的私钥签名，背书"这个公钥属于这个身份"。任何人拿到证书后，用 CA 的公钥验签，就能确认这份背书没被篡改。

ANS 体系中有两张证书：

| 证书 | 签发方 | SAN 类型 | SAN 值 | 用途 |
|------|--------|---------|--------|------|
| **Server Certificate** | Public CA | dNSName | FQDN（如 `support.example.com`） | 标准 TLS，证明域名控制权 |
| **Identity Certificate** | Private CA | URI | ANSName（如 `ans://v1.5.0.support.example.com`） | 版本绑定身份，用于 mTLS |

---

## 3. 证书从哪来：注册阶段

### 3.1 AHP 本地生成密钥对

```
AHP 本地：
  ┌──────────────────────┐
  │ 生成 ECDSA P-256 密钥对 │
  │                        │
  │ 私钥 ──→ 永远留在本地    │
  │ 公钥 ──→ 放进 CSR       │
  └──────────────────────┘
```

关键原则（ANS spec §4.3）：RA 永远不接触 AHP 的私钥。

### 3.2 CSR 提交与证书签发

```
AHP                              RA                         Private CA
 │                                │                              │
 │  CSR = {公钥, 身份信息,         │                              │
 │         用私钥签的签名}          │                              │
 │  ──────────────────────────→   │                              │
 │                                │  转发 CSR ──────────────→    │
 │                                │                              │
 │                                │                    验证 CSR 签名：
 │                                │                    用 CSR 里的公钥
 │                                │                    验证 CSR 上的签名
 │                                │                    ──→ 通过 = 申请者
 │                                │                        确实持有私钥
 │                                │                              │
 │                                │  ←── Identity Certificate    │
 │  ←── Identity Certificate ──── │     (CA 用自己的私钥签名)      │
 │      + Private CA 证书链        │                              │
 │      + DNS 记录内容             │                              │
 │                                │                              │
```

CSR 签名的作用：证明 AHP 持有与公钥配对的私钥，防止别人冒用 AHP 的公钥申请证书。CA 不需要看到私钥本身。

### 3.3 RA 返回给 AHP 的内容

| 返回内容 | 说明 |
|---------|------|
| Identity Certificate | Private CA 签发，URI SAN = ANSName |
| Private CA 证书链 | 中间 CA → 根 CA，用于构建完整验证链 |
| Server Certificate | Public CA 签发（仅当 AHP 提交了 serverCsrPEM 时；BYOC 模式下 AHP 已有） |
| DNS 记录内容 | `_ans` TXT、`_ans-badge` TXT、TLSA 等，AHP 需去 DNS provider 配置 |

不包含：AHP 的私钥（从不经过 RA）、`_ans-identity._tls` TLSA 记录（AHP 自己管理）。

### 3.4 AHP 安装证书

```
AHP Keystore:
  ┌────────────────────────────────────────┐
  │  Identity Certificate + 私钥 ──→ mTLS │
  │  Server Certificate   + 私钥 ──→ TLS  │
  │  Private CA 证书链    ──→ 验证对方用    │
  └────────────────────────────────────────┘
```

---

## 4. Private CA 根证书从哪来

Private CA 根证书不在操作系统/浏览器的公共信任库里。需要通过 **Trust Provisioner**（ADR 009）预装到 agent 的信任库。

| 部署模式 | 分发方式 |
|---------|---------|
| Public ANS | Trust Provisioner 自动分发 |
| Internal ANS | 企业 MDM（设备管理）推送 |
| Enterprise ANS | 企业云账户内的 trust store |
| Extranet ANS | Trust Provisioner 或共享 trust bundle |

SDK 初始化时完成预装（ANS spec §2.5）：单 RA 场景装一个根证书，联邦场景装多个 RA 的根证书 bundle。

**存放位置：SDK 管理的本地信任库**，不是系统级信任库。

---

## 5. mTLS 握手：完整验证流程

### 5.1 标准 TLS（单向验证）

普通 TLS 只验证 server：

```
Client                                    Server
  │  ClientHello ──────────────────────→    │
  │                                         │
  │  ←── ServerHello                        │
  │  ←── Server Certificate                 │  从 keystore 取出
  │       (包含公钥 + Public CA 签名)        │
  │  ←── CertificateVerify                  │  server 用私钥签名握手消息
  │                                         │
  │  验证：                                  │
  │  1. 证书链 → Public CA 根证书？ ✓         │
  │  2. SAN 域名 == 连接的 FQDN？ ✓          │
  │  3. 没过期？没吊销？ ✓                    │
  │  4. CertificateVerify 签名验证 ✓         │
  │     (用证书里的公钥验证)                   │
  │     验过 = server 确实持有私钥             │
  │                                         │
  │  ←──── 加密通道建立 ────────────────→    │
```

### 5.2 mTLS（双向验证）

mTLS 在标准 TLS 基础上增加 client 证书验证（ANS spec §4.5.1）：

```
Agent A (Client)                           Agent B (Server)
  │                                           │
  │  ClientHello ───────────────────────→     │
  │                                           │
  │  ←── ServerHello                          │
  │  ←── Server Certificate (Public CA)       │
  │  ←── CertificateRequest                   │  "我也要看你的证书"
  │  ←── CertificateVerify (server 签名)       │
  │                                           │
  │  A 验证 B 的 Server Certificate:           │
  │  1. 链追溯 → Public CA 根证书 ✓            │  (系统信任库里有)
  │  2. dNSName SAN == FQDN ✓                 │
  │  3. 没过期、没吊销 ✓                       │
  │  4. CertificateVerify 签名验证 ✓           │
  │                                           │
  │  发送 A 的 Identity Certificate ────→     │
  │  (URI SAN: ans://v1.0.0.agent-a.com)      │
  │  CertificateVerify ─────────────────→     │  A 用私钥签名握手消息
  │                                           │
  │                                B 验证 A 的 Identity Certificate:
  │                                1. 链追溯 → Private CA 根证书 ✓
  │                                   (Trust Provisioner 预装的)
  │                                2. URI SAN 格式合法 ✓
  │                                3. 没过期、没吊销 ✓
  │                                   (查 Private CA 的 OCSP)
  │                                4. CertificateVerify 签名验证 ✓
  │                                   (用 A 证书里的公钥验证)
  │                                   验过 = A 确实持有私钥
  │                                           │
  │  ←──── 双向认证 mTLS 通道建立 ──────→     │
```

### 5.3 验证的密码学本质

每一步验证都在回答一个问题：

| 步骤 | 问题 | 怎么证明 |
|------|------|---------|
| 证书链验证 | 这张证书是 CA 签发的吗？ | 用 CA 公钥验证证书上的签名 |
| CertificateVerify | 发证书的人真的持有对应私钥吗？ | 对方用私钥签名握手消息，我用证书里的公钥验签 |
| SAN 匹配 | 这张证书是给这个域名/身份的吗？ | 证书 SAN 字段 == 期望的域名或 ANSName |
| 吊销检查 | 这张证书还有效吗？ | 查询 CA 的 OCSP responder 或 CRL |

核心逻辑：**证书绑定了"公钥 <-> 身份"，CertificateVerify 证明了"对方持有私钥"，两者合起来证明了"对方就是证书声称的那个身份"。**

---

## 6. 握手后：ANS 业务层验证

mTLS 通道建立后，TLS 层面的验证已完成。ANS 在此基础上叠加独立验证通道。

### 6.1 A 验证 B（ANS spec §4.5.1 Step 6）

A 作为 client 主动连接 B，需要确认"我连对人了"：

```
mTLS 建立后，A 额外做:

Bronze: 到此为止（PKI only）
  └── 已完成：B 的 Server Certificate 由 Public CA 签发且域名匹配

Silver: + DANE 验证
  └── 查 DNS: _443._tcp.{B的FQDN} TLSA 记录
      比对 B 的 Server Certificate 指纹 == TLSA 记录值
      (需 DNSSEC 保护，防止 DNS 被篡改)

Gold: + TL 验证
  └── 查 DNS: _ans-badge.{B的FQDN} TXT 记录 → 获取 badge URL
      从 TL 拉取 inclusion proof
      验证 B 的注册确实被 seal 进了透明日志
```

### 6.2 B 验证 A

B 作为 server 在 mTLS 握手中已通过 Private CA 链验证了 A 的 Identity Certificate。握手后，B 可以选择做更深的验证：

```
TLS 层面已完成: A 持有合法的 Identity Certificate ✓

B 可选择额外做:
  从 A 的 Identity Certificate URI SAN 提取 ANSName
  ──→ 解析出 A 的 FQDN 和版本

Bronze: 到此为止
Silver: 查 A 的 DANE TLSA 记录
Gold:   查 A 的 _ans-badge → TL inclusion proof
```

验证深度是每个 agent 自己的信任策略决定的（ANS spec §4.1.1）：

> "A tier describes what the *client* verified, not a property the RA assigned."

---

## 7. 不对称设计：为什么 A 和 B 用不同证书

| | A（Client） | B（Server） |
|---|------------|------------|
| **发出的证书** | Identity Certificate（Private CA） | Server Certificate（Public CA） |
| **对方用什么验证** | Private CA 根证书（Trust Provisioner 预装） | Public CA 根证书（系统信任库自带） |
| **SAN 类型** | URI（`ans://v1.0.0.agent-a.com`） | dNSName（`support.example.com`） |

原因：

1. **Server Certificate 必须来自 Public CA**：因为非 ANS 客户端（浏览器、普通 HTTP 客户端）也需要连接 agent 的 FQDN，它们不认 Private CA。
2. **Identity Certificate 必须来自 Private CA**：因为它需要 URI SAN（`ans://` scheme），CA/B Forum 禁止 Public CA 在 server 证书中使用 URI SAN。
3. **Server Certificate 绑定域名，Identity Certificate 绑定版本**：域名跨版本稳定，版本每次变更。两个生命周期不同。

### 7.1 A 作为 client 需要 Private CA 根证书吗？

**在 client 角色中不需要。** A 验证 B 的 Server Certificate 用的是系统信任库里的 Public CA 根证书。

A 需要 Private CA 根证书的场景是 **A 作为 server 时**——当其他 agent 调用 A，对方会发 Identity Certificate，A 需要 Private CA 根证书来验证对方。

每个 ANS agent 都可能同时扮演 client 和 server 两个角色，所以都需要预装 Private CA 根证书。

---

## 8. DANE：为什么要第二条验证通道

PKI 的弱点：如果 CA 被攻破，攻击者能签一张假证书。DANE 通过 DNS 增加第二条独立信任通道。

```
信任通道 1: PKI                    信任通道 2: DNS (DNSSEC)
  │                                  │
  Server Certificate                 _443._tcp TLSA 记录
  指纹: SHA256:abcd...               包含指纹: SHA256:abcd...
  │                                  │
  └──────── 两边必须一致 ────────────┘
```

攻击者要同时攻破 CA 系统 + DNSSEC 才能伪造，难度指数级上升。

TLSA 记录参数：`TLSA 3 0 1 [sha256_hash]`
- 3 = DANE-EE（直接验证证书，不走 CA 链）
- 0 = 完整证书（selector）
- 1 = SHA-256（matching type）

DANE 要求 DNSSEC。没有 DNSSEC 的域名无法使用 DANE 验证（RFC 6698 §4）。

---

## 9. TL 验证：为什么要第三条验证通道

PKI + DANE 证明了"这个证书是合法的、指纹和 DNS 一致"。但无法证明"这个 agent 的注册事件确实被记录在不可篡改的日志里"。

TL（Transparency Log）提供 inclusion proof：

```
TL 验证步骤:
1. 查 DNS: _ans-badge.{host} → 获取 badge URL
2. 从 TL 获取 badge（含 sealed event + inclusion proof）
3. 验证 TL 签名（用 TL 公钥，从 /root-keys 获取）
4. 验证 Merkle inclusion proof（数学证明事件在日志中）
5. 比对 badge 中的证书指纹 == 握手中的证书指纹
```

三条通道的信任锚点各自独立：

| 通道 | 信任锚点 | 攻破它意味着 |
|------|---------|------------|
| PKI | CA 系统 | CA 被攻破 |
| DANE | DNSSEC | DNS 根签名被攻破 |
| TL | KMS 签名密钥 | TL 日志被篡改 |

Gold 验证 = 三条通道全部通过。攻击者需要同时攻破三个独立系统。

---

## 10. 总结：一句话

**证书绑定了"公钥 <-> 身份"，TLS 握手中的 CertificateVerify 证明了"对方持有私钥"，两者合起来证明了"对方就是证书声称的那个身份"。DANE 和 TL 在此基础上叠加独立信任通道，防止任何单点失败。**
