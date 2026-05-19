# ATI 系统映射（阿里云 + CNNIC ↔ GoDaddy ANS）

## 一、SDK 需要沟通的角色 & 对应 GoDaddy 系统映射

```
┌──────────────────────────────────────────────────────────────────────────────┐
│                                                                              │
│    ATI 系统（阿里云 + CNNIC）          ←对应→      GoDaddy ANS 系统           │
│                                                                              │
│  ┌────────────────────────────┐              ┌────────────────────────────┐  │
│  │ ATI API / RA (阿里云)      │    ═══════   │ RA (Registration Authority)│  │
│  │ ACME验证 / 证书编排 / 生命周期│              │ GoDaddy ANS RA             │  │
│  └────────────────────────────┘              └────────────────────────────┘  │
│                                                                              │
│  ┌────────────────────────────┐              ┌────────────────────────────┐  │
│  │ 云解析 DNS (阿里云)         │    ═══════   │ DNS Provider               │  │
│  │ _ati / _ati-badge / TLSA   │              │ GoDaddy DNS / 任意 DNS     │  │
│  └────────────────────────────┘              └────────────────────────────┘  │
│                                                                              │
│  ┌────────────────────────────┐              ┌────────────────────────────┐  │
│  │ Private CA (CNNIC)         │    ═══════   │ Private CA (GoDaddy 运营)   │  │
│  │ Identity Cert 签发          │              │ Identity Cert 签发          │  │
│  └────────────────────────────┘              └────────────────────────────┘  │
│                                                                              │
│  ┌────────────────────────────┐              ┌────────────────────────────┐  │
│  │ 透明日志 TL (CNNIC)        │    ═══════   │ Transparency Log (GoDaddy) │  │
│  │ Merkle封印/Badge查询/Proof  │              │ SCITT TL / Badge API       │  │
│  └────────────────────────────┘              └────────────────────────────┘  │
│                                                                              │
│  ┌────────────────────────────┐              ┌────────────────────────────┐  │
│  │ Trust Card 托管 (CNNIC)    │    ═══════   │ TL Badge Endpoint          │  │
│  │ 公开查询 / Trust Index      │              │ + Trust Index Provider     │  │
│  └────────────────────────────┘              └────────────────────────────┘  │
│                                                                              │
│  ┌────────────────────────────┐              ┌────────────────────────────┐  │
│  │ 阿里云证书服务 (Public CA)  │    ═══════   │ Public CA (Let's Encrypt等)│  │
│  │ Server Cert / ACME 自动化   │              │ Server Cert 签发           │  │
│  └────────────────────────────┘              └────────────────────────────┘  │
│                                                                              │
└──────────────────────────────────────────────────────────────────────────────┘
```

---

## 二、SDK 需要与哪些角色通信？逐一翻译

### 角色 1：RA（Registration Authority / 注册机构）

| 维度 | ATI | GoDaddy ANS |
|------|-----|-------------|
| 负责方 | 阿里云 | GoDaddy |
| 系统名 | ATI API (RESTful) | ANS RA API |
| SDK 交互方式 | HTTPS REST API | HTTPS REST API |
| SDK 做什么 | 注册 Agent、提交 CSR、查询状态、吊销、解析名字、事件订阅 | 同左 |
| SDK 代码 | `ans/client.go` | 同左 |

**SDK 发起的请求举例：**

- `POST /register` — 提交注册请求
- `GET /agents/{agentId}/status` — 查询注册状态
- `POST /agents/{agentId}/revoke` — 吊销 Agent
- `GET /v1/events` — 事件流订阅

**ATI PRD 中的具体接口：**

- SDK 调用 ATI API 做"一键注册"：`client.register()` → 自动完成 密钥生成 → ACME → DNS → CA → TL
- MVP 阶段 SDK 需要配置 AccessKey（阿里云账号体系）

---

### 角色 2：DNS Server（域名解析服务）

| 维度 | ATI | GoDaddy ANS |
|------|-----|-------------|
| 负责方 | 阿里云云解析 DNS | GoDaddy DNS / 任意 DNS |
| 系统名 | 云解析 DNS | DNS Provider |
| SDK 交互方式 | DNS 协议 (UDP/TCP) | DNS 协议 (UDP/TCP) |
| SDK 做什么 | 查询 `_ati-badge` TXT 获取 Badge URL；查询 TLSA 做 DANE | 查询 `_ans-badge` TXT；查询 TLSA |
| SDK 代码 | `verify/dns.go`, `verify/dns_resolver.go` | 同左 |

**DNS 记录名称差异：**

| GoDaddy ANS | ATI | 作用 |
|-------------|-----|------|
| `_ans-badge.{host}` | `_ati-badge.{host}` | Badge URL 指向透明日志 |
| `_ans.{host}` | `_ati.{host}` | 协议发现（agent card URL） |
| `_443._tcp.{host}` | `_443._tcp.{host}` | TLSA / DANE（相同） |

**SDK 需要适配的点：** DNS 记录前缀从 `_ans` 改为 `_ati`，badge 格式从 `v=ans-badge1` 改为 ATI 对应格式。

---

### 角色 3：Transparency Log（透明日志）

| 维度 | ATI | GoDaddy ANS |
|------|-----|-------------|
| 负责方 | CNNIC | GoDaddy |
| 系统名 | 透明日志 | Transparency Log |
| SDK 交互方式 | HTTPS REST API | HTTPS REST API |
| SDK 做什么 | `GET /v1/agents/{id}` 获取 Badge（含状态+指纹+Inclusion Proof）；`GET /root-keys` 获取签名公钥 | 同左 |
| SDK 代码 | `verify/tlog.go`, `verify/scitt/` | 同左 |

**ATI PRD 明确指出 CNNIC 提供：**

- Merkle Tree 封印
- KMS 签名
- Inclusion Proof
- 公开查询 API

**SDK 需要 CNNIC TL 提供的前置条件：**

- Badge 查询 API 可用（`GET /v1/agents/{agentId}`）
- 签名验证公钥可获取（`GET /root-keys`）
- Inclusion Proof 可验证

---

### 角色 4：Trust Card 托管服务

| 维度 | ATI | GoDaddy ANS |
|------|-----|-------------|
| 负责方 | CNNIC | Agent 自己托管 / TL 提供 |
| 系统名 | Trust Card 托管 | `/.well-known/ans/trust-card.json` 或 TL Badge |
| SDK 交互方式 | HTTPS GET | HTTPS GET |
| SDK 做什么 | 获取 Trust Card 内容用于 Agent 发现和信任评估 | 同左 |

**ATI 的差异点：** GoDaddy 方案中 Trust Card 是 AHP 自己在 Agent 域名下托管；ATI 方案中由 CNNIC 集中托管并提供公开查询，这简化了 AHP 的部署。

---

### 角色 5：Target Agent（目标 Agent 本身）

| 维度 | ATI | GoDaddy ANS |
|------|-----|-------------|
| 负责方 | 对方 AHP（百炼/钉钉/PAI/自建） | 对方 AHP |
| 系统名 | Agent 功能端点 | Agent Functional Endpoint |
| SDK 交互方式 | HTTPS / mTLS | HTTPS / mTLS |
| SDK 做什么 | 发起业务请求，同时从 TLS 握手中提取 Server Certificate 做验证 | 同左 |
| SDK 代码 | `ans/agent_client.go` | 同左 |

---

### 角色 6：Public CA（公有 CA）

| 维度 | ATI | GoDaddy ANS |
|------|-----|-------------|
| 负责方 | 阿里云证书服务 | Public CA (Let's Encrypt / GoDaddy CA 等) |
| SDK 交互方式 | 间接 — 通过 RA 完成 | 间接 — 通过 RA 完成 |
| SDK 做什么 | SDK 不直接与 Public CA 通信，RA 代为获取 Server Certificate | 同左 |

> **注意：** SDK 不需要直接与 Public CA 通信，这一步是 RA 内部编排完成的。

---

## 三、完整交互矩阵

```
┌─────────────────────────────────────────────────────────────────────┐
│                           SDK 交互全景                               │
│                                                                     │
│                    ┌─────────────┐                                  │
│                    │   ATI SDK   │                                  │
│                    └──────┬──────┘                                  │
│           ┌───────────────┼───────────────────────────┐            │
│           │               │                           │            │
│     注册场景          验证场景(A2A)               发现场景          │
│           │               │                           │            │
│           ↓               ↓                           ↓            │
│   ┌──────────────┐ ┌────────────┐ ┌────────────┐ ┌───────────┐   │
│   │ ATI API / RA │ │ DNS Server │ │     TL     │ │Trust Card │   │
│   │  (阿里云)    │ │  (阿里云   │ │  (CNNIC)   │ │  (CNNIC)  │   │
│   │              │ │  云解析)   │ │            │ │           │   │
│   │ ═ GoDaddy RA │ │ ═ GoDaddy  │ │ ═ GoDaddy  │ │ ═ TL Badge│   │
│   │              │ │   DNS      │ │   TL       │ │  Endpoint │   │
│   └──────────────┘ └────────────┘ └────────────┘ └───────────┘   │
│           │               │              │             │           │
│           │               ↓              │             │           │
│           │        ┌────────────┐        │             │           │
│           │        │Target Agent│←───────┘             │           │
│           │        │ (对方AHP)  │                      │           │
│           │        │ ═ Agent    │                      │           │
│           │        │  Endpoint  │                      │           │
│           │        └────────────┘                      │           │
│           │                                            │           │
│           └──→ Private CA (CNNIC) ═ GoDaddy Private CA │           │
│               （SDK 不直接通信，RA 代为）                │           │
│                                                        │           │
│               Public CA (阿里云证书服务) ═ GoDaddy/LE   │           │
│               （SDK 不直接通信，RA 代为）                │           │
└─────────────────────────────────────────────────────────────────────┘
```

---

## 四、SDK 与各角色的通信协议和前置条件总结

| SDK 交互的角色 | ATI 系统 | GoDaddy 对应 | 通信协议 | SDK 需要的前置/上下文 |
|--------------|---------|-------------|---------|---------------------|
| RA | ATI API (阿里云) | GoDaddy ANS RA | HTTPS REST | AccessKey/Token、RA endpoint URL |
| DNS | 云解析 DNS (阿里云) | GoDaddy DNS | DNS UDP/TCP | 目标 Agent 域名；DNS 记录已配置完成（`_ati-badge`） |
| TL | 透明日志 (CNNIC) | GoDaddy TL | HTTPS REST | TL endpoint URL（从 DNS badge 记录中获取）；TL 公钥（`/root-keys`） |
| Trust Card | Trust Card 托管 (CNNIC) | Trust Card at agent FQDN | HTTPS GET | Trust Card URL（从 DNS `_ati` 记录或 TL 响应中获取） |
| Target Agent | 对方 Agent (百炼/钉钉/PAI/自建) | 对方 Agent | HTTPS/mTLS | HTTPS 服务正常；Server Cert 已安装；Agent 状态 ACTIVE |
| Private CA | CNNIC | GoDaddy Private CA | ❌ 不直接通信 | 由 RA 代为编排 |
| Public CA | 阿里云证书服务 | GoDaddy CA / LE | ❌ 不直接通信 | 由 RA 代为编排 |

---

## 五、关键差异点（ATI vs GoDaddy ANS）

| 维度 | GoDaddy ANS | ATI (阿里云+CNNIC) |
|------|-------------|-------------------|
| DNS 前缀 | `_ans-badge`、`_ans` | `_ati-badge`、`_ati` |
| Badge 格式版本 | `v=ans-badge1` | 待确认（可能 `v=ati-badge1`） |
| Trust Card 托管 | AHP 自行托管 (`/.well-known/ans/trust-card.json`) | CNNIC 集中托管 |
| 认证体系 | RA 自有的 API Key | 阿里云 AccessKey / RAM |
| CA 分工 | GoDaddy 统一运营 | Private CA = CNNIC、Public CA = 阿里云证书服务 |
| TL 运营 | GoDaddy 运营 | CNNIC 运营 |
| 部署模式 | 公网 SaaS | 阿里云内部 + CNNIC 对接 |
| 认证级别名称 | Bronze / Silver / Gold | Bronze / Silver / Gold（相同） |
| SDK 自动注册 | 支持 | 支持（`client.register()` 一键注册） |

---

## 六、SDK 在 ATI 场景中的工作时序

### 场景 A：SDK 一键注册（对接 ATI API = GoDaddy RA）

```
SDK                    ATI API/RA (阿里云)         Private CA (CNNIC)       TL (CNNIC)
 │                          │                          │                      │
 │── client.register() ───→ │                          │                      │
 │   (agentHost+version+    │                          │                      │
 │    endpoints+CSR)        │                          │                      │
 │                          │── ACME DNS-01 挑战 ─────→ (验证域名)             │
 │                          │← 域名验证通过 ──────────                         │
 │                          │── 请求 Identity Cert ──→ │                      │
 │                          │← Identity Certificate ──│                      │
 │                          │── 提交注册事件 ──────────────────────────────────→│
 │                          │← Inclusion Proof ────────────────────────────── │
 │                          │── 生成 DNS 记录内容                              │
 │                          │── 写入 _ati-badge + _ati ─→ (云解析 DNS)         │
 │← 证书 + DNS 内容返回 ────│                                                  │
 │                          │                                                  │
 │ (SDK 自动安装证书)                                                           │
```

### 场景 B：SDK A2A 验证通信（Verifier 角色）

```
SDK (AgentClient)        DNS (阿里云云解析)       TL/Trust Card (CNNIC)     Target Agent
 │                             │                        │                      │
 │── DNS TXT query ──────────→ │                        │                      │
 │   _ati-badge.target.com     │                        │                      │
 │← "url=https://cnnic/..." ──│                        │                      │
 │                             │                        │                      │
 │── GET Badge ─────────────────────────────────────→   │                      │
 │← Badge{status,fingerprint} ─────────────────────     │                      │
 │                                                                             │
 │── HTTPS request ────────────────────────────────────────────────────────→   │
 │← Response + TLS Certificate ────────────────────────────────────────────    │
 │                                                                             │
 │ [验证: cert.SHA256 == badge.fingerprint? ✓]                                │
 │ [验证: badge.status == ACTIVE? ✓]                                          │
 │ [验证: badge.host == target.com? ✓]                                        │
 │                                                                             │
 │── 返回 Response + VerifiedOutcome                                           │
```

---

## 总结

- **SDK 直接通信的角色有 4 个：** RA (ATI API)、DNS、TL、Target Agent
- **SDK 不直接通信但依赖的有 2 个：** Private CA、Public CA（都由 RA 代为编排）
- **ATI 相比 GoDaddy 最大的架构差异：** 把 Trust Card 托管和 TL 从 RA 运营方独立出来给了 CNNIC，形成"阿里云管注册编排 + CNNIC 管信任存证"的分工模式
