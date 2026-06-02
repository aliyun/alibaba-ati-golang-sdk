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
│  │ JSON/JCS/ECDSA 封印         │              │ SCITT CBOR/COSE TL         │  │
│  │ Merkle Proof / Badge 查询   │              │ SCITT Receipt / Badge API  │  │
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

## 二、SDK 迁移实现状态

### 已完成的迁移工作

| 功能 | 原 GoDaddy 实现 | ATI 实现 | 状态 |
|------|-----------------|---------|------|
| **模块路径** | `github.com/godaddy/ans-sdk-go` | `gitlab.alibaba-inc.com/alibaba-dns/ati-golang-sdk` | ✅ 完成 |
| **DNS 前缀** | `_ans-badge` / `_ans` | `_ati-badge` / `_ati` | ✅ 完成 |
| **ATI Name** | `ans://v{ver}.{host}` | `ati://v{ver}.{host}` | ✅ 完成 |
| **mTLS 客户端** | `ans.AgentClient`（badge-based） | `ati.AgentClient`（mTLS + 三级信任） | ✅ 完成 |
| **服务端 TLS** | 无 | `ati.NewServerTLSConfig` + `VerifyPeerCertificate` | ✅ 新增 |
| **信任等级** | FailurePolicy (FailClosed/FailOpen) | Bronze / Silver / Gold | ✅ 完成 |
| **Bronze 验证** | Badge URL + 指纹匹配 | DNS `_ati` 发现 + CA 链 + SAN 匹配 | ✅ 完成 |
| **Silver 验证** | DANE（可选附加） | Bronze + DANE/TLSA | ✅ 完成 |
| **Gold 验证** | SCITT (CBOR/COSE) | CNNIC TL (JSON/JCS/ECDSA) | ✅ 完成 |
| **密封验证** | COSE_Sign1 + SCITT Receipt | JCS 规范化 + SHA-256 + ECDSA | ✅ 完成 |
| **Merkle 证明** | SCITT Merkle (0x00/0x01 前缀) | RFC 9162 风格 (无前缀) | ✅ 完成 |
| **Trust Card** | `/.well-known/ans/trust-card.json` | CNNIC TL API 集中查询 | ✅ 完成 |
| **诊断工具** | 无 | `ati.Diagnose()` 7 步诊断 | ✅ 新增 |
| **RA API 客户端** | `ans/client.go` (公共包) | `internal/registry/client.go` (内部包) | ✅ 完成 |
| **CLI 工具** | `cmd/ans-cli` | `cmd/ati-cli` | ✅ 完成 |

---

## 三、SDK 与各角色通信方式

### 角色 1：RA（Registration Authority / 注册机构）

| 维度 | ATI | GoDaddy ANS |
|------|-----|-------------|
| 负责方 | 阿里云 | GoDaddy |
| SDK 交互方式 | HTTPS REST API | HTTPS REST API |
| SDK 代码 | `internal/registry/client.go` | `ans/client.go` |

### 角色 2：DNS Server（域名解析服务）

| 维度 | ATI | GoDaddy ANS |
|------|-----|-------------|
| 负责方 | 阿里云云解析 DNS | GoDaddy DNS |
| SDK 交互方式 | DNS 协议 (UDP/TCP) | DNS 协议 (UDP/TCP) |
| SDK 代码 | `verify/dns.go`, `verify/dns_resolver.go` | 同左 |

**DNS 记录名称对照：**

| GoDaddy ANS | ATI | 作用 |
|-------------|-----|------|
| `_ans-badge.{host}` | `_ati-badge.{host}` | Badge URL 指向透明日志 |
| `_ans.{host}` | `_ati.{host}` | 协议发现（Agent ID、版本、模式） |
| `_443._tcp.{host}` | `_443._tcp.{host}` | TLSA / DANE（相同） |

### 角色 3：Transparency Log（透明日志）

| 维度 | ATI | GoDaddy ANS |
|------|-----|-------------|
| 负责方 | CNNIC | GoDaddy |
| 封印格式 | JSON/JCS/ECDSA | CBOR/COSE/SCITT |
| API 端点 | `tl.ansagent.cn:8180` | `transparency.ans.godaddy.com` |
| SDK 代码 | `verify/seal.go`, `verify/merkle.go`, `verify/gold.go` | `verify/scitt/` |

**关键密码学差异：**

| 维度 | CNNIC TL (ATI) | GoDaddy TL (ANS) |
|------|---------------|------------------|
| 数据格式 | JSON | CBOR |
| 规范化 | RFC 8785 JCS | 无（CBOR 自身有序） |
| 签名信封 | 裸 ECDSA (DER) | COSE_Sign1 |
| 摘要算法 | SHA-256 | SHA-256 |
| 签名算法 | SHA256withECDSA | ES256 (P-256) |
| Merkle 节点 | `SHA-256(left \|\| right)` | `SHA-256(0x01 \|\| left \|\| right)` |
| Merkle 叶子 | 无前缀 | `SHA-256(0x00 \|\| data)` |

### 角色 4：Trust Card 托管服务

| 维度 | ATI | GoDaddy ANS |
|------|-----|-------------|
| 负责方 | CNNIC 集中托管 | Agent 自己托管 |
| 访问方式 | TL API: `GET /tl/agents/{id}/logs/latest` | `GET /.well-known/ans/trust-card.json` |
| SDK 代码 | `ati/trust_card.go` | 无专用代码（HTTP GET） |

### 角色 5：Target Agent（目标 Agent 本身）

| 维度 | ATI | GoDaddy ANS |
|------|-----|-------------|
| SDK 交互方式 | HTTPS / mTLS | HTTPS / mTLS |
| 验证模型 | 三级信任（Bronze/Silver/Gold）| Badge + SCITT |
| SDK 代码 | `ati/mtls_client.go` | `ans/agent_client.go` |

---

## 四、完整交互矩阵

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
│   (internal/          (ati/)                    (ati/)             │
│    registry/)              │                           │            │
│           │               │                           │            │
│           ↓               ↓                           ↓            │
│   ┌──────────────┐ ┌────────────┐ ┌────────────┐ ┌───────────┐   │
│   │ ATI API / RA │ │ DNS Server │ │     TL     │ │Trust Card │   │
│   │  (阿里云)    │ │  (阿里云   │ │  (CNNIC)   │ │  (CNNIC)  │   │
│   └──────────────┘ │  云解析)   │ │            │ │           │   │
│                     └────────────┘ └────────────┘ └───────────┘   │
│                            │              │                        │
│                            ↓              │                        │
│                     ┌────────────┐        │                        │
│                     │Target Agent│←───────┘                        │
│                     │ (对方AHP)  │                                 │
│                     └────────────┘                                 │
│                                                                     │
│           Private CA (CNNIC) — SDK 不直接通信，RA 代为               │
│           Public CA (阿里云证书服务) — SDK 不直接通信，RA 代为       │
└─────────────────────────────────────────────────────────────────────┘
```

---

## 五、SDK 在 ATI 场景中的工作时序

### 场景 A：Agent 间 mTLS 通信（Bronze 级别）

```
SDK (AgentClient)        DNS (阿里云云解析)                    Target Agent
 │                             │                                    │
 │── DNS TXT 查询 ───────────→│                                    │
 │   _ati.target.com           │                                    │
 │←─ ATIRecord { ID, Mode } ──│                                    │
 │                             │                                    │
 │══ mTLS 握手 ════════════════════════════════════════════════════►│
 │   (双方交换 Identity Certificate)                                │
 │                             │                                    │
 │── Bronze 验证:              │                                    │
 │   a) CA 链有效 ✓            │                                    │
 │   b) ati:// URI SAN 存在 ✓  │                                    │
 │   c) SAN host 匹配 ✓       │                                    │
 │                             │                                    │
 │══ HTTP 请求 ════════════════════════════════════════════════════►│
 │◄═ HTTP 响应 ═══════════════════════════════════════════════════│
 │                             │                                    │
 │── 返回 Response + BronzeOutcome { TrustLevel: Bronze }          │
```

### 场景 B：Gold 级别验证通信

```
SDK (AgentClient)     DNS          CNNIC TL                   Target Agent
 │                     │               │                           │
 │── _ati TXT ────────→│               │                           │
 │←─ agentId ──────────│               │                           │
 │                     │               │                           │
 │══ mTLS 握手 + Bronze 验证 ═════════════════════════════════════►│
 │                                     │                           │
 │── GET /tl/agents/{id}/logs/latest ─→│                           │
 │←─ TLLogResponse ───────────────────│                           │
 │                                     │                           │
 │── 密封验证: JCS → SHA-256 → ECDSA ✓ │                           │
 │── Merkle 验证: leafHash + path ✓    │                           │
 │── 指纹匹配: cert == TL record ✓     │                           │
 │── 状态: ACTIVE ✓                    │                           │
 │                                     │                           │
 │── BronzeOutcome { TrustLevel: Gold, SealVerified, MerkleVerified }
```

### 场景 C：诊断流程

```
SDK (Diagnose)         DNS          CNNIC TL
 │                      │               │
 │── [1] Host 校验                      │
 │── [2] _ati TXT ─────→│               │
 │←─ agentId ───────────│               │
 │── [3] _ati-badge ───→│               │
 │←─ badge URL (可选) ──│               │
 │── [4] GET TL Log ───────────────────→│
 │←─ TLLogResponse ────────────────────│
 │── [5] 密封验证 (JCS + ECDSA)         │
 │── [6] Merkle 验证                    │
 │── [7] 证书指纹检查                   │
 │                                      │
 │── DiagnoseResult { Steps[], Summary }│
```

---

## 六、关键差异点（ATI vs GoDaddy ANS）

| 维度 | GoDaddy ANS | ATI (阿里云+CNNIC) |
|------|-------------|-------------------|
| DNS 前缀 | `_ans-badge`、`_ans` | `_ati-badge`、`_ati` |
| ATI Name 协议 | `ans://` | `ati://` |
| Trust Card 托管 | AHP 自行托管 (`/.well-known/`) | CNNIC 集中托管 (TL API) |
| 认证体系 | GoDaddy API Key / JWT | 阿里云 AccessKey / RAM |
| CA 分工 | GoDaddy 统一运营 | Private CA = CNNIC、Public CA = 阿里云 |
| TL 运营 | GoDaddy 运营 | CNNIC 运营 |
| TL 数据格式 | CBOR / COSE / SCITT | JSON / JCS / ECDSA |
| Merkle 实现 | RFC 9162 (0x00/0x01 前缀) | RFC 9162 风格 (无前缀) |
| A2A 验证模型 | Badge URL 指纹匹配 + SCITT | mTLS + Bronze/Silver/Gold 三级 |
| 服务端验证 | 无内置支持 | `VerifyPeerCertificate` 回调 |
| 诊断工具 | 无 | `ati.Diagnose()` |
| SDK 包结构 | `ans/` (公共包) | `ati/` (公共) + `internal/registry/` (内部) |

---

## 七、总结

- **SDK 直接通信的角色有 4 个：** RA (ATI API)、DNS、TL、Target Agent
- **SDK 不直接通信但依赖的有 2 个：** Private CA、Public CA（都由 RA 代为编排）
- **ATI 相比 GoDaddy 最大的架构差异：**
  1. 把 Trust Card 托管和 TL 从 RA 运营方独立出来给了 CNNIC，形成"阿里云管注册编排 + CNNIC 管信任存证"的分工模式
  2. TL 封印从 CBOR/COSE/SCITT 改为 JSON/JCS/ECDSA，简化了密码学栈
  3. A2A 通信从 badge-based HTTP 客户端升级为 mTLS + 三级信任验证，安全性更强
  4. 新增服务端验证回调（`VerifyPeerCertificate`），支持服务端主动验证客户端 ATI 身份
