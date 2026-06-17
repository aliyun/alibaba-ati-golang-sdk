# ATI-Golang-SDK 需求规格

## 1. 概述

为 `alibaba-dns/ati-golang-sdk` 实现四项核心功能，完善 SDK 的公共 API 层（`ati/` 包）和内部基础设施（`internal/registry/`），使其具备开箱即用的默认验证策略、统一的 Agent 发现接口、阿里云 OpenAPI 集成能力以及合理的客户端/服务端验证默认值。

**仓库**：`alibaba-dns/ati-golang-sdk`
**分支**：`feature/support_ati`
**基线**：已有 `verify/` 包（badge 解析、DNS 解析、TL 客户端、DANE/SCITT 验证）、`models/` 包、`internal/httputility/` 包、`keygen/` 包。`ati/` 公共 API 层和 `internal/registry/` RA 客户端尚未实现。

---

## 2. 功能需求

### FR-1：默认验证策略 policy=badge_required

**描述**：当用户未显式指定验证策略时，SDK 默认采用 `badge_required` 策略——要求 badge 验证必须通过。

**详细规则**：

1. 定义 `VerificationPolicy` 枚举类型：
   - `PolicyNone`：不做任何验证（仅 TLS 握手）
   - `PolicyPKIOnly`：仅 PKI 验证（CA 链 + SAN 匹配，需提供 ca_bundle）
   - `PolicyBadgeRequired`（默认值）：badge 透明日志指纹验证必须通过。若提供 ca_bundle 则额外执行 PKI 链验证；若无 ca_bundle 则跳过 PKI 链验证，仅依赖 badge 验证
   - `PolicyFull`：badge + DANE/TLSA 验证。若提供 ca_bundle 则额外执行 PKI 链验证；若无 ca_bundle 则跳过 PKI 链验证

2. `PolicyBadgeRequired` 行为：
   - 执行 DNS 查询 `_ati-badge.{host}` TXT 记录
   - 解析 badge 记录，提取 URL 中的 **path** 和 **port**
   - 将提取的 path 和 port 拼接到配置的 TL base_url 上，构造最终的 TL 查询地址
   - 向该地址获取 badge 数据并完成验证
   - badge 获取或验证失败时，根据 `FailurePolicy`（FailClosed/FailOpen）处理

3. Badge URL 构造逻辑：
   - 输入：badge TXT 记录中的 `url` 字段（如 `https://tl.ansagent.cn:8180/ans/api/v1/agents/{id}/badge`）
   - 提取：path 部分（`/ans/api/v1/agents/{id}/badge`）和 port（`8180`）
   - TL base_url：可配置，默认为 `https://tl.ansagent.cn`
   - 输出：`{tl_base_url}:{port}{path}` → `https://tl.ansagent.cn:8180/ans/api/v1/agents/{id}/badge`
   - 安全约束：仅允许 HTTPS、可信域名列表、端口白名单（443/8180）、禁止路径穿越

4. 配置接口：
   - `WithVerificationPolicy(policy VerificationPolicy)` — 覆盖默认策略
   - `WithTLBaseURL(url string)` — 覆盖默认 TL base_url

**验收标准**：
- 不指定策略时，客户端验证服务端自动走 badge_required 流程
- badge TXT 记录中的 path+port 被正确提取并拼接到 TL base_url
- badge 验证失败在 FailClosed 模式下拒绝连接

---

### FR-2：Agent 发现统一接口

**描述**：提供一个统一的 `AgentDiscoverer` 接口，抽象底层发现机制（DNS / RA API），调用方无需关心发现方式。

**详细规则**：

1. 定义统一接口：
   ```go
   type AgentDiscoverer interface {
       Discover(ctx context.Context, fqdn string) (*AgentInfo, error)
       DiscoverWithOptions(ctx context.Context, fqdn string, opts ...DiscoverOption) (*AgentInfo, error)
   }
   ```

2. `AgentInfo` 返回结构：
   ```go
   type AgentInfo struct {
       FQDN          string
       AgentID       string
       BadgeURL      string       // 从 _ati-badge TXT 获取
       RAEndpoint    string       // 从 _ati TXT 的 ra 字段获取
       Version       string       // 从 _ati TXT 的 version 字段获取
       Protocol      string       // 从 _ati TXT 的 p 字段获取（mcp/a2a/openapi）
       Mode          string       // 从 _ati TXT 的 mode 字段获取
       Source        DiscoverySource // DNS / RAAPI
   }
   ```

3. 发现选项：
   - `WithVersion(version string)` — 指定版本过滤
   - `WithProtocol(protocol string)` — 指定协议过滤
   - `WithSource(source DiscoverySource)` — 强制指定发现源

4. 实现两个发现源：
   - `DNSDiscoverer`：基于现有 `DNSResolver`，查询 `_ati` 和 `_ati-badge` TXT 记录
   - `RAAPIDiscoverer`：通过 RA API 查询 Agent 信息（依赖 FR-3 的 OpenAPI 集成）

5. 默认行为：优先 DNS 发现；DNS 发现失败时降级到 RA API（如已配置）

**验收标准**：
- 通过 `AgentDiscoverer.Discover()` 可获取完整的 Agent 信息
- DNS 发现和 RA API 发现返回一致的 `AgentInfo` 结构
- 单一接口屏蔽底层发现机制差异

---

### FR-3：集成阿里云 OpenAPI SDK（子账号 AK/SK）

**描述**：使用阿里云 OpenAPI SDK（`darabonba-openapi`）实现 RA API 客户端，认证方式为 RAM 子账号 AccessKey ID / AccessKey Secret。

**详细规则**：

1. 新建 `internal/registry/` 包，实现 RA API 客户端：
   ```go
   type RAClient struct { ... }

   func NewRAClient(opts ...RAClientOption) (*RAClient, error)
   ```

2. 认证方式：
   - 使用 `github.com/alibabacloud-go/darabonba-openapi/v2` SDK
   - 凭证类型：`access_key`（RAM 子账号 AK/SK）
   - 通过 `github.com/aliyun/credentials-go` 管理凭证
   - 配置项：`WithAccessKeyID(id)`, `WithAccessKeySecret(secret)`, `WithEndpoint(endpoint)`

3. RA API 能力（基于已有 examples 推断）：
   - Agent 注册：`RegisterAgent(ctx, req *AgentRegistrationRequest) (*AgentRegistrationResponse, error)`
   - Agent 查询：`GetAgent(ctx, agentID string) (*AgentInfo, error)`
   - Badge/TL 查询：`GetAgentBadge(ctx, agentID string) (*BadgeResponse, error)`
   - Agent 列表：`ListAgents(ctx, opts ...ListOption) ([]*AgentInfo, error)`
   - 审计日志：`GetAuditTrail(ctx, agentID string, opts ...AuditOption) (*AuditTrailResponse, error)`

4. 默认 RA endpoint：`https://ra.ansagent.cn:8180/ans/api/v1`

5. 错误处理：
   - AK/SK 无效 → 返回认证错误，不降级
   - API 调用失败 → 包装为 SDK 标准错误类型，保留原始错误链

**验收标准**：
- 可通过 RAM 子账号 AK/SK 成功调用 RA API
- 依赖项 `darabonba-openapi` 和 `credentials-go` 被正确使用（当前为 indirect，需改为 direct）
- 错误信息清晰，包含 API 调用上下文

---

### FR-4：客户端/服务端默认验证行为

**描述**：设定合理的默认验证行为——客户端验证服务端默认采用 badge 验证，服务端验证客户端默认不验证。PKI 链验证作为正交行为，由 ca_bundle 是否存在决定。

**详细规则**：

1. **客户端验证服务端**（`AgentClient`）：
   - 默认策略：`PolicyBadgeRequired`（badge 验证）
   - 验证流程：TLS 握手 → DNS badge 查询 → badge 透明日志指纹验证；若配置了 ca_bundle 则额外执行 CA 链验证 + SAN 匹配
   - 可通过 `WithVerificationPolicy(PolicyNone)` 降级为仅 TLS
   - 可通过 `WithVerificationPolicy(PolicyFull)` 升级为 badge + DANE

2. **服务端验证客户端**（`ServerTLSConfig`）：
   - 默认策略：`PolicyNone`（不验证客户端证书）
   - TLS 配置：`tls.NoClientCert`（默认不要求客户端证书）
   - 可通过 `WithClientVerificationPolicy(PolicyBadgeRequired)` 开启客户端 badge 验证
   - 可通过 `WithClientVerificationPolicy(PolicyFull)` 开启客户端 badge + DANE 验证
   - **ca_bundle 降级机制**：开启验证后（PolicyPKIOnly / PolicyBadgeRequired / PolicyFull），根据 `ca_bundle`（clientCAPool）是否存在，决定 TLS ClientAuth 模式：
     - **有 ca_bundle**：`tls.RequireAndVerifyClientCert`（PKI 链验证 + 策略指定的验证）
     - **无 ca_bundle**（仅 PolicyBadgeRequired / PolicyFull）：`tls.RequireAnyClientCert`（跳过 PKI 链验证，仅要求客户端提供证书，依赖 badge 透明日志指纹验证）
     - **无 ca_bundle + PolicyPKIOnly**：返回错误（PKI 验证必须有 ca_bundle）

3. 配置示例：
   ```go
   // 客户端：默认 badge 验证（无需额外配置）
   client := ati.NewAgentClient(
       ati.WithMTLSCerts(identityCert, privateKey, serverCert, caBundle),
   )

   // 服务端：默认不验证客户端（无需额外配置）
   tlsConfig := ati.NewServerTLSConfig(
       ati.WithServerCert(serverCert, serverKey),
   )

   // 服务端：开启客户端 badge 验证（有 ca_bundle → PKI + badge）
   tlsConfig := ati.NewServerTLSConfig(
       ati.WithServerCert(serverCert, serverKey),
       ati.WithClientCA(caBundle),
       ati.WithClientVerificationPolicy(ati.PolicyBadgeRequired),
   )

   // 服务端：开启客户端 badge 验证（无 ca_bundle → 仅 badge，跳过 PKI）
   tlsConfig := ati.NewServerTLSConfig(
       ati.WithServerCert(serverCert, serverKey),
       ati.WithClientVerificationPolicy(ati.PolicyBadgeRequired),
   )
   ```

**验收标准**：
- `NewAgentClient()` 不指定策略时，自动执行 badge 验证
- `NewServerTLSConfig()` 不指定策略时，不要求客户端证书
- 服务端开启 PolicyBadgeRequired/PolicyFull 但无 ca_bundle 时，使用 `RequireAnyClientCert` 而非 `RequireAndVerifyClientCert`
- 服务端开启 PolicyPKIOnly 但无 ca_bundle 时，返回错误
- 两端都支持通过 Option 升级或降级验证级别

---

## 3. 非功能需求

| 项目 | 要求 |
|------|------|
| Go 版本 | >= 1.25.0 |
| TLS 最低版本 | TLS 1.3 |
| 测试覆盖率 | >= 90%（CI 已有要求） |
| 命名规范 | ATI 前缀（非 ANS），`ati://` URI scheme |
| 兼容性 | 保留 `_ra-badge` TXT 记录 fallback |
| 安全 | AK/SK 禁止硬编码，支持环境变量 / 配置文件读取 |
| 日志 | 使用 `slog` 结构化日志 |

---

## 4. 术语对照

| 术语 | 含义 |
|------|------|
| ATI | Agent Trust Infrastructure，阿里巴巴+CNNIC 的 Agent 信任基础设施 |
| badge | DNS TXT 记录（`_ati-badge.{host}`）中指向 TL 的 URL |
| TL | Transparency Log，透明日志，CNNIC 运营 |
| RA | Registration Authority，注册机构，阿里巴巴运营 |
| PKI | Public Key Infrastructure，公钥基础设施 |
| DANE | DNS-based Authentication of Named Entities |
| AK/SK | AccessKey ID / AccessKey Secret，阿里云 RAM 子账号凭证 |
| FQDN | Fully Qualified Domain Name |

---

## 5. 影响范围

| 包/目录 | 变更类型 | 说明 |
|---------|---------|------|
| `ati/` | **新建** | 公共 API 层：AgentClient、ServerTLSConfig、VerificationPolicy、AgentDiscoverer |
| `internal/registry/` | **新建** | RA API 客户端，阿里云 OpenAPI SDK 集成 |
| `verify/options.go` | 修改 | 新增 WithVerificationPolicy、WithTLBaseURL 等 Option |
| `verify/verify.go` | 修改 | badge URL 构造逻辑调整（path+port 提取拼接 TL base_url） |
| `verify/url_validator.go` | 修改 | 支持 TL base_url 拼接模式 |
| `models/` | 修改 | 新增 AgentInfo、DiscoverySource 等类型 |
| `go.mod` | 修改 | 将阿里云 SDK 依赖从 indirect 改为 direct |
