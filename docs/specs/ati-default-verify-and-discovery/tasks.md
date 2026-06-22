# ATI-Golang-SDK 任务清单

> 对应编码方案：[coding_design.md](coding_design.md)
> 对应需求规格：[specs/ati-golang-sdk-spec.md](specs/ati-golang-sdk-spec.md)

---

## Phase 1：基础类型与策略定义

### Task 1.1：创建 `ati/policy.go`
- 定义 `VerificationPolicy` 枚举（PolicyNone / PolicyPKIOnly / PolicyBadgeRequired / PolicyFull）
- PolicyBadgeRequired：badge 验证 + PKI（需 ca_bundle）
- PolicyFull：badge + DANE + PKI（需 ca_bundle）
- 定义 `String()` 方法
- 编写单元测试 `ati/policy_test.go`

### Task 1.2：创建 `ati/types.go`
- 定义 `AgentEndpoint` 结构体（Host, Port, Protocol）
- 定义 `AgentInfo` 结构体（FQDN, AgentID, BadgeURL, RAEndpoint, Endpoints, TrustLevel, Categories, Version, Protocol, Mode, Source）
- 定义 `DiscoverySource` 枚举（SourceDNS / SourceRAAPI）
- 定义 `DiscoverOption` 及相关选项函数（WithVersion, WithProtocol, WithSource）
- 定义 `ResolveDiscoverOptions()` 辅助函数

### Task 1.3：补全 `models/` 缺失类型
- 确认并实现 `ATIRecord` 结构体（`_ati` TXT 记录解析结果）
- 确认并实现 `ParseATIRecord()` 函数
- 确认 `TLResponse`, `TLPayload`, `TLCertificates`, `TLAgentStatus` 是否需要在此阶段定义
- 编写相应单元测试

---

## Phase 2：Badge URL 构造与验证策略改造

### Task 2.1：`verify/url_validator.go` — 新增 `BuildBadgeURL()`
- 实现 `BuildBadgeURL(badgeRawURL, tlBaseURL string) (string, error)`
- 从 badge URL 提取 path 和 port
- 与 TL base_url 拼接构造最终地址
- 保留现有安全校验（HTTPS、可信域名、端口白名单、路径穿越检测）
- 编写单元测试覆盖：正常 URL、无端口、非标端口、路径穿越、非 HTTPS 等场景

### Task 2.2：`verify/options.go` — 新增配置字段和 Option
- `verifierConfig` 新增 `tlBaseURL string` 字段，默认 `"https://tl.ansagent.cn"`
- `verifierConfig` 新增 `verificationPolicy` 字段，默认 `PolicyBadgeRequired`
- 新增 `WithTLBaseURL(url string) Option`
- 新增 `WithVerificationPolicy(p VerificationPolicy) Option`
- 更新 `defaultConfig()` 设置默认值

### Task 2.3：`verify/verify.go` — 替换 badge URL 构造逻辑
- `ServerVerifier.Verify()` 中将 `RewriteBadgeURLHost()` 调用改为 `BuildBadgeURL()`
- `ClientVerifier.Verify()` 中同上改造
- 根据 `verificationPolicy` 决定是否执行 badge 验证步骤
- 更新现有单元测试，验证新逻辑

---

## Phase 3：统一 Agent 发现接口

### Task 3.1：创建 `ati/discovery.go` — 接口与组合发现器
- 定义 `AgentDiscoverer` 接口（Discover / DiscoverWithOptions）
- 实现 `CompositeDiscoverer`（primary + fallback 模式）
- 编写单元测试

### Task 3.2：创建 `verify/dns_discoverer.go` — DNS 发现器适配
- 实现 `DNSDiscoverer` 结构体，包装现有 `DNSResolver`
- `Discover()` 方法：并行查询 `_ati` TXT + `_ati-badge` TXT，组装 `AgentInfo`
- `DiscoverWithOptions()` 支持版本/协议过滤
- 编写单元测试（使用现有 `MockDNSResolver`）

### Task 3.3：创建 `internal/registry/discoverer.go` — RA API 发现器
- 实现 `RAAPIDiscoverer` 结构体
- `Discover()` 方法：调用 `RAClient.DescribeAgentRegisterInfoMarket()` 按主机名查询
- `DiscoverWithOptions()` 方法：传递 version 参数给 `DescribeAgentRegisterInfoMarket`
- `marketResultToATI()` 转换函数：映射 `DescribeAgentMarketPopResult` → `AgentInfo`
- 编写单元测试

---

## Phase 4：阿里云 OpenAPI SDK 集成

### Task 4.1：创建 `internal/registry/ra_options.go`
- 定义 `raConfig` 结构体（accessKeyID, accessKeySecret, endpoint）
- 定义 `RAClientOption` 类型及选项函数
- 默认 endpoint：`alidns.aliyuncs.com`

### Task 4.2：创建 `internal/registry/ra_models.go`
- 定义 `DescribeAgentMarketPopResult` 响应模型（RequestId, AgentHost, AgentId, Version, TrustLevel, Categories, Endpoints, BadgeUrl, Mode, Status）
- 定义 `MarketAgentEndpoint` 结构体（Host, Port, Protocol, Weight）

### Task 4.3：创建 `internal/registry/ra_client.go`
- 实现 `NewRAClient()` 构造函数
- 使用 `credentials-go` 创建 access_key 凭证
- 使用 `darabonba-openapi` 初始化 OpenAPI 客户端
- 实现 `DescribeAgentRegisterInfoMarket()` 方法：POP RPC 泛化调用（Action=DescribeAgentRegisterInfoMarket, Version=2015-01-09, Style=RPC）
- `callApiWithContext()` 传播 context deadline
- 错误包装：保留原始错误链，添加调用上下文

### Task 4.4：更新 `go.mod`
- 将 `alibabacloud-go/darabonba-openapi/v2` 和 `aliyun/credentials-go` 从 indirect 改为 direct
- 运行 `go mod tidy` 确认依赖关系

### Task 4.5：编写 `internal/registry/` 单元测试
- 凭证创建测试（AK/SK 缺失时报错）
- API 调用测试（httptest.Server mock）
- 错误处理测试

---

## Phase 5：公共 API 层 — AgentClient & ServerTLSConfig

### Task 5.1：创建 `ati/options.go`
- 定义 `ClientOption` 和 `ServerOption`
- 客户端选项：WithMTLSCerts, WithVerificationPolicy, WithTLBaseURL, WithDiscoverer, WithRAClient
- 服务端选项：WithServerCert, WithClientCA, WithClientVerificationPolicy

### Task 5.2：创建 `ati/client.go`
- 实现 `NewAgentClient()` 构造函数
- 默认 policy = PolicyBadgeRequired
- 配置 TLS 1.3 + VerifyConnection 回调
- 实现 HTTP 方法：Get, Post, Put, Delete, Do
- 回调中根据 policy 调用 verifyPKI / verifyPKIAndBadge / verifyFull

### Task 5.3：创建 `ati/server.go`
- 实现 `NewServerTLSConfig()` 构造函数
- 默认 clientPolicy = PolicyNone → tls.NoClientCert
- 新增 `WithIgnoreCheckClient()` ServerOption：开启后 ClientAuth=NoClientCert，不要求 ca_bundle
- PolicyPKIOnly：必须有 ca_bundle，否则返回错误 → tls.RequireAndVerifyClientCert
- PolicyBadgeRequired/PolicyFull：必须有 ca_bundle，否则返回错误 → tls.RequireAndVerifyClientCert

### Task 5.4：编写 `ati/` 包单元测试
- `client_test.go`：默认策略验证、策略覆盖、TLS 配置检查
- `server_test.go`：默认不验证客户端、PolicyBadgeRequired/PolicyFull + 有 ca_bundle → RequireAndVerifyClientCert、PolicyBadgeRequired/PolicyFull + 无 ca_bundle → 返回错误、PolicyPKIOnly + 无 ca_bundle → 返回错误、WithIgnoreCheckClient() → NoClientCert（无论 policy/ca_bundle）
- `discovery_test.go`：组合发现器 primary/fallback 行为

---

## Phase 6：集成测试与文档

### Task 6.1：集成测试
- 端到端客户端-服务端连接测试（本地 TLS）
- 默认策略场景：客户端 badge_required + 服务端 none
- 策略升级/降级场景

### Task 6.2：更新 examples/
- 新增 `examples/client_server/` 示例：展示默认策略的客户端-服务端连接
- 新增 `examples/discovery/` 示例：展示统一发现接口用法
- 新增 `examples/openapi_registration/` 示例：展示 AK/SK 方式注册 Agent

### Task 6.3：更新 README.md
- 更新客户端/服务端默认行为描述
- 新增 Agent 发现章节
- 新增阿里云 OpenAPI 集成章节
