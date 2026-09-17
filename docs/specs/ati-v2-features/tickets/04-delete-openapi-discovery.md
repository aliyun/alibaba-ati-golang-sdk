# 04 — Delete OpenAPI discovery

**What to build:** Remove the legacy OpenAPI-based agent discovery (`AliyunATIDiscovery`) entirely. DNS TXT `_ati` records via `StandardDNSResolver` are the sole discovery mechanism going forward.

**Blocked by:** None — can start immediately.

**Status:** ready-for-agent

- [ ] Delete `verify/aliyun_discovery.go` and its test file
- [ ] Remove `WithServerAliyunDiscovery` ServerOption from `ati/server.go`
- [ ] Remove `AliyunATIConfig` and all related types/structs
- [ ] Remove associated imports (`darabonba-openapi`, `openapi-util`, `tea`, `tea-utils`) from `go.mod` if no longer used elsewhere
- [ ] Run `go mod tidy` — build succeeds
- [ ] All remaining tests pass (DNS TXT path unaffected)
