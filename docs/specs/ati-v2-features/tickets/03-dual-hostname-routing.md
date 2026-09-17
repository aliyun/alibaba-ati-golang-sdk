# 03 — Dual-hostname client routing

**What to build:** Client-side `WithIdentityHost` and `WithAccessHost` options that route Badge/identity-DANE lookups and transport-DANE lookups to separate hostnames, supporting proxy-gateway topologies where the ATI identity and the network endpoint differ.

**Blocked by:** 01 — VerificationPolicy type + deprecation expand

**Status:** ready-for-agent

- [ ] `agentClientConfig` gains `identityHost` and `accessHost` string fields
- [ ] `WithIdentityHost(host string)` AgentClientOption sets identityHost
- [ ] `WithAccessHost(host string)` AgentClientOption sets accessHost
- [ ] Badge verification resolves via identityHost (falls back to connection URL host)
- [ ] Transport DANE (`_443._tcp`) resolves via accessHost (falls back to connection URL host)
- [ ] Unit test: identityHost set → Badge lookup uses identityHost, not connection host
- [ ] Unit test: accessHost set → DANE lookup uses accessHost, not connection host
- [ ] Unit test: neither set → same behavior as before (no regression)
