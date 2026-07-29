# 02 — NONE policy end-to-end (client + server)

**What to build:** A client configured with PolicyNone connects to any server without TLS certificate validation (dev/test only). A server configured with PolicyNone accepts connections without requesting client certificates. Conflicting configs (NONE + WithClientCA) are rejected at construction time.

**Blocked by:** 01 — VerificationPolicy type + deprecation expand

**Status:** ready-for-agent

- [ ] Client: PolicyNone sets `tls.Config.InsecureSkipVerify = true`, skips Badge/DANE verification
- [ ] Client: WARN-level log emitted when NONE is active ("TLS validation disabled — dev/test only")
- [ ] Server: `WithClientVerifier(PolicyNone)` → `tls.NoClientCert`, no VerifyConnection callback
- [ ] Config validation: PolicyNone + WithClientCA (client) returns error
- [ ] Config validation: PolicyNone + WithClientCA (server) returns error
- [ ] Integration test: NONE client connects to self-signed server successfully
- [ ] Integration test: NONE server accepts connection without client cert
- [ ] Existing trust level tests pass without regression
