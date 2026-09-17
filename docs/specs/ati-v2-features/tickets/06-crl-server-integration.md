# 06 — CRL server integration

**What to build:** Wire the CRL checker into the server mTLS flow. When a CA bundle is configured and trust level ≠ NONE, CRL checking runs automatically in `buildVerifyConnection` (after cert validity, before Badge). Provides explicit opt-in/opt-out server options and a custom HTTP client hook for testing.

**Blocked by:** 01 — VerificationPolicy type, 05 — CRL core library

**Status:** ready-for-agent

- [ ] `WithCRLCheck()` ServerOption: explicitly enables CRL
- [ ] `WithCRLCheckDisabled()` ServerOption: explicitly disables CRL
- [ ] `WithCRLHTTPClient(*http.Client)` ServerOption: injects HTTP client for CRL fetcher
- [ ] Auto-enable logic: CA bundle present + trustLevel not nil/NONE → CRL enabled
- [ ] `buildVerifyConnection`: CRL check runs after cert validity, before Badge/DANE
- [ ] CRL reject → connection fails with descriptive error message
- [ ] CRL skip (no CDP) → connection proceeds normally
- [ ] Integration test: mTLS with revoked mock cert → rejected
- [ ] Integration test: mTLS with valid mock cert (CDP present) → accepted
- [ ] Integration test: mTLS with cert without CDP → accepted (CRL skipped)
- [ ] Integration test: WithCRLCheckDisabled → CRL does not run even with CA bundle
- [ ] Integration test: Badge fail + CRL pass → rejected (dual-track independence)
- [ ] Integration test: Badge pass + CRL revoked → rejected (dual-track independence)
