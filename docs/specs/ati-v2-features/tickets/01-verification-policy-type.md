# 01 — VerificationPolicy type + deprecation expand

**What to build:** Introduce the new `VerificationPolicy` type with NONE/BASIC/ENHANCED/ADVANCED constants, aligned with ATI Console trust levels. Old `TrustLevel` type becomes a deprecated alias. All existing code still compiles unchanged — this is the expand phase of an expand-contract rename.

**Blocked by:** None — can start immediately.

**Status:** ready-for-agent

- [ ] New `ati/verification_policy.go` defines `VerificationPolicy` type and constants (PolicyNone, PolicyBasic, PolicyEnhanced, PolicyAdvanced)
- [ ] `DisplayName()` returns correct Console labels (L0 无认证, L1 基础认证, L2 增强认证, L3 高级认证)
- [ ] `HasBadgeVerification()` and `HasDANEVerification()` return correct booleans
- [ ] `ati/trust_level.go` rewritten: `TrustLevel = VerificationPolicy` type alias with `// Deprecated:` comments on PKIOnly/BadgeRequired/DANEAndBadge
- [ ] All existing tests pass without modification (backward compatible)
- [ ] Unit tests for new type methods
