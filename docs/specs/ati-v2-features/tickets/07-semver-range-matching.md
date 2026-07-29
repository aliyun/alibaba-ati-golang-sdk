# 07 — Full semver range matching for DNS TXT discovery

**What to build:** When multiple `_ati` DNS TXT records exist with different `av` values, version selection uses proper semver range evaluation (matching Java SDK's semver4j behavior). Supports `^1.2.0`, `~1.2.0`, `>=1.0.0`, range expressions, and "no constraint = latest version".

**Blocked by:** None — can start immediately.

**Status:** ready-for-agent

- [ ] Add `github.com/Masterminds/semver/v3` dependency
- [ ] Rewrite `resolveLatestCompatible` in `ati/version_policy.go` to use `semver.NewConstraint()` for range parsing
- [ ] Filter records with `constraint.Check(version)`, then pick the highest among matches
- [ ] `^1.2.0` correctly matches 1.2.0, 1.3.0, 1.99.0; rejects 1.1.9, 2.0.0
- [ ] `~1.2.0` correctly matches 1.2.0, 1.2.5; rejects 1.3.0
- [ ] `>=1.0.0` matches 1.0.0, 2.0.0, etc.
- [ ] No constraint → returns the highest version across all records
- [ ] No matching records → returns descriptive error
- [ ] Existing `VersionPolicyExact` and `VersionPolicyLatest` behavior unchanged
