# 05 — CRL core library (verify/crl package)

**What to build:** A standalone `verify/crl` package that resolves CDP URIs from a certificate chain, fetches and caches CRLs (nextUpdate-aware, 12h max), validates CRL signatures against issuing CA, and checks whether a client certificate serial is revoked. Independently testable with mock HTTP — no server integration yet.

**Blocked by:** None — can start immediately.

**Status:** ready-for-agent

- [ ] `verify/crl/result.go`: Status enum (Skipped/Passed/Revoked/Failed), Result struct, ShouldReject()
- [ ] `verify/crl/cdp.go`: ResolveCDP uses `x509.Certificate.CRLDistributionPoints` (leaf → issuer fallback)
- [ ] CDP: no CDP on chain → Skipped; CDP exists but no HTTP(S) URI → Failed
- [ ] `verify/crl/validator.go`: Parse (x509.ParseRevocationList), VerifySignature (CheckSignatureFrom), IsRevoked, ValidateNotRevoked
- [ ] `verify/crl/fetcher.go`: HTTP fetch + sync.Mutex cache, TTL = min(nextUpdate, 12h), Accept header
- [ ] `verify/crl/checker.go`: Check() orchestrates CDP → fetch → validate, fail-closed on any error when CDP is active
- [ ] Unit test: revoked serial → Result{Revoked}
- [ ] Unit test: valid serial → Result{Passed}
- [ ] Unit test: no CDP → Result{Skipped}
- [ ] Unit test: fetch failure (CDP active) → Result{Failed}
- [ ] Unit test: invalid CRL signature → Result{Failed}
- [ ] Unit test: cache hit before TTL → no second HTTP call
- [ ] Unit test: cache expired → re-fetches
