# Implementation evidence

Foundation passed all gates in [run 37815056773](https://github.com/tenzerka2/northvtb/actions/runs/37815056773). Trust core passed all gates in [run 37815973585](https://github.com/tenzerka2/northvtb/actions/runs/37815973585).

Stage 2 tests include owner approval digest, signature/terms tampering, revoked and expired authority, version replacement, transactional audit rollback and privileged audit tampering detection. PostgreSQL tests run using the restricted application role; deliberate tamper tests use a separately supplied admin connection. Unit tests skip database tests locally when NORTH_TEST_DSN is absent; CI supplies it explicitly.

Stage 3 is under verification: deterministic rule trace, signed transaction-bound grants, expiry, reservation/consume, idempotency and authoritative offer matching. Integration tests race 32 issuers and 32 consumers, require one grant/command, and attack amount, merchant, product, signature, expiry and revocation.

Stage 4 payment execution/marketplace/continuation/refunds and stage 5 hardening have not started. No financial HTTP endpoints or real provider exist yet. The current HTTP service exposes only health/readiness and correctly returns 503 readiness.

Local Go 1.26.9 was installed from a SHA-256-verified official archive. Container builder uses the same checksum-pinned archive because the selected Docker Hub Go tag was unavailable. Container target: linux/amd64. Production key management, OIDC and independent audit anchoring remain required.
