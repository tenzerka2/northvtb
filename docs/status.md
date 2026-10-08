# Verification evidence

All five implementation stages are represented in the repository. The current head must pass the regression jobs on [PR #1](https://github.com/tenzerka2/northvtb/pull/1) before review. Historical checkpoints below are observed successful runs, not inferred results.

| Gate | Observed successful run | Evidence |
| --- | --- | --- |
| Foundation | [37815056773](https://github.com/tenzerka2/northvtb/actions/runs/37815056773) | Go/race, schema roles/invariants, OpenAPI, container build |
| Trust core | [37815973585](https://github.com/tenzerka2/northvtb/actions/runs/37815973585) | PostgreSQL approval/versioning/revocation, expiry and signature checks, transactional audit rollback, privileged audit tampering detection |
| Authorization | [37816994720](https://github.com/tenzerka2/northvtb/actions/runs/37816994720) | 32 concurrent issuers: one grant; 32 consumers: one command; idempotency, transaction binding, expiry and revocation |
| Payment library | [37818017577](https://github.com/tenzerka2/northvtb/actions/runs/37818017577) | Durable capture, UNKNOWN recovery, concurrent retries, refunds, signed callbacks, pre-dispatch revocation and ASK_USER continuation |
| HTTP end-to-end | [37819566215](https://github.com/tenzerka2/northvtb/actions/runs/37819566215) | Owner/agent separation, three offers, payment/consumption, replay and amount-tampering rejection over HTTP |
| Hardening/Compose checkpoint | [37821990456](https://github.com/tenzerka2/northvtb/actions/runs/37821990456) | Full `make demo` through Compose, PostgreSQL/outbox/expiry tests, trace export test, rate-limit/strict-JSON tests and HTTP refund path |

The final regression suite additionally verifies owner-scoped audit evidence, separate rule/reason codes, live stolen-agent authority, callback settlement from UNKNOWN exactly once, expired/revoked reservation cleanup and generated OpenAPI consistency. Final head results are visible in [the workflow history](https://github.com/tenzerka2/northvtb/actions/workflows/foundation.yml) and PR checks.

Local verification uses official SHA-256-verified Go 1.26.9: `go test -race -count=1 ./...`, `go vet ./...`, OpenAPI validator 0.7.2 and `git diff --check`. `govulncheck ./...` reported **No vulnerabilities found** on 2026-10-08. This is a point-in-time vulnerability database result, not a guarantee of absence of defects.

PostgreSQL/Docker are not available in the local editing runtime. Database tests explicitly SKIP without NORTH_TEST_DSN; those skips are not counted as integration evidence. CI provides PostgreSQL 17, restricted app/provider roles and a separate admin connection for deliberate tamper tests. Compose tests create real isolated login roles and run the same user-facing demo command. Container target is linux/amd64.

Known boundaries: sandbox credentials, sandbox Ed25519, simulated provider and controlled merchant catalogue; full refunds only; local durable inbox; external audit anchoring, OIDC/HSM/key rotation, real bank adapters and production operational qualification are not delivered. See production-roadmap.md and security-review.md.
