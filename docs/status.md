# Implementation evidence

Foundation passed all gates in [run 37815056773](https://github.com/tenzerka2/northvtb/actions/runs/37815056773). Trust core passed all gates in [run 37815973585](https://github.com/tenzerka2/northvtb/actions/runs/37815973585).

Stage 2 tests include owner approval digest, signature/terms tampering, revoked and expired authority, version replacement, transactional audit rollback and privileged audit tampering detection. PostgreSQL tests run using the restricted application role; deliberate tamper tests use a separately supplied admin connection. Unit tests skip database tests locally when NORTH_TEST_DSN is absent; CI supplies it explicitly.

Stage 3 passed all gates in [run 37816994720](https://github.com/tenzerka2/northvtb/actions/runs/37816994720): deterministic rule trace, signed transaction-bound grants, expiry, reservation/consume, idempotency and authoritative offer matching. Integration tests race 32 issuers and 32 consumers, require one grant/command, and attack amount, merchant, product, signature, expiry and revocation.

Stage 4 payment library passed [run 37818017577](https://github.com/tenzerka2/northvtb/actions/runs/37818017577): timeout recovery, one durable sandbox capture, refunds, callbacks, pre-dispatch revocation and risk challenge continuation. Financial HTTP routes, isolated sandbox credentials, merchant discovery and scripts/demo.py are now undergoing end-to-end verification. Stage 5 hardening has not started. No real payment rail is connected.

Local Go 1.26.9 was installed from a SHA-256-verified official archive. Container builder uses the same checksum-pinned archive because the selected Docker Hub Go tag was unavailable. Container target: linux/amd64. Production key management, OIDC and independent audit anchoring remain required.
