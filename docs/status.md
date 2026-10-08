# Implementation evidence

Stage 1 foundation is under development. Stages 2–5 have not started.

Implemented: domain amount/transaction validation and lifecycle transitions, CryptoProvider port, fail-closed health/readiness HTTP service, PostgreSQL foundation schema and role restrictions, initial OpenAPI, architecture decisions and threat analysis.

Not implemented: authenticated financial APIs, persistent application repositories, signing adapter, approval, policy evaluation, grants, enforcement, worker, provider, marketplace, refunds, callbacks, OIDC, OpenTelemetry export and end-to-end demo. Schema objects are storage foundations, not evidence these features work.

Local environment lacks Go, PostgreSQL and Docker. CI is the intended verification environment. Test execution status must be updated with observed results before advancing the foundation gate.
