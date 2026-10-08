# Implementation evidence

Stage 1 foundation is under development. Stages 2–5 have not started.

Implemented: domain amount/transaction validation and lifecycle transitions, CryptoProvider port, fail-closed health/readiness HTTP service, PostgreSQL foundation schema and role restrictions, initial OpenAPI, architecture decisions and threat analysis.

Not implemented: authenticated financial APIs, persistent application repositories, signing adapter, approval, policy evaluation, grants, enforcement, worker, provider, marketplace, refunds, callbacks, OIDC, OpenTelemetry export and end-to-end demo. Schema objects are storage foundations, not evidence these features work.

Go 1.26.9 was installed locally from an official SHA-256-verified archive. Local `go test -race -count=1 ./...`, `go vet ./...`, and build passed. OpenAPI validator 0.7.2 and PostgreSQL SQL parser also passed locally.

GitHub Actions run https://github.com/tenzerka2/northvtb/actions/runs/37814749579 confirmed Go tests, vet, build, OpenAPI validation and schema integration tests on PostgreSQL 17. The container build failed because Docker Hub returned not-found for `golang:1.26.9-bookworm`. The Dockerfile now installs the checksum-pinned official Go archive on Debian; revalidation is required. Container architecture is currently linux/amd64 only. PostgreSQL and Docker are unavailable locally.

The full foundation gate remains pending a successful container build. No later stage has started.
