# ADR 0003: Evidence before advancing stages

Accepted.

Financial correctness must not be inferred from generated code. Stage one exports only health and readiness; readiness fails closed until dependencies and services exist. Contracts describing implemented routes are separate from the financial roadmap. No stub financial endpoints or fake successful responses.

Run Go tests with the race detector and PostgreSQL schema tests in CI. A green unit suite alone is insufficient for trust/authorization gates. A missing tool, unavailable runner or permission denial is a blocked gate, not a passed test. Record actual CI URLs and limitations in docs/status.md. Continue later stages only after preceding evidence is available.
