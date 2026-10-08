# NORTH architecture

Status: sandbox MVP implementation. Financial API and payment flow are gated by PostgreSQL, HTTP and Compose tests; this is not a production banking system. Amounts are integer minor units (RUB 85,000 = 8,500,000 kopecks). All timestamps are UTC; expiry is exclusive (`now >= expires_at` rejects). No float or natural-language value enters authorization.

## Boundaries and dependencies

The deployment is a Go modular monolith with PostgreSQL as its system of record. Domain packages have no HTTP, SQL, LLM, clock or payment SDK dependencies. Application use cases own transactions and call ports; adapters implement ports. Redis is unnecessary for the MVP. No external LLM is required to run.

| Context | Owns | Trust boundary |
| --- | --- | --- |
| Identity | registered agents, owner identity, credential references and revocation | authenticated subject, never a supplied agent ID |
| Intent | untrusted user text and structured drafts | may propose, cannot approve |
| Mandates | immutable terms, owner approval, signatures, lifecycle | only owner approves/revokes; no agent self-approval |
| Policy | pure deterministic evaluation with rule trace | authoritative merchant/offer and database state |
| Authorization | transaction-bound, expiring, single-use grants and reservations | must run atomically with evaluation |
| Enforcement | repeat validation and consume grant | sole entry to payment execution |
| Payments | durable attempts, provider reconciliation, refunds | adapter credentials never exposed to agents |
| Audit | append-only chained evidence and outbox | application role cannot mutate history |

Planned packages: `internal/identity`, `intent`, `mandates`, `policy`, `authorization`, `enforcement`, `payments`, `merchants`, `audit`; each contains domain/application ports and adapters only as needed. Foundation shared value/state types live in `internal/domain`; `internal/cryptography` defines the replaceable signing port; `internal/platform/httpapi` owns transport infrastructure. Do not manufacture empty packages or fake business endpoints to imply implementation.

## Authorization and execution

Canonical terms include schema version, owner, mandate ID/version, agent ID, action, purpose, product, category, condition, currency, merchant policy, amount ceiling, operation count, risk ceiling, creation and expiry. Active terms never change. An owner must explicitly approve the exact canonical digest. A new version has a new ID and predecessor relation; replacement revokes the predecessor atomically. User approval authentication must be independent of the agent credential.

Transaction canonical bytes include schema version, mandate/agent/merchant/offer IDs, product, category, condition, quantity, unit price, total including fees/shipping, currency and offer revision. Merchant/product claims come from the trusted sandbox catalogue or an authenticated merchant adapter, never from agent assertions alone. A signed grant also binds grant ID, nonce, issued/expiry times, signing key ID and max uses=1. Signatures use a purpose/version prefix to prevent cross-protocol substitution. Hashes are integrity bindings, not credentials.

All mutations use a fixed lock order: agent -> mandate -> grant -> payment -> audit head. Evaluation and grant issuance are one transaction. Lock the agent and mandate; validate authoritative state and signed terms; reserve `reserved_uses + consumed_uses < max_uses`; insert the grant, audit event, outbox and idempotent response together. Reserved usage prevents multiple outstanding grants exhausting a single-use mandate.

Enforcement authenticates the bound agent and locks the same records. It verifies signatures, exact transaction hash and authoritative offer, expiry, revocation and reservation. It atomically consumes the grant and creates one durable payment command. A consumed grant can never become reusable, including when payment fails. Provider network I/O occurs outside the database transaction, using the payment ID as provider idempotency key. A failed definitive payment releases the reservation but does not resurrect its grant; a fresh proposal is required.

Dispatch rechecks revocation and expiry immediately before atomically marking the command SUBMITTED. This commit is the cancellation linearization point: revocation committed first prevents submission; revocation afterwards cannot promise to cancel a command that may already be sent. Pending-but-not-submitted commands are cancellable. Do not hold database locks across remote network calls. A crash after SUBMITTED is handled by status reconciliation and idempotent provider retry, never by issuing another payment identity.

A timeout means UNKNOWN, not FAILED. Keep its reservation until GetStatus or authenticated callback resolves the attempt. SUCCESS transfers reserved usage to consumed usage atomically and sets mandate CONSUMED at its limit. Refunds do not restore purchasing authority. A provider must support durable idempotency and status lookup; without these properties an adapter cannot promise no duplicate external effect. Authorization/capture are separate durable operations with separate stable keys; ambiguous authorization must be resolved before capture. Uncaptured authorizations require provider-specific void/expiry handling before releasing a reservation.

## State machines

Mandate: DRAFT -> ACTIVE or REVOKED; ACTIVE -> REVOKED, EXPIRED or CONSUMED. Terminal states never reactivate. Effective expiration is checked at every use, independently of an expiry worker. Remaining grants must be expired/released atomically before a new reservation is granted. Agent: ACTIVE -> REVOKED only; re-enrolment gets a new identity.

Grant: ISSUED -> CONSUMED, EXPIRED or REVOKED. CONSUMED is terminal and corresponds to one durable payment command, not necessarily a successful charge.

Payment: PENDING -> SUBMITTED or CANCELLED; SUBMITTED -> SUCCEEDED, FAILED or UNKNOWN; UNKNOWN -> SUCCEEDED or FAILED after reconciliation. Refund state belongs to a separate durable refund operation; payment SUCCEEDED is not overwritten. Each callback uses a unique provider event ID, signature validation and payment/currency/amount binding. Duplicate or out-of-order callbacks cannot regress final state.

ASK_USER is a persisted, expiring challenge bound to the exact proposal digest and owner. Owner consent may relax only explicitly overridable risk rules. It never overrides amount, wrong agent, revoked/expired mandate or transaction binding. A mandate requiring verified merchants is a hard denial for an unverified merchant. Only a mandate permitting owner escalation may ASK_USER. Consent consumes a one-time challenge and triggers full fresh evaluation, not blanket ALLOW.

## API conventions

OpenAPI 3.1 is authoritative for implemented endpoints. Future financial endpoints stay in the roadmap until implemented. OAuth2/OIDC-compatible authentication yields issuer+subject, scopes and owner/agent identity; JWT validation must pin algorithm, issuer, audience and key and validate time claims. ID possession alone grants no access. No default credentials, authentication bypass or production-mode sandbox switch.

Mutations require `Idempotency-Key` (bounded ASCII). Namespace includes authenticated principal, operation and key. SHA-256 of canonical validated request is persisted with final response. Same key/body returns the stored result, different body is HTTP 409; concurrent identical submissions serialize. Retryable infrastructure failures do not permanently poison the key. Retention must outlive the supported retry window and provider retention; never silently expire payment identities. Error envelope: `error.code`, safe `error.message`, `request_id`; no tokens, stack traces or provider secrets. Use 400 syntax, 401 authentication, 403 subject/scope, 404 inaccessible resource, 409 conflict, 422 invalid state/policy, 429 throttled, 503 readiness/dependency. Rule codes are separate from HTTP errors.

## Audit and operational safety

Audit append serializes on a singleton head in the same transaction as the business mutation. Hash uses a versioned domain prefix and unambiguous canonical payload with sequence, previous hash, event ID, timestamp, actor, type and subject. The database role cannot UPDATE/DELETE/TRUNCATE events. Recompute full history and compare an externally retained signed checkpoint to detect rollback or suffix deletion; a local chain alone cannot detect a privileged attacker rewriting the entire chain. Outbox delivery is at least once; consumers deduplicate event ID. Leases recover after worker crashes. Do not claim exactly-once transport.

Logs contain request IDs and sanitized reason codes, not raw intents, credentials or payment data. Health is liveness only; readiness requires dependencies and migrations. Foundation mode returns readiness 503; explicitly configured sandbox mode checks both application and provider databases. Production needs OIDC integration, rate limiting by authenticated identity, OpenTelemetry, TLS, key management/rotation, restore testing, independent audit anchoring and banking review. No real funds move in the sandbox.

## Stage gates

1. Foundation: domain invariants/state tests; schema up twice safely via a migration runner; schema permission and constraint tests on PostgreSQL; error/health contract checks; OpenAPI validation.
2. Trust: signed immutable approval, subject binding, versioning, tamper/expiry/revocation tests and audit atomicity.
3. Policy/authorization: rule traces and PostgreSQL concurrent reservations/consume; exactly one command per grant; idempotency conflicts and replay denied.
4. Execution: deterministic three-offer demo, durable provider state, UNKNOWN recovery, callbacks and refund tests; ASK_USER continuation.
5. Hardening: adversarial matrix, deployment/telemetry and recovery tests; documented actual results.

No later stage starts until the previous gate passes. See THREAT_MODEL.md and docs/status.md for implementation evidence.

## Implemented adapter choices

Sandbox identity uses a separate owner bearer and hashed agent credentials; the authentication port is ready for a bank OIDC adapter, which is not implemented. HTTP idempotency shares the transaction with the business operation. `internal/trust` owns agent/mandate use cases; policy, authorization, payments, audit and merchants have separate packages. `internal/adapters/postgres` implements their transactional ports. The HTTP adapter and runtime are composition/read-model boundaries.

The worker performs expiry/revocation cleanup, payment/refund reconciliation with bounded backoff, and outbox delivery to a durable local inbox. External event transport and signed external audit checkpoint storage are production extension points, not claimed delivered integrations. OpenTelemetry traces HTTP and worker batches; owner-protected Prometheus metrics can be scraped by an OTel Collector.
