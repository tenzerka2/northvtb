# NORTH threat model

Scope: untrusted agents, intents and merchants; trusted application runtime and narrowly privileged PostgreSQL role. Database administrator compromise and signing-key compromise require external controls. Status F means foundation/design only, not an implemented defense in a running payment flow.

| Threat / attack | Impact | Mitigation | Residual risk | MVP status |
| --- | --- | --- | --- | --- |
| Prompt injection changes purchase intent | Unwanted purchase | LLM has draft-only access; owner confirms canonical terms; deterministic checks | Owner approves deceptive terms | F; approval not built |
| Agent compromise | Unauthorized proposals | Agent/owner binding, scope, merchant/amount limits | Abuse within an approved mandate | F |
| Credential theft | Agent impersonation | Revocation checked under lock, short-lived scoped credentials | Use before detection | F |
| Stolen mandate ID | Cross-owner use | Derive principal from auth, verify bound agent and owner | Compromised bound identity | F |
| Mandate tampering | Limit changes | Immutable signed canonical terms, database guards | Signing/admin compromise | DB guard drafted; signing pending |
| Transaction tampering | Different amount/product/merchant | Exact canonical digest and authoritative offer match at enforcement | False trusted catalogue data | F |
| Replay | Multiple charges | Unique grant->command, terminal consumed grant, stable provider key | Provider breaks idempotency | Schema unique constraint only |
| Double spend / parallel grants | Limit overrun | Mandate lock and usage reservations in issuance transaction | Implementation lock-order defects | Schema counter bounds only |
| Parallel consume | Duplicate dispatch | Atomic state transition plus unique payment grant | Provider retention mismatch | Schema uniqueness only |
| TOCTOU / revoke during dispatch | Payment after revocation | Recheck at SUBMITTED linearization point; cancel before it | Remote operation after this point cannot be guaranteed cancelled | F |
| Expired mandate | Stale approval used | Injected clock and fresh expiry checks at authorization, consume and dispatch | Clock skew | Value tests only |
| Revoked mandate | Cancelled mandate used | Database lifecycle reread and locks | Already submitted operation | F |
| Revoked agent | Continued credential use | Agent lock and revocation check throughout | Detection latency | F |
| Merchant spoofing | Funds to attacker | Authoritative merchant ID/payee mapping and authenticated catalogue | Catalogue operator compromise | F |
| Forged product attributes | Wrong item passes policy | Offer revision and verified catalogue values, total costs bound | Physical fulfillment fraud outside payment authorization | F |
| Provider timeout | Retry double charge | UNKNOWN with held reservation, stable keys and reconciliation | Provider cannot resolve status | F |
| Duplicate/forged callback | Repeated accounting/state regression | Signed callback, unique provider/event ID, payment field checks | Provider signing-key compromise | Schema dedupe only |
| Audit tampering | Hidden unauthorized actions | Append-only role, chained events, external signed checkpoints | Privileged rewrite without external checkpoint | DB guards only; chain pending |
| Privilege escalation | Agent approves its own mandate | Separate owner scopes/subject, no client-supplied principal | Owner IdP compromise | F |
| Key substitution / algorithm confusion | Forged authorization | Purpose-bound CryptoProvider and key policy; pinned algorithms | HSM/operator compromise | Port only |
| Idempotency key body substitution | Reuse successful authorization for new body | Principal/operation namespace plus canonical request hash | Key retention errors | Schema only |
| Outbox redelivery | Repeated external effects | At-least-once event dedupe and stable provider operation keys | Non-idempotent adapter | Schema only |
| Refund abuse | Unauthorized reversal or restored spend | Owner scope, refund cap and stable refund keys; no restored mandate uses | Provider refund ambiguity | F |
| Resource exhaustion | Availability loss | Request bounds/timeouts, identity rate limits, bounded worker batches | Distributed denial of service | HTTP size/time limits only |

No claim of banking certification, regulatory compliance, production readiness or absence of security defects follows from this model. Real integration requires bank-specific security review and threat testing.
