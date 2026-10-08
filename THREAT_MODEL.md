# NORTH threat model

Scope: hostile agents, injected intent, untrusted proposal data, stolen identifiers, concurrency and ambiguous provider results. The application runtime and its private signing material remain trusted. Implemented controls are tested in the sandbox; no production-bank certification is implied.

| Attack | Impact | Implemented mitigation / evidence | Residual risk |
| --- | --- | --- | --- |
| Prompt injection or hallucinated intent | Unwanted purchase | Compiler has draft-only port; authenticated owner confirms exact canonical digest; LLM absent from policy | Owner approves malicious terms; optional external compiler is not implemented |
| Compromised agent | Unauthorized proposal/execution | Bound agent identity, immutable mandate, deterministic limits, one-use grant; HTTP role and stolen-authority tests | Abuse inside genuinely approved authority |
| Stolen credential | Impersonation | Hashed agent credentials, unique references, authenticated registry lookup, row-locked revocation rechecks | Activity before revocation; sandbox owner token is not production OIDC |
| Stolen mandate ID | Another agent spends | Owner/agent binding in trust, policy, enforcement; live HTTP stolen-mandate test | Compromise of the correctly bound identity |
| Mandate tampering | Changed limits/merchant/product | Canonical signature, duplicated-column consistency checks, immutable SQL trigger; unit and PostgreSQL tamper tests | Signing key/runtime/database administrator compromise |
| Transaction tampering | Changed sum/payee/product after approval | Signed grant binds full canonical digest; adversarial 82,990 -> 92,990 HTTP demo and field mutation tests | False data from the trusted catalogue operator |
| Grant theft or invalid signature | Unauthorized execution | Authenticated agent binding, key/purpose checks, stored claims comparison, lifecycle check | Theft of both a valid grant and its bound credential within limits |
| Replay | Repeated execution | Terminal single-use grant, unique grant-to-command constraint; 32 parallel consumers | Provider must honor durable idempotency |
| Parallel issuance / double spend | Multiple grants over one-use mandate | Agent/mandate row locks and capacity reservation; 32 parallel issuers yield one grant | Contention/availability; independent banking limits are out of scope |
| Concurrent settlement | Multiple accounting updates | Locked payment/mandate and terminal transition checks; concurrent timeout recovery test | Contradictory authoritative provider results require operator reconciliation |
| TOCTOU / revoke before dispatch | Revoked authority reaches provider | Recheck policy and authority at SUBMITTED boundary; pre-dispatch revocation test | Already submitted external operation may complete |
| Expired mandate or grant | Stale approval used | Exclusive expiry checks at issue, consume and dispatch; effective checks plus expiry sweeper | Trusted clock skew needs production monitoring |
| Revoked mandate | Cancelled mandate reused | Locked persisted state, immutable terminal state; PostgreSQL integration tests | External command submitted before revocation |
| Revoked agent | Credential continues spending | Registry denies authentication; trust/dispatch recheck; sweeper revokes unused authority | Delayed detection before revocation |
| Merchant spoofing / forged attributes | Wrong beneficiary/item | Read-only authoritative catalogue and complete offer revision/field match; proposal/field tests | Catalogue attestation and physical fulfillment are not implemented |
| Provider timeout after capture | Double charge on retry | UNKNOWN retains reservation; stable provider identity and GetStatus reconciliation; one persistent capture verified | Real adapter must support idempotency and status lookup |
| Duplicate / forged callback | Duplicate accounting or regressed state | HMAC, exact amount/currency binding, unique event ID and transition checks; duplicate UNKNOWN settlement test | Provider callback secret compromise |
| Privilege escalation | Agent approves/revokes owner authority | Separate owner/agent API roles and owner checks; HTTP agent-approval rejection | Owner IdP compromise; sandbox authentication must be replaced |
| ASK_USER abuse | Consent overrides hard limits | Exact one-use challenge/digest/owner binding; only explicitly overridable risk; hard rules remain DENY | Owner approves an allowed risk exception |
| Idempotency body substitution | Different request reuses success | Principal+operation namespace, canonical body hash, atomic stored response, advisory lock; conflict tests | Retention and coordinated sandbox secret rotation need operational policy |
| Refund abuse | Excess refund/restored budget | Owner-only command, stable full-refund identity, provider payment lock; authority remains consumed | Partial refunds/voids are not implemented |
| Audit history change | Concealed operation | Append-only app role and SQL trigger, chained canonical evidence, full verification; privileged tamper test | Full privileged rewrite requires independent external checkpoint anchoring |
| Audit failure during mutation | Financial change without evidence | Same transaction for domain state, audit and outbox; rollback integration test | Availability loss when audit storage unavailable |
| Outbox redelivery / worker crash | Duplicate downstream effect | SKIP LOCKED relay, unique durable inbox, atomic delivery marker; concurrent relay test | External transport/consumer is a future adapter |
| SQL privilege expansion | Agent/merchant data overwritten | Parameterized queries, limited app/provider roles, fixed SECURITY DEFINER locker; role/immutability SQL tests | App runtime compromise is beyond an untrusted-agent boundary |
| Cross-protocol crypto use | Mandate signature accepted as grant | Fixed purpose prefixes, explicit key reference, replaceable CryptoProvider; cross-purpose rejection test | HSM, certification and key rotation are not implemented |
| Secret or trace leakage | Credential/data exposure | No request bodies/bearers in logs, hashed credential storage, ignored private files, normalized trace routes; trace export leakage test | Local host compromise; TLS/managed secrets needed for a pilot |
| Resource exhaustion | Denial of service | HTTP size/time limits, bounded global/per-principal rate limiter, DB lock/statement timeouts, worker backoff | Distributed/edge protection and load qualification remain production tasks |

Production requirements and unimplemented integrations are detailed in docs/production-roadmap.md. Test references and observed CI evidence are maintained in docs/status.md; passing tests establish these tested behaviors, not a proof that every possible attack is excluded.
