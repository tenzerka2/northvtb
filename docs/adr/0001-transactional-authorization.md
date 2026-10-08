# ADR 0001: PostgreSQL reservations and durable payment commands

Accepted design, implementation staged.

A one-time grant alone prevents grant replay but does not stop two independently issued grants from consuming one mandate. Therefore grant issuance reserves usage under a mandate row lock. Consumption creates one durable payment command under a unique grant constraint. PostgreSQL owns correctness; an in-process mutex or Redis lock cannot substitute for database serialization.

The external provider is outside our transaction. Exactly-once external execution is conditional on durable provider idempotency and reconciliation. Use a stable payment ID, never a new retry key. UNKNOWN holds the reservation. Success consumes it; definitive failure releases it; refund does not restore it. The sandbox provider must persist its own effects and idempotency keys, not use an in-memory map.

Revocation cannot atomically cancel an already-submitted external call. Define SUBMITTED commit as the linearization point and explain that boundary to the owner. Holding a PostgreSQL lock during provider I/O would not make the remote side transactional and creates availability/locking hazards.

Consequence: recovery worker and explicit ambiguous states are mandatory before the end-to-end stage passes. No API response may say FAILED solely due to a timeout.
