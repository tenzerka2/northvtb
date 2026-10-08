# ADR 0004: Catalogue evidence and reservation ownership

Accepted during stage 3.

Policy receives authoritative offer fields from a PostgreSQL catalogue readable but not writable by the application role. Every proposal must match the complete offer revision, merchant, product, condition, quantity and total costs. Agent-provided risk/verified flags are never trusted. Sandbox catalogue administration belongs to its isolated adapter/setup identity.

Grant expiry is reconciled while holding its agent and mandate locks, before reserving new usage. Consuming a grant does not free capacity; it creates a PENDING command and retains its reservation until a definitive provider outcome. Policy consumption checks the existing grant reservation rather than incorrectly treating its own reservation as exhausted capacity.

Authorization idempotency is scoped by authenticated agent, operation and key. The agent row serializes requests even across mandates, preventing a same-key race before a row exists. This intentionally trades per-agent throughput for simple correctness in the MVP. A retry returns historical authorization output; enforcement independently checks current expiry/revocation.
