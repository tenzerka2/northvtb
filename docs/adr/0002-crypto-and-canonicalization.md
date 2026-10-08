# ADR 0002: Versioned canonical structs and replaceable cryptography

Accepted design, implementation staged.

Use fixed typed schemas, integer minor units, UTC integer timestamps, explicit fields and sorted/unique set fields. Reject unknown JSON fields and duplicate keys at the transport boundary. Canonicalization must not use arbitrary JSON maps or float conversion. Preserve UTF-8 strings exactly; document any normalization before owner approval. Every signature/hash has a purpose and schema prefix.

CryptoProvider abstracts Sign and Verify with explicit purpose, key ID and payload. MVP may use Ed25519 from Go standard library; production can use a bank-specific adapter/HSM subject to its certification requirements. Core domain knows neither private keys nor a specific algorithm. Pin purpose-to-key usage and prevent retired/revoked keys from signing. Keep verification keys needed for retained audit evidence. Canonicalization changes require a new schema version and golden compatibility vectors.

Signing does not prove owner approval: the approval use case must authenticate the owner and bind approval to the exact digest, then sign. Likewise, a valid grant signature does not prove current authorization: enforcement must reread database lifecycle, agent binding and expiry.
