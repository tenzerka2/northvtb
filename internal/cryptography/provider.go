// Package cryptography defines the bank-replaceable signing boundary.
package cryptography

import "context"

type Purpose string

const (
	MandateV1         Purpose = "north:mandate:v1"
	GrantV1           Purpose = "north:grant:v1"
	AuditCheckpointV1 Purpose = "north:audit-checkpoint:v1"
)

// Signature has an explicit key reference. Algorithm choice is adapter policy,
// never negotiated from attacker-controlled input.
type Signature struct {
	KeyID string `json:"key_id"`
	Value []byte `json:"value"`
}

// Provider implementations MUST domain-separate purpose and reject unknown keys.
// There is deliberately no insecure default implementation.
type Provider interface {
	Sign(ctx context.Context, purpose Purpose, canonical []byte) (Signature, error)
	Verify(ctx context.Context, purpose Purpose, canonical []byte, signature Signature) error
}
