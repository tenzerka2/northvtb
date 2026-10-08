package cryptography

import (
	"context"
	"crypto/ed25519"
	"errors"
)

// Ed25519Provider is a sandbox adapter. Supply private key bytes from secret storage.
type Ed25519Provider struct {
	id      string
	private ed25519.PrivateKey
	public  ed25519.PublicKey
}

func NewEd25519(id string, private []byte) (*Ed25519Provider, error) {
	if id == "" || len(private) != ed25519.PrivateKeySize {
		return nil, errors.New("invalid signing key")
	}
	k := append(ed25519.PrivateKey(nil), private...)
	return &Ed25519Provider{id, k, k.Public().(ed25519.PublicKey)}, nil
}
func message(p Purpose, b []byte) ([]byte, error) {
	switch p {
	case MandateV1, GrantV1, AuditCheckpointV1:
	default:
		return nil, errors.New("unsupported signing purpose")
	}
	return append(append([]byte(string(p)), 0), b...), nil
}
func (p *Ed25519Provider) Sign(ctx context.Context, purpose Purpose, b []byte) (Signature, error) {
	if e := ctx.Err(); e != nil {
		return Signature{}, e
	}
	m, e := message(purpose, b)
	if e != nil {
		return Signature{}, e
	}
	return Signature{p.id, ed25519.Sign(p.private, m)}, nil
}
func (p *Ed25519Provider) Verify(ctx context.Context, purpose Purpose, b []byte, s Signature) error {
	if e := ctx.Err(); e != nil {
		return e
	}
	m, e := message(purpose, b)
	if e != nil {
		return e
	}
	if s.KeyID != p.id || !ed25519.Verify(p.public, m, s.Value) {
		return errors.New("invalid signature")
	}
	return nil
}
