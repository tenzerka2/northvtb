package identity

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
)

type Principal struct{ Owner, AgentID string }
type Authenticator interface {
	Authenticate(context.Context, string) (Principal, error)
}
type Registry interface {
	FindCredential(context.Context, string) (Principal, error)
}

var ErrUnauthenticated = errors.New("unauthenticated")

// SandboxAuth is an explicit local adapter. Production supplies an OIDC adapter
// that pins issuer, audience, algorithm and scopes and returns the same principal.
type SandboxAuth struct {
	OwnerHash [32]byte
	Owner     string
	Registry  Registry
}

func Credential(token string) string {
	h := sha256.Sum256([]byte(token))
	return "sha256:" + hex.EncodeToString(h[:])
}
func (a SandboxAuth) Authenticate(ctx context.Context, token string) (Principal, error) {
	if len(token) < 32 || len(token) > 512 {
		return Principal{}, ErrUnauthenticated
	}
	h := sha256.Sum256([]byte(token))
	if subtle.ConstantTimeCompare(h[:], a.OwnerHash[:]) == 1 {
		return Principal{Owner: a.Owner}, nil
	}
	p, e := a.Registry.FindCredential(ctx, Credential(token))
	if e != nil {
		return Principal{}, ErrUnauthenticated
	}
	return p, nil
}
