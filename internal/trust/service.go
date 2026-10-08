package trust

import (
	"context"
	"encoding/json"
	"github.com/tenzerka2/northvtb/internal/cryptography"
	"github.com/tenzerka2/northvtb/internal/domain"
)

// Tx is implemented by a PostgreSQL adapter. Get methods lock rows.
// All mutation methods and Emit participate in the same transaction.
type Tx interface {
	Agent(string) (Agent, error)
	InsertAgent(Agent) error
	RevokeAgent(string, int64) error
	Mandate(string) (Mandate, error)
	InsertMandate(Mandate) error
	SaveMandate(Mandate) error
	Emit(actor, kind, subject string, at int64) error
}
type Store interface {
	Within(context.Context, func(Tx) error) error
}
type Service struct {
	Store  Store
	Crypto cryptography.Provider
	Now    func() int64
}

func (s Service) Register(ctx context.Context, owner string, a Agent) (Agent, error) {
	if owner == "" || !valid(a.Provider) || a.CredentialRef == "" || len(a.CredentialRef) > 512 || a.Risk < 0 || a.Risk > 100 {
		return Agent{}, domain.ErrInvalid
	}
	a.ID = ID()
	a.Owner = owner
	a.Version = 1
	a.Status = "ACTIVE"
	a.CreatedAt = s.Now()
	a.RevokedAt = 0
	e := s.Store.Within(ctx, func(tx Tx) error {
		if e := tx.InsertAgent(a); e != nil {
			return e
		}
		return tx.Emit(owner, "agent.registered", a.ID, a.CreatedAt)
	})
	return a, e
}
func (s Service) Draft(ctx context.Context, owner string, t Terms) (Mandate, error) {
	t.SchemaVersion = 1
	t.ID = ID()
	t.Owner = owner
	t.CreatedAt = s.Now()
	t.Version = 1
	t.PredecessorID = ""
	raw, e := t.Canonical()
	if e != nil {
		return Mandate{}, e
	}
	if e = json.Unmarshal(raw, &t); e != nil {
		return Mandate{}, e
	}
	m := Mandate{Terms: t, State: domain.Draft}
	e = s.Store.Within(ctx, func(tx Tx) error {
		a, e := tx.Agent(t.AgentID)
		if e != nil {
			return e
		}
		if a.Owner != owner || a.Status != "ACTIVE" {
			return ErrDenied
		}
		if e = tx.InsertMandate(m); e != nil {
			return e
		}
		return tx.Emit(owner, "mandate.created", t.ID, s.Now())
	})
	return m, e
}
func (s Service) Approve(ctx context.Context, owner, agent, id, expectedDigest string) (Mandate, error) {
	var out Mandate
	e := s.Store.Within(ctx, func(tx Tx) error {
		a, e := tx.Agent(agent)
		if e != nil {
			return e
		}
		m, e := tx.Mandate(id)
		if e != nil {
			return e
		}
		if a.Owner != owner || a.Status != "ACTIVE" || m.Terms.Owner != owner || m.Terms.AgentID != agent {
			return ErrDenied
		}
		if m.State != domain.Draft || s.Now() >= m.Terms.ExpiresAt {
			return ErrConflict
		}
		digest, e := m.Terms.Digest()
		if e != nil {
			return e
		}
		if digest != expectedDigest {
			return ErrDenied
		}
		b, e := m.Terms.Canonical()
		if e != nil {
			return e
		}
		sig, e := s.Crypto.Sign(ctx, cryptography.MandateV1, b)
		if e != nil {
			return e
		}
		m.State = domain.Active
		m.Signature = sig
		m.ApprovedAt = s.Now()
		if e = tx.SaveMandate(m); e != nil {
			return e
		}
		out = m
		return tx.Emit(owner, "mandate.approved", id, s.Now())
	})
	return out, e
}
func (s Service) Verify(ctx context.Context, a Agent, m Mandate) error {
	if a.ID != m.Terms.AgentID || a.Owner != m.Terms.Owner || a.Status != "ACTIVE" || m.State != domain.Active || s.Now() >= m.Terms.ExpiresAt || m.ApprovedAt <= 0 {
		return ErrDenied
	}
	b, e := m.Terms.Canonical()
	if e != nil {
		return ErrDenied
	}
	if e = s.Crypto.Verify(ctx, cryptography.MandateV1, b, m.Signature); e != nil {
		return ErrDenied
	}
	return nil
}

// Check reloads current database state. Callers must not cache Verify results for execution.
func (s Service) Check(ctx context.Context, agent, id string) error {
	return s.Store.Within(ctx, func(tx Tx) error {
		a, e := tx.Agent(agent)
		if e != nil {
			return e
		}
		m, e := tx.Mandate(id)
		if e != nil {
			return e
		}
		return s.Verify(ctx, a, m)
	})
}
func (s Service) Revoke(ctx context.Context, owner, agent, id string) error {
	return s.Store.Within(ctx, func(tx Tx) error {
		a, e := tx.Agent(agent)
		if e != nil {
			return e
		}
		m, e := tx.Mandate(id)
		if e != nil {
			return e
		}
		if a.Owner != owner || m.Terms.Owner != owner || m.Terms.AgentID != agent {
			return ErrDenied
		}
		if m.State == domain.Revoked {
			return nil
		}
		if e = m.State.Transition(domain.Revoked); e != nil {
			return ErrConflict
		}
		m.State = domain.Revoked
		if e = tx.SaveMandate(m); e != nil {
			return e
		}
		return tx.Emit(owner, "mandate.revoked", id, s.Now())
	})
}
func (s Service) RevokeAgent(ctx context.Context, owner, agent string) error {
	return s.Store.Within(ctx, func(tx Tx) error {
		a, e := tx.Agent(agent)
		if e != nil {
			return e
		}
		if a.Owner != owner {
			return ErrDenied
		}
		if a.Status == "REVOKED" {
			return nil
		}
		if e = tx.RevokeAgent(agent, s.Now()); e != nil {
			return e
		}
		return tx.Emit(owner, "agent.revoked", agent, s.Now())
	})
}

// Replace revokes the predecessor and creates a draft atomically. New terms require fresh owner approval.
func (s Service) Replace(ctx context.Context, owner, agent, id string, t Terms) (Mandate, error) {
	var out Mandate
	e := s.Store.Within(ctx, func(tx Tx) error {
		a, e := tx.Agent(agent)
		if e != nil {
			return e
		}
		old, e := tx.Mandate(id)
		if e != nil {
			return e
		}
		if a.Owner != owner || a.Status != "ACTIVE" || old.Terms.Owner != owner || old.Terms.AgentID != agent {
			return ErrDenied
		}
		if old.State != domain.Active {
			return ErrConflict
		}
		t.SchemaVersion = 1
		t.ID = ID()
		t.Owner = owner
		t.AgentID = agent
		t.Version = old.Terms.Version + 1
		t.PredecessorID = id
		t.CreatedAt = s.Now()
		if _, e = t.Canonical(); e != nil {
			return e
		}
		old.State = domain.Revoked
		if e = tx.SaveMandate(old); e != nil {
			return e
		}
		if e = tx.Emit(owner, "mandate.revoked", id, s.Now()); e != nil {
			return e
		}
		out = Mandate{Terms: t, State: domain.Draft}
		if e = tx.InsertMandate(out); e != nil {
			return e
		}
		return tx.Emit(owner, "mandate.created", t.ID, s.Now())
	})
	return out, e
}
