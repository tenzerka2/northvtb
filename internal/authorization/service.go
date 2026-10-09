package authorization

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"

	"github.com/tenzerka2/northvtb/internal/cryptography"
	"github.com/tenzerka2/northvtb/internal/domain"
	"github.com/tenzerka2/northvtb/internal/policy"
	"github.com/tenzerka2/northvtb/internal/trust"
)

var ErrReplay = errors.New("grant not usable")
var ErrHash = errors.New("transaction hash mismatch")

type Claims struct {
	RiskApprovalID string        `json:"risk_approval_id"`
	ID             string        `json:"grant_id"`
	MandateID      string        `json:"mandate_id"`
	AgentID        string        `json:"agent_id"`
	MerchantID     string        `json:"merchant_id"`
	Hash           string        `json:"transaction_hash"`
	Amount         domain.Amount `json:"amount"`
	Currency       string        `json:"currency"`
	IssuedAt       int64         `json:"issued_at"`
	ExpiresAt      int64         `json:"expires_at"`
	Nonce          string        `json:"nonce"`
	MaxUses        int           `json:"max_uses"`
}
type Challenge struct {
	ID, AgentID, MandateID, Hash, GrantID string
	ExpiresAt, ApprovedAt                 int64
}
type Grant struct {
	Claims      Claims                 `json:"claims"`
	Signature   cryptography.Signature `json:"signature"`
	State       domain.GrantState      `json:"-"`
	Transaction domain.TransactionV1   `json:"-"`
}
type Response struct {
	ChallengeID string        `json:"challenge_id,omitempty"`
	Policy      policy.Result `json:"policy"`
	Grant       *Grant        `json:"grant,omitempty"`
}
type Tx interface {
	trust.Tx
	ApprovedChallenge(string, string, string, int64) (string, error)
	NewChallenge(Challenge) error
	Challenge(string) (Challenge, error)
	ApproveChallenge(string, int64) error
	BindChallenge(string, string) error
	Offer(string) (policy.Offer, error)
	Grant(string) (Grant, error)
	InsertGrant(Grant) error
	ExpireGrants(string, int64) (int64, error)
	Consume(Grant, string, int64) error
	Cached(principal, key string) (string, []byte, error)
	Cache(principal, key, hash string, body []byte, at int64) error
}
type Store interface {
	Authorization(context.Context, func(Tx) error) error
}
type Service struct {
	Store  Store
	Trust  trust.Service
	Crypto cryptography.Provider
	Now    func() int64
}

func keyValid(s string) bool {
	if len(s) < 1 || len(s) > 128 {
		return false
	}
	for _, c := range s {
		if c < '!' || c > '~' {
			return false
		}
	}
	return true
}
func (s Service) Issue(ctx context.Context, agent, key string, t domain.TransactionV1) (Response, error) {
	var out Response
	if !keyValid(key) || t.Validate() != nil {
		return out, domain.ErrInvalid
	}
	requestHash, e := t.Digest()
	if e != nil {
		return out, e
	}
	e = s.Store.Authorization(ctx, func(tx Tx) error {
		a, e := tx.Agent(agent)
		if e != nil {
			return e
		}
		if a.Status != "ACTIVE" || t.AgentID != agent {
			return trust.ErrDenied
		}
		h, b, e := tx.Cached(agent, key)
		if e == nil {
			if h != requestHash {
				return trust.ErrConflict
			}
			return json.Unmarshal(b, &out)
		}
		if !errors.Is(e, trust.ErrNotFound) {
			return e
		}
		m, e := tx.Mandate(t.MandateID)
		if e != nil {
			return e
		}
		if e = s.Trust.Verify(ctx, a, m); e != nil {
			return e
		}
		released, e := tx.ExpireGrants(m.Terms.ID, s.Now())
		if e != nil {
			return e
		}
		m.Reserved -= released
		if m.Reserved < 0 {
			return trust.ErrConflict
		}
		o, e := tx.Offer(t.OfferID)
		if e != nil {
			return e
		}
		approval, e := tx.ApprovedChallenge(agent, m.Terms.ID, requestHash, s.Now())
		if e != nil {
			return e
		}
		out.Policy = policy.Evaluate(policy.Input{Agent: a, Mandate: m, Transaction: t, Offer: o, Now: s.Now(), OwnerRiskApproved: approval != "", Available: domain.Available(m.State, s.Now(), m.Terms.ExpiresAt, m.Terms.MaxUses, m.Reserved, m.Consumed)})
		canonical, _ := t.Canonical()
		if e = tx.EmitData(agent, "transaction.proposed", requestHash, s.Now(), canonical); e != nil {
			return e
		}
		trace, _ := json.Marshal(out.Policy)
		if e = tx.EmitData(agent, "policy.evaluated", requestHash, s.Now(), trace); e != nil {
			return e
		}
		if out.Policy.Decision == policy.Allow {
			var nonce [32]byte
			if _, e = rand.Read(nonce[:]); e != nil {
				return e
			}
			expiry := s.Now() + 60
			if expiry > m.Terms.ExpiresAt {
				expiry = m.Terms.ExpiresAt
			}
			if approval != "" {
				c, e := tx.Challenge(approval)
				if e != nil {
					return e
				}
				if expiry > c.ExpiresAt {
					expiry = c.ExpiresAt
				}
			}
			g := Grant{Claims: Claims{RiskApprovalID: approval, ID: trust.ID(), MandateID: m.Terms.ID, AgentID: agent, MerchantID: o.Merchant, Hash: requestHash, Amount: t.Amount, Currency: t.Currency, IssuedAt: s.Now(), ExpiresAt: expiry, Nonce: hex.EncodeToString(nonce[:]), MaxUses: 1}, State: domain.GrantIssued, Transaction: t}
			b, e := json.Marshal(g.Claims)
			if e != nil {
				return e
			}
			g.Signature, e = s.Crypto.Sign(ctx, cryptography.GrantV1, b)
			if e != nil {
				return e
			}
			if e = tx.InsertGrant(g); e != nil {
				return e
			}
			if approval != "" {
				if e = tx.BindChallenge(approval, g.Claims.ID); e != nil {
					return e
				}
			}
			m.Reserved++
			out.Grant = &g
			if e = tx.Emit(agent, "authorization.issued", g.Claims.ID, s.Now()); e != nil {
				return e
			}
		} else {
			if out.Policy.Decision == policy.AskUser {
				out.ChallengeID = trust.ID()
				if e = tx.NewChallenge(Challenge{ID: out.ChallengeID, AgentID: agent, MandateID: m.Terms.ID, Hash: requestHash, ExpiresAt: s.Now() + 300}); e != nil {
					return e
				}
			}
			if e = tx.Emit(agent, "authorization.denied", m.Terms.ID, s.Now()); e != nil {
				return e
			}
		}
		if e = tx.SaveMandate(m); e != nil {
			return e
		}
		encoded, e := json.Marshal(out)
		if e != nil {
			return e
		}
		return tx.Cache(agent, key, requestHash, encoded, s.Now())
	})
	return out, e
}

// Consume performs enforcement only: the provider is invoked later by a durable worker.
func (s Service) Consume(ctx context.Context, agent string, g Grant, t domain.TransactionV1) (string, error) {
	var payment string
	var denial error
	e := s.Store.Authorization(ctx, func(tx Tx) error {
		a, e := tx.Agent(agent)
		if e != nil {
			return e
		}
		m, e := tx.Mandate(g.Claims.MandateID)
		if e != nil {
			return e
		}
		stored, e := tx.Grant(g.Claims.ID)
		if e != nil {
			return e
		}
		deny := func(reason error) error {
			denial = reason
			return tx.Emit(agent, "authorization.denied", g.Claims.ID, s.Now())
		}
		if e = s.Trust.Verify(ctx, a, m); e != nil {
			return deny(e)
		}
		b, e := json.Marshal(g.Claims)
		if e != nil {
			return e
		}
		sb, _ := json.Marshal(stored.Claims)
		if sha256.Sum256(b) != sha256.Sum256(sb) || s.Crypto.Verify(ctx, cryptography.GrantV1, b, g.Signature) != nil {
			return deny(trust.ErrDenied)
		}
		if g.Claims.AgentID != agent || stored.State != domain.GrantIssued || g.Claims.MaxUses != 1 || s.Now() >= g.Claims.ExpiresAt || s.Now() < g.Claims.IssuedAt {
			return deny(ErrReplay)
		}
		h, e := t.Digest()
		if e != nil || h != g.Claims.Hash {
			return deny(ErrHash)
		}
		o, e := tx.Offer(t.OfferID)
		if e != nil {
			return e
		}
		approved := false
		if stored.Claims.RiskApprovalID != "" {
			c, e := tx.Challenge(stored.Claims.RiskApprovalID)
			if e != nil {
				return e
			}
			approved = c.AgentID == agent && c.MandateID == m.Terms.ID && c.Hash == h && c.GrantID == stored.Claims.ID && c.ApprovedAt > 0 && s.Now() < c.ExpiresAt
		}
		r := policy.Evaluate(policy.Input{Agent: a, Mandate: m, Transaction: t, Offer: o, Now: s.Now(), OwnerRiskApproved: approved, Available: m.Reserved > 0 && m.Consumed < m.Terms.MaxUses})
		if r.Decision != policy.Allow {
			return deny(trust.ErrDenied)
		}
		payment = trust.ID()
		if e = tx.Consume(stored, payment, s.Now()); e != nil {
			return e
		}
		return tx.Emit(agent, "grant.consumed", g.Claims.ID, s.Now())
	})
	if e != nil {
		return "", e
	}
	if denial != nil {
		return "", denial
	}
	return payment, nil
}

// ApproveRisk requires an authenticated owner confirming the exact transaction digest.
func (s Service) ApproveRisk(ctx context.Context, owner, agent, mandate, id, hash string) error {
	return s.Store.Authorization(ctx, func(tx Tx) error {
		a, e := tx.Agent(agent)
		if e != nil {
			return e
		}
		m, e := tx.Mandate(mandate)
		if e != nil {
			return e
		}
		c, e := tx.Challenge(id)
		if e != nil {
			return e
		}
		if a.Owner != owner || m.Terms.Owner != owner || m.Terms.AgentID != agent || c.AgentID != agent || c.MandateID != mandate || c.Hash != hash || c.GrantID != "" || s.Now() >= c.ExpiresAt || (!m.Terms.AllowRiskApproval && !m.Terms.AllowMerchantApproval) {
			return trust.ErrDenied
		}
		if e = s.Trust.Verify(ctx, a, m); e != nil {
			return e
		}
		if c.ApprovedAt > 0 {
			return nil
		}
		if e = tx.ApproveChallenge(id, s.Now()); e != nil {
			return e
		}
		return tx.Emit(owner, "challenge.approved", id, s.Now())
	})
}
