package postgres

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"github.com/tenzerka2/northvtb/internal/authorization"
	"github.com/tenzerka2/northvtb/internal/domain"
	"github.com/tenzerka2/northvtb/internal/payments"
	"github.com/tenzerka2/northvtb/internal/policy"
	"github.com/tenzerka2/northvtb/internal/trust"
	"time"
)

type PaymentStore struct {
	Store *Store
	Trust trust.Service
	Now   func() int64
}

// lockPayment establishes the canonical lock order using immutable references.
func (t *Tx) lockPayment(id string) (trust.Agent, trust.Mandate, authorization.Grant, domain.PaymentState, error) {
	var agent, mandate, grant string
	e := t.SQL.QueryRowContext(t.Ctx, `SELECT g.agent_id,g.mandate_id,g.id FROM north.payments p JOIN north.grants g ON g.id=p.grant_id WHERE p.id=$1`, id).Scan(&agent, &mandate, &grant)
	if e != nil {
		return trust.Agent{}, trust.Mandate{}, authorization.Grant{}, "", absent(e)
	}
	a, e := t.Agent(agent)
	if e != nil {
		return a, trust.Mandate{}, authorization.Grant{}, "", e
	}
	m, e := t.Mandate(mandate)
	if e != nil {
		return a, m, authorization.Grant{}, "", e
	}
	g, e := t.Grant(grant)
	if e != nil {
		return a, m, g, "", e
	}
	var state domain.PaymentState
	e = t.SQL.QueryRowContext(t.Ctx, `SELECT state FROM north.payments WHERE id=$1 FOR UPDATE`, id).Scan(&state)
	return a, m, g, state, e
}
func (p PaymentStore) Prepare(ctx context.Context, id string) (payments.Command, error) {
	var out payments.Command
	e := p.Store.Atomic(ctx, func(tx *Tx) error {
		a, m, g, state, e := tx.lockPayment(id)
		if e != nil {
			return e
		}
		out = payments.Command{Request: payments.Request{ID: id, Hash: g.Claims.Hash, Merchant: g.Claims.MerchantID, Currency: g.Claims.Currency, Amount: g.Claims.Amount}, State: state}
		if state != domain.Pending {
			return nil
		}
		if p.Trust.Verify(ctx, a, m) != nil || p.Now() >= g.Claims.ExpiresAt {
			out.State = domain.Cancelled
			return p.settleLocked(tx, id, m, domain.Cancelled)
		}
		// Recheck authoritative offer at submission, not only during grant consumption.
		o, e := tx.Offer(g.Transaction.OfferID)
		if e != nil {
			return e
		}
		approved := false
		if g.Claims.RiskApprovalID != "" {
			c, e := tx.Challenge(g.Claims.RiskApprovalID)
			if e != nil {
				return e
			}
			approved = c.AgentID == a.ID && c.MandateID == m.Terms.ID && c.Hash == g.Claims.Hash && c.GrantID == g.Claims.ID && c.ApprovedAt > 0 && p.Now() < c.ExpiresAt
		}
		decision := policy.Evaluate(policy.Input{Agent: a, Mandate: m, Transaction: g.Transaction, Offer: o, Now: p.Now(), OwnerRiskApproved: approved, Available: m.Reserved > 0 && m.Consumed < m.Terms.MaxUses})
		if decision.Decision != policy.Allow {
			out.State = domain.Cancelled
			return p.settleLocked(tx, id, m, domain.Cancelled)
		}
		_, e = tx.SQL.ExecContext(ctx, `UPDATE north.payments SET state='SUBMITTED',updated_at=$2 WHERE id=$1`, id, time.Unix(p.Now(), 0))
		if e != nil {
			return e
		}
		out.State = domain.Submitted
		return tx.Emit(a.ID, "payment.started", id, p.Now())
	})
	return out, e
}
func (p PaymentStore) settleLocked(tx *Tx, id string, m trust.Mandate, next domain.PaymentState) error {
	if next == domain.Succeeded || next == domain.Failed || next == domain.Cancelled {
		if m.Reserved < 1 {
			return trust.ErrConflict
		}
		m.Reserved--
		if next == domain.Succeeded {
			m.Consumed++
			if m.Consumed == m.Terms.MaxUses && m.State == domain.Active {
				m.State = domain.Consumed
			}
		}
		if e := tx.SaveMandate(m); e != nil {
			return e
		}
	}
	if _, e := tx.SQL.ExecContext(tx.Ctx, `UPDATE north.payments SET state=$2,updated_at=$3 WHERE id=$1`, id, next, time.Unix(p.Now(), 0)); e != nil {
		return e
	}
	kind := "payment.unknown"
	switch next {
	case domain.Succeeded:
		kind = "payment.succeeded"
	case domain.Failed:
		kind = "payment.failed"
	case domain.Cancelled:
		kind = "payment.cancelled"
	}
	return tx.Emit("payment-worker", kind, id, p.Now())
}
func (p PaymentStore) Settle(ctx context.Context, id string, next domain.PaymentState) error {
	return p.Store.Atomic(ctx, func(tx *Tx) error {
		_, m, _, state, e := tx.lockPayment(id)
		if e != nil {
			return e
		}
		if state == domain.Succeeded || state == domain.Failed || state == domain.Cancelled {
			return nil
		}
		if state == next {
			return nil
		}
		if e = state.Transition(next); e != nil {
			return e
		}
		return p.settleLocked(tx, id, m, next)
	})
}
func (p PaymentStore) BeginRefund(ctx context.Context, owner, id string) (string, error) {
	var refund string
	e := p.Store.Atomic(ctx, func(tx *Tx) error {
		a, m, _, state, e := tx.lockPayment(id)
		if e != nil {
			return e
		}
		if a.Owner != owner || m.Terms.Owner != owner || state != domain.Succeeded {
			return trust.ErrDenied
		}
		e = tx.SQL.QueryRowContext(ctx, `SELECT id FROM north.refunds WHERE payment_id=$1`, id).Scan(&refund)
		if e == nil {
			return nil
		}
		if e != sql.ErrNoRows {
			return e
		}
		refund = trust.ID()
		_, e = tx.SQL.ExecContext(ctx, `INSERT INTO north.refunds VALUES($1,$2,'PENDING',$3,$3)`, refund, id, time.Unix(p.Now(), 0))
		if e != nil {
			return e
		}
		return tx.Emit(owner, "refund.started", refund, p.Now())
	})
	return refund, e
}
func (p PaymentStore) EndRefund(ctx context.Context, id string, success bool) error {
	return p.Store.Atomic(ctx, func(tx *Tx) error {
		var payment string
		if e := tx.SQL.QueryRowContext(ctx, `SELECT payment_id FROM north.refunds WHERE id=$1`, id).Scan(&payment); e != nil {
			return e
		}
		if _, _, _, _, e := tx.lockPayment(payment); e != nil {
			return e
		}
		var state string
		if e := tx.SQL.QueryRowContext(ctx, `SELECT state FROM north.refunds WHERE id=$1 FOR UPDATE`, id).Scan(&state); e != nil {
			return e
		}
		if state == "SUCCEEDED" {
			return nil
		}
		next := "UNKNOWN"
		kind := "refund.unknown"
		if success {
			next = "SUCCEEDED"
			kind = "payment.refunded"
		}
		if _, e := tx.SQL.ExecContext(ctx, `UPDATE north.refunds SET state=$2,updated_at=$3 WHERE id=$1`, id, next, time.Unix(p.Now(), 0)); e != nil {
			return e
		}
		return tx.Emit("payment-worker", kind, id, p.Now())
	})
}

// Callback settles exactly once; authentication is verified before database access.
func (p PaymentStore) Callback(ctx context.Context, secret []byte, c payments.Callback, mac string) error {
	if e := payments.VerifyCallback(secret, c, mac); e != nil {
		return e
	}
	return p.Store.Atomic(ctx, func(tx *Tx) error {
		_, m, g, state, e := tx.lockPayment(c.PaymentID)
		if e != nil {
			return e
		}
		if c.Amount != g.Claims.Amount || c.Currency != g.Claims.Currency {
			return trust.ErrDenied
		}
		raw, e := c.Bytes()
		if e != nil {
			return e
		}
		hash := sha256.Sum256(raw)
		var previous []byte
		e = tx.SQL.QueryRowContext(ctx, `SELECT payload_hash FROM north.provider_callbacks WHERE provider_id=$1 AND event_id=$2`, c.Provider, c.EventID).Scan(&previous)
		if e == nil {
			if !bytes.Equal(previous, hash[:]) {
				return trust.ErrConflict
			}
			return nil
		}
		if e != sql.ErrNoRows {
			return e
		}
		if state != c.Status {
			if e = state.Transition(c.Status); e != nil {
				return trust.ErrConflict
			}
		}
		if _, e = tx.SQL.ExecContext(ctx, `INSERT INTO north.provider_callbacks VALUES($1,$2,$3,$4,$5)`, c.Provider, c.EventID, c.PaymentID, hash[:], time.Unix(p.Now(), 0)); e != nil {
			return e
		}
		if state == c.Status {
			return nil
		}
		return p.settleLocked(tx, c.PaymentID, m, c.Status)
	})
}
