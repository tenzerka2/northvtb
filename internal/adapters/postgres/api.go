package postgres

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"github.com/tenzerka2/northvtb/internal/audit"
	"github.com/tenzerka2/northvtb/internal/authorization"
	"github.com/tenzerka2/northvtb/internal/identity"
	"github.com/tenzerka2/northvtb/internal/policy"
	"github.com/tenzerka2/northvtb/internal/trust"
	"time"
)

func (s *Store) FindCredential(ctx context.Context, credential string) (identity.Principal, error) {
	var p identity.Principal
	e := s.DB.QueryRowContext(ctx, `SELECT owner_subject,id FROM north.agents WHERE credential_ref=$1 AND status='ACTIVE'`, credential).Scan(&p.Owner, &p.AgentID)
	return p, absent(e)
}
func (s *Store) Offers(ctx context.Context, product string) ([]policy.Offer, error) {
	rows, e := s.DB.QueryContext(ctx, `SELECT id,merchant_id,product,category,condition,currency,revision,quantity,unit_amount,fees,shipping,amount,verified,risk,active FROM north.offers WHERE active AND product=$1 ORDER BY id`, product)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	out := []policy.Offer{}
	for rows.Next() {
		var o policy.Offer
		if e = rows.Scan(&o.ID, &o.Merchant, &o.Product, &o.Category, &o.Condition, &o.Currency, &o.Revision, &o.Quantity, &o.UnitAmount, &o.Fees, &o.Shipping, &o.Amount, &o.Verified, &o.Risk, &o.Active); e != nil {
			return nil, e
		}
		out = append(out, o)
	}
	return out, rows.Err()
}

type RequestTx interface {
	trust.Store
	StartRefund(string, string, int64) (string, error)
}

func (b boundStore) StartRefund(owner, id string, at int64) (string, error) {
	return b.t.StartRefund(owner, id, at)
}

type boundStore struct{ t *Tx }

func (b boundStore) Within(_ context.Context, f func(trust.Tx) error) error { return f(b.t) }
func (b boundStore) Authorization(_ context.Context, f func(authorization.Tx) error) error {
	return f(b.t)
}

// Request executes a successful HTTP mutation and stores its response in the same
// transaction. Advisory locking handles absent idempotency rows without races.
func (s *Store) Request(ctx context.Context, principal, operation, key string, body []byte, f func(RequestTx, authorization.Store) (any, error)) ([]byte, error) {
	if len(key) < 1 || len(key) > 128 {
		return nil, trust.ErrDenied
	}
	for _, c := range key {
		if c < '!' || c > '~' {
			return nil, trust.ErrDenied
		}
	}
	hash := sha256.Sum256(body)
	lock := sha256.Sum256([]byte(principal + "\x00" + operation + "\x00" + key))
	var response []byte
	e := s.Atomic(ctx, func(tx *Tx) error {
		if _, e := tx.SQL.ExecContext(ctx, `SELECT pg_advisory_xact_lock($1)`, int64(binary.BigEndian.Uint64(lock[:8]))); e != nil {
			return e
		}
		var stored []byte
		e := tx.SQL.QueryRowContext(ctx, `SELECT request_hash,response_body FROM north.idempotency WHERE principal=$1 AND operation=$2 AND key=$3`, principal, operation, key).Scan(&stored, &response)
		if e == nil {
			if hex.EncodeToString(stored) != hex.EncodeToString(hash[:]) {
				return trust.ErrConflict
			}
			return nil
		}
		if e != sql.ErrNoRows {
			return e
		}
		v, e := f(boundStore{tx}, boundStore{tx})
		if e != nil {
			return e
		}
		response, e = json.Marshal(v)
		if e != nil {
			return e
		}
		_, e = tx.SQL.ExecContext(ctx, `INSERT INTO north.idempotency VALUES($1,$2,$3,$4,200,$5,$6)`, principal, operation, key, hash[:], response, time.Now().UTC())
		return e
	})
	return response, e
}
func (s *Store) PaymentOwner(ctx context.Context, id string) (string, string, error) {
	var owner, agent string
	e := s.DB.QueryRowContext(ctx, `SELECT a.owner_subject,a.id FROM north.payments p JOIN north.grants g ON g.id=p.grant_id JOIN north.agents a ON a.id=g.agent_id WHERE p.id=$1`, id).Scan(&owner, &agent)
	return owner, agent, absent(e)
}
func (s *Store) SafeAppRole(ctx context.Context) error {
	var dangerous bool
	e := s.DB.QueryRowContext(ctx, `SELECT has_table_privilege(current_user,'north.audit_events','UPDATE') OR has_schema_privilege(current_user,'north','CREATE') OR has_table_privilege(current_user,'north.offers','UPDATE') OR (SELECT rolsuper FROM pg_roles WHERE rolname=current_user)`).Scan(&dangerous)
	if e != nil {
		return e
	}
	if dangerous {
		return trust.ErrDenied
	}
	return nil
}

func (s *Store) OwnerAudit(ctx context.Context, owner string) ([]audit.Event, error) {
	rows, e := s.DB.QueryContext(ctx, `SELECT canonical_event FROM north.audit_events e WHERE e.actor=$1 OR e.actor IN(SELECT id FROM north.agents WHERE owner_subject=$1) OR e.subject IN(SELECT id FROM north.mandates WHERE owner_subject=$1 UNION SELECT g.id FROM north.grants g JOIN north.mandates m ON m.id=g.mandate_id WHERE m.owner_subject=$1 UNION SELECT p.id FROM north.payments p JOIN north.grants g ON g.id=p.grant_id JOIN north.mandates m ON m.id=g.mandate_id WHERE m.owner_subject=$1 UNION SELECT r.id FROM north.refunds r JOIN north.payments p ON p.id=r.payment_id JOIN north.grants g ON g.id=p.grant_id JOIN north.mandates m ON m.id=g.mandate_id WHERE m.owner_subject=$1) ORDER BY sequence DESC LIMIT 200`, owner)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	out := []audit.Event{}
	for rows.Next() {
		var raw []byte
		if e = rows.Scan(&raw); e != nil {
			return nil, e
		}
		var event audit.Event
		if e = json.Unmarshal(raw, &event); e != nil {
			return nil, e
		}
		out = append(out, event)
	}
	return out, rows.Err()
}
