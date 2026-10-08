package postgres

import (
	"context"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"github.com/tenzerka2/northvtb/internal/authorization"
	"github.com/tenzerka2/northvtb/internal/policy"
	"github.com/tenzerka2/northvtb/internal/trust"
	"time"
)

func (s *Store) Authorization(ctx context.Context, f func(authorization.Tx) error) error {
	return s.Atomic(ctx, func(t *Tx) error { return f(t) })
}
func (t *Tx) Offer(id string) (policy.Offer, error) {
	var o policy.Offer
	e := t.SQL.QueryRowContext(t.Ctx, `SELECT id,merchant_id,product,category,condition,currency,revision,quantity,unit_amount,fees,shipping,amount,verified,risk,active FROM north.lock_offer($1)`, id).Scan(&o.ID, &o.Merchant, &o.Product, &o.Category, &o.Condition, &o.Currency, &o.Revision, &o.Quantity, &o.UnitAmount, &o.Fees, &o.Shipping, &o.Amount, &o.Verified, &o.Risk, &o.Active)
	return o, absent(e)
}
func (t *Tx) InsertGrant(g authorization.Grant) error {
	h, e := hex.DecodeString(g.Claims.Hash)
	if e != nil {
		return e
	}
	nonce, e := hex.DecodeString(g.Claims.Nonce)
	if e != nil {
		return e
	}
	b, e := g.Transaction.Canonical()
	if e != nil {
		return e
	}
	var approval any
	if g.Claims.RiskApprovalID != "" {
		approval = g.Claims.RiskApprovalID
	}
	_, e = t.SQL.ExecContext(t.Ctx, `INSERT INTO north.grants(id,mandate_id,agent_id,merchant_id,transaction_hash,canonical_transaction,amount,currency,nonce,max_uses,issued_at,expires_at,key_id,signature,state,risk_approval_id) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,1,$10,$11,$12,$13,'ISSUED',$14)`, g.Claims.ID, g.Claims.MandateID, g.Claims.AgentID, g.Claims.MerchantID, h, b, g.Claims.Amount, g.Claims.Currency, nonce, time.Unix(g.Claims.IssuedAt, 0), time.Unix(g.Claims.ExpiresAt, 0), g.Signature.KeyID, g.Signature.Value, approval)
	return e
}
func (t *Tx) Grant(id string) (authorization.Grant, error) {
	var g authorization.Grant
	var hash, nonce, raw []byte
	var issued, expires time.Time
	e := t.SQL.QueryRowContext(t.Ctx, `SELECT id,mandate_id,agent_id,merchant_id,transaction_hash,canonical_transaction,amount,currency,nonce,max_uses,issued_at,expires_at,key_id,signature,state,COALESCE(risk_approval_id,'') FROM north.grants WHERE id=$1 FOR UPDATE`, id).Scan(&g.Claims.ID, &g.Claims.MandateID, &g.Claims.AgentID, &g.Claims.MerchantID, &hash, &raw, &g.Claims.Amount, &g.Claims.Currency, &nonce, &g.Claims.MaxUses, &issued, &expires, &g.Signature.KeyID, &g.Signature.Value, &g.State, &g.Claims.RiskApprovalID)
	if e != nil {
		return g, absent(e)
	}
	g.Claims.Hash = hex.EncodeToString(hash)
	g.Claims.Nonce = hex.EncodeToString(nonce)
	g.Claims.IssuedAt = issued.Unix()
	g.Claims.ExpiresAt = expires.Unix()
	if e = json.Unmarshal(raw, &g.Transaction); e != nil {
		return g, trust.ErrDenied
	}
	h, e := g.Transaction.Digest()
	if e != nil || h != g.Claims.Hash {
		return g, trust.ErrDenied
	}
	return g, nil
}
func (t *Tx) ExpireGrants(id string, now int64) (int64, error) {
	r, e := t.SQL.ExecContext(t.Ctx, `UPDATE north.grants SET state='EXPIRED' WHERE mandate_id=$1 AND state='ISSUED' AND expires_at <= $2`, id, time.Unix(now, 0))
	if e != nil {
		return 0, e
	}
	return r.RowsAffected()
}
func (t *Tx) Consume(g authorization.Grant, payment string, at int64) error {
	r, e := t.SQL.ExecContext(t.Ctx, `UPDATE north.grants SET state='CONSUMED',consumed_at=$2 WHERE id=$1 AND state='ISSUED'`, g.Claims.ID, time.Unix(at, 0))
	if e != nil {
		return e
	}
	n, e := r.RowsAffected()
	if e != nil {
		return e
	}
	if n != 1 {
		return authorization.ErrReplay
	}
	_, e = t.SQL.ExecContext(t.Ctx, `INSERT INTO north.payments(id,grant_id,provider_id,state,amount,currency,created_at,updated_at) VALUES($1,$2,'sandbox','PENDING',$3,$4,$5,$5)`, payment, g.Claims.ID, g.Claims.Amount, g.Claims.Currency, time.Unix(at, 0))
	return e
}
func (t *Tx) Cached(principal, key string) (string, []byte, error) {
	var hash, b []byte
	e := t.SQL.QueryRowContext(t.Ctx, `SELECT request_hash,response_body FROM north.idempotency WHERE principal=$1 AND operation='authorize' AND key=$2`, principal, key).Scan(&hash, &b)
	return hex.EncodeToString(hash), b, absent(e)
}
func (t *Tx) Cache(principal, key, hash string, b []byte, at int64) error {
	h, e := hex.DecodeString(hash)
	if e != nil {
		return e
	}
	_, e = t.SQL.ExecContext(t.Ctx, `INSERT INTO north.idempotency VALUES($1,'authorize',$2,$3,200,$4,$5)`, principal, key, h, b, time.Unix(at, 0))
	return e
}

func (t *Tx) ApprovedChallenge(agent, mandate, hash string, now int64) (string, error) {
	h, e := hex.DecodeString(hash)
	if e != nil {
		return "", e
	}
	var id string
	e = t.SQL.QueryRowContext(t.Ctx, `SELECT id FROM north.challenges WHERE agent_id=$1 AND mandate_id=$2 AND transaction_hash=$3 AND approved_at IS NOT NULL AND grant_id IS NULL AND expires_at>$4 ORDER BY id LIMIT 1 FOR UPDATE`, agent, mandate, h, time.Unix(now, 0)).Scan(&id)
	if e == sql.ErrNoRows {
		return "", nil
	}
	return id, e
}
func (t *Tx) NewChallenge(c authorization.Challenge) error {
	h, e := hex.DecodeString(c.Hash)
	if e != nil {
		return e
	}
	_, e = t.SQL.ExecContext(t.Ctx, `INSERT INTO north.challenges(id,agent_id,mandate_id,transaction_hash,expires_at) VALUES($1,$2,$3,$4,$5)`, c.ID, c.AgentID, c.MandateID, h, time.Unix(c.ExpiresAt, 0))
	return e
}
func (t *Tx) Challenge(id string) (authorization.Challenge, error) {
	var c authorization.Challenge
	var h []byte
	var expiry time.Time
	var approval sql.NullTime
	var grant sql.NullString
	e := t.SQL.QueryRowContext(t.Ctx, `SELECT id,agent_id,mandate_id,transaction_hash,expires_at,approved_at,grant_id FROM north.challenges WHERE id=$1 FOR UPDATE`, id).Scan(&c.ID, &c.AgentID, &c.MandateID, &h, &expiry, &approval, &grant)
	c.Hash = hex.EncodeToString(h)
	c.ExpiresAt = expiry.Unix()
	c.GrantID = grant.String
	if approval.Valid {
		c.ApprovedAt = approval.Time.Unix()
	}
	return c, absent(e)
}
func (t *Tx) ApproveChallenge(id string, at int64) error {
	_, e := t.SQL.ExecContext(t.Ctx, `UPDATE north.challenges SET approved_at=$2 WHERE id=$1 AND approved_at IS NULL AND grant_id IS NULL`, id, time.Unix(at, 0))
	return e
}
func (t *Tx) BindChallenge(id, grant string) error {
	r, e := t.SQL.ExecContext(t.Ctx, `UPDATE north.challenges SET grant_id=$2 WHERE id=$1 AND grant_id IS NULL AND approved_at IS NOT NULL`, id, grant)
	if e != nil {
		return e
	}
	n, e := r.RowsAffected()
	if e != nil {
		return e
	}
	if n != 1 {
		return trust.ErrConflict
	}
	return nil
}
