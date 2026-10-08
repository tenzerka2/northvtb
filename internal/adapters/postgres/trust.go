package postgres

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/tenzerka2/northvtb/internal/audit"
	"github.com/tenzerka2/northvtb/internal/trust"
)

type Store struct{ DB *sql.DB }
type Tx struct {
	SQL *sql.Tx
	Ctx context.Context
}

func Open(ctx context.Context, dsn string) (*Store, error) {
	db, e := sql.Open("pgx", dsn)
	if e != nil {
		return nil, e
	}
	db.SetMaxOpenConns(16)
	db.SetMaxIdleConns(4)
	if e = db.PingContext(ctx); e != nil {
		db.Close()
		return nil, e
	}
	return &Store{db}, nil
}
func (s *Store) Within(ctx context.Context, f func(trust.Tx) error) error {
	return s.Atomic(ctx, func(t *Tx) error { return f(t) })
}
func (s *Store) Atomic(ctx context.Context, f func(*Tx) error) error {
	tx, e := s.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if e != nil {
		return e
	}
	defer tx.Rollback()
	if e = f(&Tx{tx, ctx}); e != nil {
		return e
	}
	return tx.Commit()
}
func absent(e error) error {
	if errors.Is(e, sql.ErrNoRows) {
		return trust.ErrNotFound
	}
	return e
}
func (t *Tx) Agent(id string) (trust.Agent, error) {
	var a trust.Agent
	var created time.Time
	var revoked sql.NullTime
	e := t.SQL.QueryRowContext(t.Ctx, `SELECT id,owner_subject,provider_id,credential_ref,version,status,risk_class,created_at,revoked_at FROM north.agents WHERE id=$1 FOR UPDATE`, id).Scan(&a.ID, &a.Owner, &a.Provider, &a.CredentialRef, &a.Version, &a.Status, &a.Risk, &created, &revoked)
	a.CreatedAt = created.Unix()
	if revoked.Valid {
		a.RevokedAt = revoked.Time.Unix()
	}
	return a, absent(e)
}
func (t *Tx) InsertAgent(a trust.Agent) error {
	_, e := t.SQL.ExecContext(t.Ctx, `INSERT INTO north.agents VALUES ($1,$2,$3,$4,$5,$6,$7,$8,NULL)`, a.ID, a.Owner, a.Provider, a.CredentialRef, a.Version, a.Status, a.Risk, time.Unix(a.CreatedAt, 0))
	return e
}
func (t *Tx) RevokeAgent(id string, at int64) error {
	_, e := t.SQL.ExecContext(t.Ctx, `UPDATE north.agents SET status='REVOKED',revoked_at=$2 WHERE id=$1`, id, time.Unix(at, 0))
	return e
}
func (t *Tx) Mandate(id string) (trust.Mandate, error) {
	var m trust.Mandate
	var raw, digest []byte
	var key sql.NullString
	var approved sql.NullTime
	var owner, agent, currency string
	var amount, uses, version int64
	var created, expires time.Time
	var predecessor sql.NullString
	e := t.SQL.QueryRowContext(t.Ctx, `SELECT canonical_terms,terms_digest,state,key_id,signature,approved_at,reserved_uses,consumed_uses,owner_subject,agent_id,max_amount,currency,max_uses,version,created_at,expires_at,predecessor_id FROM north.mandates WHERE id=$1 FOR UPDATE`, id).Scan(&raw, &digest, &m.State, &key, &m.Signature.Value, &approved, &m.Reserved, &m.Consumed, &owner, &agent, &amount, &currency, &uses, &version, &created, &expires, &predecessor)
	if e != nil {
		return m, absent(e)
	}
	if e = json.Unmarshal(raw, &m.Terms); e != nil {
		return m, trust.ErrDenied
	}
	canonical, e := m.Terms.Canonical()
	if e != nil || !bytes.Equal(raw, canonical) {
		return m, trust.ErrDenied
	}
	h, e := m.Terms.Digest()
	if e != nil || h != hex.EncodeToString(digest) {
		return m, trust.ErrDenied
	}
	if m.Terms.ID != id || m.Terms.Owner != owner || m.Terms.AgentID != agent || int64(m.Terms.MaxAmount) != amount || m.Terms.Currency != currency || m.Terms.MaxUses != uses || m.Terms.Version != version || m.Terms.CreatedAt != created.Unix() || m.Terms.ExpiresAt != expires.Unix() || m.Terms.PredecessorID != predecessor.String {
		return m, trust.ErrDenied
	}
	m.Signature.KeyID = key.String
	if approved.Valid {
		m.ApprovedAt = approved.Time.Unix()
	}
	return m, nil
}
func (t *Tx) InsertMandate(m trust.Mandate) error {
	b, e := m.Terms.Canonical()
	if e != nil {
		return e
	}
	h, e := m.Terms.Digest()
	if e != nil {
		return e
	}
	digest, _ := hex.DecodeString(h)
	var predecessor any
	if m.Terms.PredecessorID != "" {
		predecessor = m.Terms.PredecessorID
	}
	_, e = t.SQL.ExecContext(t.Ctx, `INSERT INTO north.mandates(id,owner_subject,agent_id,version,predecessor_id,state,canonical_terms,terms_digest,max_amount,currency,max_uses,created_at,expires_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)`, m.Terms.ID, m.Terms.Owner, m.Terms.AgentID, m.Terms.Version, predecessor, m.State, b, digest, m.Terms.MaxAmount, m.Terms.Currency, m.Terms.MaxUses, time.Unix(m.Terms.CreatedAt, 0), time.Unix(m.Terms.ExpiresAt, 0))
	return e
}
func (t *Tx) SaveMandate(m trust.Mandate) error {
	var key, signature, at any
	if m.Signature.KeyID != "" {
		key = m.Signature.KeyID
		signature = m.Signature.Value
	}
	if m.ApprovedAt > 0 {
		at = time.Unix(m.ApprovedAt, 0)
	}
	_, e := t.SQL.ExecContext(t.Ctx, `UPDATE north.mandates SET state=$2,key_id=$3,signature=$4,approved_at=$5,reserved_uses=$6,consumed_uses=$7 WHERE id=$1`, m.Terms.ID, m.State, key, signature, at, m.Reserved, m.Consumed)
	return e
}
func (t *Tx) Emit(actor, kind, subject string, at int64) error {
	var seq int64
	var previous []byte
	if e := t.SQL.QueryRowContext(t.Ctx, `SELECT sequence,hash FROM north.audit_head WHERE singleton FOR UPDATE`).Scan(&seq, &previous); e != nil {
		return e
	}
	event := audit.Event{Version: 1, Sequence: seq + 1, ID: trust.ID(), At: at, Actor: actor, Kind: kind, Subject: subject, Previous: hex.EncodeToString(previous)}
	raw, e := event.Bytes()
	if e != nil {
		return e
	}
	hash := audit.Hash(raw)
	if _, e = t.SQL.ExecContext(t.Ctx, `INSERT INTO north.audit_events VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)`, event.Sequence, event.ID, time.Unix(at, 0), actor, kind, subject, raw, previous, hash); e != nil {
		return e
	}
	if _, e = t.SQL.ExecContext(t.Ctx, `UPDATE north.audit_head SET sequence=$1,hash=$2 WHERE singleton`, event.Sequence, hash); e != nil {
		return e
	}
	_, e = t.SQL.ExecContext(t.Ctx, `INSERT INTO north.outbox(event_id,created_at,available_at) VALUES($1,$2,$2)`, event.ID, time.Unix(at, 0))
	return e
}

// VerifyAudit checks chain and an optional externally retained checkpoint in one snapshot.
// Without an external checkpoint a privileged full-history rewrite remains undetectable.
func (s *Store) VerifyAudit(ctx context.Context, checkpointSeq int64, checkpointHash []byte) error {
	tx, e := s.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead, ReadOnly: true})
	if e != nil {
		return e
	}
	defer tx.Rollback()
	var head int64
	var headHash []byte
	if e = tx.QueryRowContext(ctx, `SELECT sequence,hash FROM north.audit_head WHERE singleton`).Scan(&head, &headHash); e != nil {
		return e
	}
	rows, e := tx.QueryContext(ctx, `SELECT sequence,event_id,occurred_at,actor,event_type,subject,canonical_event,previous_hash,hash FROM north.audit_events ORDER BY sequence`)
	if e != nil {
		return e
	}
	defer rows.Close()
	var seq int64
	previous := make([]byte, 32)
	found := checkpointSeq == 0 && len(checkpointHash) == 0
	for rows.Next() {
		var n int64
		var id, actor, kind, subject string
		var at time.Time
		var raw, prev, hash []byte
		if e = rows.Scan(&n, &id, &at, &actor, &kind, &subject, &raw, &prev, &hash); e != nil {
			return e
		}
		expected, e := (audit.Event{1, n, id, at.Unix(), actor, kind, subject, hex.EncodeToString(prev)}).Bytes()
		if e != nil || n != seq+1 || !bytes.Equal(previous, prev) || !bytes.Equal(raw, expected) || !bytes.Equal(hash, audit.Hash(raw)) {
			return trust.ErrDenied
		}
		seq = n
		previous = hash
		if seq == checkpointSeq {
			found = bytes.Equal(hash, checkpointHash)
		}
	}
	if e = rows.Err(); e != nil {
		return e
	}
	if seq != head || !bytes.Equal(previous, headHash) || !found {
		return trust.ErrDenied
	}
	return tx.Commit()
}
