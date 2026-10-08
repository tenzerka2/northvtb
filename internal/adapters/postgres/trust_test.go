package postgres

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"testing"
	"time"

	"github.com/tenzerka2/northvtb/internal/cryptography"
	"github.com/tenzerka2/northvtb/internal/trust"
)

func setup(t *testing.T) (*Store, trust.Service, *int64) {
	t.Helper()
	dsn := os.Getenv("NORTH_TEST_DSN")
	if dsn == "" {
		t.Skip("PostgreSQL integration requires NORTH_TEST_DSN")
	}
	ctx := context.Background()
	db, e := Open(ctx, dsn)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { db.DB.Close() })
	_, key, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	c, e := cryptography.NewEd25519("test-key", key)
	if e != nil {
		t.Fatal(e)
	}
	now := time.Now().Unix()
	return db, trust.Service{Store: db, Crypto: c, Now: func() int64 { return now }}, &now
}
func makeMandate(t *testing.T, s trust.Service) (trust.Agent, trust.Mandate) {
	t.Helper()
	ctx := context.Background()
	a, e := s.Register(ctx, "issuer|owner", trust.Agent{Provider: "sandbox", CredentialRef: "vault:" + trust.ID(), Risk: 0})
	if e != nil {
		t.Fatal(e)
	}
	m, e := s.Draft(ctx, a.Owner, trust.Terms{AgentID: a.ID, Action: "purchase", Purpose: "console", Product: "PS5-Pro", Category: "gaming", Condition: "new", MaxAmount: 8500000, Currency: "RUB", RequireVerified: true, MaxUses: 1, MaxRisk: 20, ExpiresAt: s.Now() + 3600})
	if e != nil {
		t.Fatal(e)
	}
	return a, m
}
func approve(t *testing.T, s trust.Service, a trust.Agent, m trust.Mandate) trust.Mandate {
	t.Helper()
	d, e := m.Terms.Digest()
	if e != nil {
		t.Fatal(e)
	}
	m, e = s.Approve(context.Background(), a.Owner, a.ID, m.Terms.ID, d)
	if e != nil {
		t.Fatal(e)
	}
	return m
}
func TestTrustLifecyclePostgres(t *testing.T) {
	db, s, now := setup(t)
	ctx := context.Background()
	a, m := makeMandate(t, s)
	if s.Check(ctx, a.ID, m.Terms.ID) == nil {
		t.Fatal("draft usable")
	}
	if _, e := s.Approve(ctx, a.Owner, a.ID, m.Terms.ID, "wrong-digest"); e == nil {
		t.Fatal("wrong approval digest accepted")
	}
	d, _ := m.Terms.Digest()
	if _, e := s.Approve(ctx, "attacker", a.ID, m.Terms.ID, d); e == nil {
		t.Fatal("attacker approved")
	}
	m = approve(t, s, a, m)
	if e := s.Check(ctx, a.ID, m.Terms.ID); e != nil {
		t.Fatal(e)
	}
	if e := s.Revoke(ctx, "attacker", a.ID, m.Terms.ID); e == nil {
		t.Fatal("attacker revoked")
	}
	*now = m.Terms.ExpiresAt
	if s.Check(ctx, a.ID, m.Terms.ID) == nil {
		t.Fatal("expired mandate accepted")
	}
	*now = m.Terms.CreatedAt + 1
	next, e := s.Replace(ctx, a.Owner, a.ID, m.Terms.ID, m.Terms)
	if e != nil {
		t.Fatal(e)
	}
	if next.Terms.Version != 2 || next.Terms.PredecessorID != m.Terms.ID {
		t.Fatal("bad version")
	}
	if s.Check(ctx, a.ID, m.Terms.ID) == nil {
		t.Fatal("replaced mandate usable")
	}
	next = approve(t, s, a, next)
	if e = s.RevokeAgent(ctx, a.Owner, a.ID); e != nil {
		t.Fatal(e)
	}
	if s.Check(ctx, a.ID, next.Terms.ID) == nil {
		t.Fatal("revoked agent usable")
	}
	if e = db.VerifyAudit(ctx, 0, nil); e != nil {
		t.Fatal(e)
	}
	if e = db.VerifyAudit(ctx, 999999, make([]byte, 32)); e == nil {
		t.Fatal("missing external checkpoint accepted")
	}
	// Audit failure must roll back the business mutation, not just the log.
	before := 0
	if e = db.DB.QueryRowContext(ctx, `SELECT count(*) FROM north.agents`).Scan(&before); e != nil {
		t.Fatal(e)
	}
	e = db.Within(ctx, func(tx trust.Tx) error {
		bad := a
		bad.ID = trust.ID()
		bad.CredentialRef = "vault:" + trust.ID()
		bad.Status = "ACTIVE"
		bad.RevokedAt = 0
		if e := tx.InsertAgent(bad); e != nil {
			return e
		}
		return tx.Emit("", "bad", "subject", s.Now())
	})
	if e == nil {
		t.Fatal("invalid audit accepted")
	}
	after := 0
	db.DB.QueryRowContext(ctx, `SELECT count(*) FROM north.agents`).Scan(&after)
	if before != after {
		t.Fatal("audit failure did not roll back agent")
	}
}
func TestRevokedMandatePostgres(t *testing.T) {
	_, s, _ := setup(t)
	a, m := makeMandate(t, s)
	m = approve(t, s, a, m)
	if e := s.Revoke(context.Background(), a.Owner, a.ID, m.Terms.ID); e != nil {
		t.Fatal(e)
	}
	if s.Check(context.Background(), a.ID, m.Terms.ID) == nil {
		t.Fatal("revoked mandate usable")
	}
}

func TestPrivilegedTamperingDetected(t *testing.T) {
	db, s, _ := setup(t)
	dsn := os.Getenv("NORTH_TEST_ADMIN_DSN")
	if dsn == "" {
		t.Skip("requires explicit test-only admin DSN")
	}
	ctx := context.Background()
	admin, e := Open(ctx, dsn)
	if e != nil {
		t.Fatal(e)
	}
	defer admin.DB.Close()
	a, m := makeMandate(t, s)
	m = approve(t, s, a, m)
	mutateSignature := func(b []byte) {
		t.Helper()
		e := admin.Atomic(ctx, func(tx *Tx) error {
			if _, e := tx.SQL.ExecContext(ctx, `ALTER TABLE north.mandates DISABLE TRIGGER immutable_mandate`); e != nil {
				return e
			}
			if _, e := tx.SQL.ExecContext(ctx, `UPDATE north.mandates SET signature=$1 WHERE id=$2`, b, m.Terms.ID); e != nil {
				return e
			}
			_, e := tx.SQL.ExecContext(ctx, `ALTER TABLE north.mandates ENABLE TRIGGER immutable_mandate`)
			return e
		})
		if e != nil {
			t.Fatal(e)
		}
	}
	mutateSignature([]byte{1})
	if s.Check(ctx, a.ID, m.Terms.ID) == nil {
		t.Fatal("forged signature accepted")
	}
	mutateSignature(m.Signature.Value)
	var seq int64
	var hash, raw []byte
	if e = db.DB.QueryRowContext(ctx, `SELECT sequence,hash,canonical_event FROM north.audit_events ORDER BY sequence DESC LIMIT 1`).Scan(&seq, &hash, &raw); e != nil {
		t.Fatal(e)
	}
	mutateAudit := func(b []byte) {
		t.Helper()
		e := admin.Atomic(ctx, func(tx *Tx) error {
			if _, e := tx.SQL.ExecContext(ctx, `ALTER TABLE north.audit_events DISABLE TRIGGER append_only_audit`); e != nil {
				return e
			}
			if _, e := tx.SQL.ExecContext(ctx, `UPDATE north.audit_events SET canonical_event=$1 WHERE sequence=$2`, b, seq); e != nil {
				return e
			}
			_, e := tx.SQL.ExecContext(ctx, `ALTER TABLE north.audit_events ENABLE TRIGGER append_only_audit`)
			return e
		})
		if e != nil {
			t.Fatal(e)
		}
	}
	mutateAudit([]byte("tampered"))
	if db.VerifyAudit(ctx, seq, hash) == nil {
		t.Fatal("tampered history accepted")
	}
	mutateAudit(raw)
	if e = db.VerifyAudit(ctx, seq, hash); e != nil {
		t.Fatal(e)
	}
}
