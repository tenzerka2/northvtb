package postgres

import (
	"context"
	"fmt"
	"os"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/tenzerka2/northvtb/internal/authorization"
	"github.com/tenzerka2/northvtb/internal/domain"
	"github.com/tenzerka2/northvtb/internal/policy"
	"github.com/tenzerka2/northvtb/internal/trust"
)

func authSetup(t *testing.T) (*Store, authorization.Service, trust.Agent, trust.Mandate, domain.TransactionV1, *int64) {
	t.Helper()
	db, s, now := setup(t)
	a, m := makeMandate(t, s)
	m = approve(t, s, a, m)
	admin, e := Open(context.Background(), os.Getenv("NORTH_TEST_ADMIN_DSN"))
	if e != nil {
		t.Fatal(e)
	}
	defer admin.DB.Close()
	id := trust.ID()
	_, e = admin.DB.Exec(`INSERT INTO north.offers VALUES($1,'verified-shop','PS5-Pro','gaming','new','RUB',1,1,8299000,0,0,8299000,true,0,true)`, id)
	if e != nil {
		t.Fatal(e)
	}
	tx := domain.TransactionV1{SchemaVersion: 1, MandateID: m.Terms.ID, AgentID: a.ID, MerchantID: "verified-shop", OfferID: id, OfferRevision: 1, Action: "purchase", Purpose: "console", Product: "PS5-Pro", Category: "gaming", Condition: "new", Quantity: 1, UnitAmount: 8299000, Amount: 8299000, Currency: "RUB"}
	return db, authorization.Service{Store: db, Trust: s, Crypto: s.Crypto, Now: s.Now}, a, m, tx, now
}
func TestConcurrentAuthorizationAndConsume(t *testing.T) {
	db, s, a, m, tx, _ := authSetup(t)
	ctx := context.Background()
	var wg sync.WaitGroup
	grants := make(chan authorization.Grant, 32)
	errs := make(chan error, 32)
	for n := 0; n < 32; n++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			r, e := s.Issue(ctx, a.ID, fmt.Sprintf("request-%d", n), tx)
			if e != nil {
				errs <- e
				return
			}
			if r.Policy.Decision == policy.Allow {
				grants <- *r.Grant
			}
		}(n)
	}
	wg.Wait()
	close(grants)
	close(errs)
	for e := range errs {
		t.Fatal(e)
	}
	if len(grants) != 1 {
		t.Fatalf("issued %d grants for one slot", len(grants))
	}
	g := <-grants
	changes := []func(*domain.TransactionV1){func(x *domain.TransactionV1) { x.Amount = 9299000; x.UnitAmount = 9299000 }, func(x *domain.TransactionV1) { x.MerchantID = "attacker" }, func(x *domain.TransactionV1) { x.Product = "different" }, func(x *domain.TransactionV1) { x.Fees = 1; x.Amount++ }}
	for _, change := range changes {
		v := tx
		change(&v)
		if _, e := s.Consume(ctx, a.ID, g, v); e != authorization.ErrHash {
			t.Fatalf("mutation not blocked by digest: %v", e)
		}
	}
	fake := g
	fake.Signature.KeyID = "stolen"
	if _, e := s.Consume(ctx, a.ID, fake, tx); e == nil {
		t.Fatal("invalid signature accepted")
	}
	var successes atomic.Int32
	for n := 0; n < 32; n++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, e := s.Consume(ctx, a.ID, g, tx); e == nil {
				successes.Add(1)
			}
		}()
	}
	wg.Wait()
	if successes.Load() != 1 {
		t.Fatalf("consumed %d times", successes.Load())
	}
	var count int
	if e := db.DB.QueryRow(`SELECT count(*) FROM north.payments p JOIN north.grants g ON g.id=p.grant_id WHERE g.mandate_id=$1`, m.Terms.ID).Scan(&count); e != nil || count != 1 {
		t.Fatal(count, e)
	}
	if e := db.VerifyAudit(ctx, 0, nil); e != nil {
		t.Fatal(e)
	}
}
func TestIdempotencyAndExpiry(t *testing.T) {
	_, s, a, _, tx, now := authSetup(t)
	ctx := context.Background()
	r, e := s.Issue(ctx, a.ID, "same", tx)
	if e != nil || r.Grant == nil {
		t.Fatal(r, e)
	}
	again, e := s.Issue(ctx, a.ID, "same", tx)
	if e != nil || again.Grant.Claims.ID != r.Grant.Claims.ID {
		t.Fatal("idempotency failed", e)
	}
	different := tx
	different.Amount++
	different.UnitAmount++
	if _, e = s.Issue(ctx, a.ID, "same", different); e != trust.ErrConflict {
		t.Fatal("key substitution allowed", e)
	}
	*now = r.Grant.Claims.ExpiresAt
	if _, e = s.Consume(ctx, a.ID, *r.Grant, tx); e != authorization.ErrReplay {
		t.Fatal("expired grant accepted", e)
	}
	replacement, e := s.Issue(ctx, a.ID, "after-expiry", tx)
	if e != nil || replacement.Grant == nil {
		t.Fatal("expired reservation not released", replacement, e)
	}
	if _, e = s.Consume(ctx, a.ID, *r.Grant, tx); e == nil {
		t.Fatal("expired grant resurrected")
	}
}
func TestRevocationBetweenIssueAndConsume(t *testing.T) {
	for _, agent := range []bool{false, true} {
		t.Run(fmt.Sprint(agent), func(t *testing.T) {
			db, s, a, m, tx, _ := authSetup(t)
			ctx := context.Background()
			r, e := s.Issue(ctx, a.ID, "initial", tx)
			if e != nil || r.Grant == nil {
				t.Fatal(e)
			}
			if agent {
				e = s.Trust.RevokeAgent(ctx, a.Owner, a.ID)
			} else {
				e = s.Trust.Revoke(ctx, a.Owner, a.ID, m.Terms.ID)
			}
			if e != nil {
				t.Fatal(e)
			}
			if _, e = s.Consume(ctx, a.ID, *r.Grant, tx); e == nil {
				t.Fatal("revoked authority consumed")
			}
			var n int
			db.DB.QueryRow(`SELECT count(*) FROM north.payments WHERE grant_id=$1`, r.Grant.Claims.ID).Scan(&n)
			if n != 0 {
				t.Fatal("revoked authority created payment")
			}
		})
	}
}
