package postgres

import (
	"bytes"
	"context"
	"github.com/tenzerka2/northvtb/internal/adapters/sandbox"
	"github.com/tenzerka2/northvtb/internal/domain"
	"github.com/tenzerka2/northvtb/internal/payments"
	"github.com/tenzerka2/northvtb/internal/policy"
	"github.com/tenzerka2/northvtb/internal/trust"
	"os"
	"sync"
	"testing"
)

func provider(t *testing.T, timeout bool) sandbox.Provider {
	t.Helper()
	db, e := Open(context.Background(), os.Getenv("NORTH_TEST_PROVIDER_DSN"))
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { db.DB.Close() })
	return sandbox.Provider{DB: db.DB, TimeoutAfterCapture: timeout}
}
func TestPaymentTimeoutRecoveryRefundAndCallbacks(t *testing.T) {
	db, auth, a, m, tx, _ := authSetup(t)
	ctx := context.Background()
	r, e := auth.Issue(ctx, a.ID, "purchase", tx)
	if e != nil || r.Grant == nil {
		t.Fatal(e)
	}
	id, e := auth.Consume(ctx, a.ID, *r.Grant, tx)
	if e != nil {
		t.Fatal(e)
	}
	store := PaymentStore{Store: db, Trust: auth.Trust, Now: auth.Now}
	p := provider(t, true)
	service := payments.Service{Store: store, Provider: p}
	state, e := service.Execute(ctx, id)
	if state != domain.Unknown || e == nil {
		t.Fatal("timeout must remain unknown", state, e)
	}
	var reserved, used int64
	db.DB.QueryRow(`SELECT reserved_uses,consumed_uses FROM north.mandates WHERE id=$1`, m.Terms.ID).Scan(&reserved, &used)
	if reserved != 1 || used != 0 {
		t.Fatal("unknown released capacity", reserved, used)
	}
	p.TimeoutAfterCapture = false
	service.Provider = p
	var wg sync.WaitGroup
	errs := make(chan error, 16)
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			state, e := service.Execute(ctx, id)
			if e != nil {
				errs <- e
			} else if state != domain.Succeeded {
				errs <- trust.ErrConflict
			}
		}()
	}
	wg.Wait()
	close(errs)
	for e := range errs {
		t.Fatal(e)
	}
	var captures int
	if e = p.DB.QueryRow(`SELECT captures FROM sandbox.payments WHERE id=$1`, id).Scan(&captures); e != nil || captures != 1 {
		t.Fatal("external double capture", captures, e)
	}
	db.DB.QueryRow(`SELECT reserved_uses,consumed_uses FROM north.mandates WHERE id=$1`, m.Terms.ID).Scan(&reserved, &used)
	if reserved != 0 || used != 1 {
		t.Fatal("wrong settled usage", reserved, used)
	}
	if _, e = auth.Issue(ctx, a.ID, "second-purchase", tx); e == nil {
		t.Fatal("consumed mandate authorized")
	}
	secret := bytes.Repeat([]byte{7}, 32)
	cb := payments.Callback{Provider: "sandbox", EventID: trust.ID(), PaymentID: id, Amount: tx.Amount, Currency: tx.Currency, Status: domain.Succeeded}
	mac, e := payments.SignCallback(secret, cb)
	if e != nil {
		t.Fatal(e)
	}
	if e = store.Callback(ctx, secret, cb, "invalid"); e == nil {
		t.Fatal("forged callback accepted")
	}
	for i := 0; i < 2; i++ {
		if e = store.Callback(ctx, secret, cb, mac); e != nil {
			t.Fatal(e)
		}
	}
	changed := cb
	changed.Amount++
	badmac, _ := payments.SignCallback(secret, changed)
	if e = store.Callback(ctx, secret, changed, badmac); e == nil {
		t.Fatal("wrong amount callback accepted")
	}
	if e = service.Refund(ctx, "attacker", id); e == nil {
		t.Fatal("attacker refunded")
	}
	for i := 0; i < 2; i++ {
		if e = service.Refund(ctx, a.Owner, id); e != nil {
			t.Fatal(e)
		}
	}
	db.DB.QueryRow(`SELECT consumed_uses FROM north.mandates WHERE id=$1`, m.Terms.ID).Scan(&used)
	if used != 1 {
		t.Fatal("refund restored authority")
	}
	if e = db.VerifyAudit(ctx, 0, nil); e != nil {
		t.Fatal(e)
	}
}
func TestRevocationBeforeDispatch(t *testing.T) {
	db, auth, a, m, tx, _ := authSetup(t)
	ctx := context.Background()
	r, e := auth.Issue(ctx, a.ID, "before-revoke", tx)
	if e != nil {
		t.Fatal(e)
	}
	id, e := auth.Consume(ctx, a.ID, *r.Grant, tx)
	if e != nil {
		t.Fatal(e)
	}
	if e = auth.Trust.Revoke(ctx, a.Owner, a.ID, m.Terms.ID); e != nil {
		t.Fatal(e)
	}
	p := provider(t, false)
	service := payments.Service{Store: PaymentStore{db, auth.Trust, auth.Now}, Provider: p}
	state, e := service.Execute(ctx, id)
	if e != nil || state != domain.Cancelled {
		t.Fatal(state, e)
	}
	status, e := p.GetStatus(ctx, id)
	if e != nil || status != payments.NotFound {
		t.Fatal("revoked command reached provider", status, e)
	}
}
func TestRiskChallengeContinuation(t *testing.T) {
	db, auth, a, m, tx, _ := authSetup(t)
	ctx := context.Background()
	terms := m.Terms
	terms.RequireVerified = false
	terms.AllowRiskApproval = true
	next, e := auth.Trust.Replace(ctx, a.Owner, a.ID, m.Terms.ID, terms)
	if e != nil {
		t.Fatal(e)
	}
	next = approve(t, auth.Trust, a, next)
	tx.MandateID = next.Terms.ID
	admin, e := Open(ctx, os.Getenv("NORTH_TEST_ADMIN_DSN"))
	if e != nil {
		t.Fatal(e)
	}
	defer admin.DB.Close()
	if _, e = admin.DB.Exec(`UPDATE north.offers SET risk=80,verified=false WHERE id=$1`, tx.OfferID); e != nil {
		t.Fatal(e)
	}
	r, e := auth.Issue(ctx, a.ID, "challenge", tx)
	if e != nil || r.Policy.Decision != policy.AskUser || r.ChallengeID == "" {
		t.Fatal(r, e)
	}
	hash, _ := tx.Digest()
	if e = auth.ApproveRisk(ctx, "attacker", a.ID, next.Terms.ID, r.ChallengeID, hash); e == nil {
		t.Fatal("agent approved risk")
	}
	if e = auth.ApproveRisk(ctx, a.Owner, a.ID, next.Terms.ID, r.ChallengeID, "wrong"); e == nil {
		t.Fatal("wrong digest approved")
	}
	if e = auth.ApproveRisk(ctx, a.Owner, a.ID, next.Terms.ID, r.ChallengeID, hash); e != nil {
		t.Fatal(e)
	}
	allowed, e := auth.Issue(ctx, a.ID, "after-owner-consent", tx)
	if e != nil || allowed.Grant == nil {
		t.Fatal(allowed, e)
	}
	id, e := auth.Consume(ctx, a.ID, *allowed.Grant, tx)
	if e != nil {
		t.Fatal(e)
	}
	service := payments.Service{Store: PaymentStore{db, auth.Trust, auth.Now}, Provider: provider(t, false)}
	if state, e := service.Execute(ctx, id); e != nil || state != domain.Succeeded {
		t.Fatal(state, e)
	}
	if e = auth.ApproveRisk(ctx, a.Owner, a.ID, next.Terms.ID, r.ChallengeID, hash); e == nil {
		t.Fatal("used challenge reused")
	}
}

func TestCallbackSettlesUnknownExactlyOnce(t *testing.T) {
	db, auth, a, m, tx, _ := authSetup(t)
	ctx := context.Background()
	r, e := auth.Issue(ctx, a.ID, "callback-source", tx)
	if e != nil {
		t.Fatal(e)
	}
	id, e := auth.Consume(ctx, a.ID, *r.Grant, tx)
	if e != nil {
		t.Fatal(e)
	}
	store := PaymentStore{Store: db, Trust: auth.Trust, Now: auth.Now}
	service := payments.Service{Store: store, Provider: provider(t, true)}
	if state, e := service.Execute(ctx, id); state != domain.Unknown || e == nil {
		t.Fatal(state, e)
	}
	secret := bytes.Repeat([]byte{9}, 32)
	cb := payments.Callback{Provider: "sandbox", EventID: trust.ID(), PaymentID: id, Amount: tx.Amount, Currency: tx.Currency, Status: domain.Succeeded}
	mac, _ := payments.SignCallback(secret, cb)
	for i := 0; i < 2; i++ {
		if e = store.Callback(ctx, secret, cb, mac); e != nil {
			t.Fatal(e)
		}
	}
	var reserved, used int64
	if e = db.DB.QueryRow(`SELECT reserved_uses,consumed_uses FROM north.mandates WHERE id=$1`, m.Terms.ID).Scan(&reserved, &used); e != nil || reserved != 0 || used != 1 {
		t.Fatal(reserved, used, e)
	}
	cb.EventID = trust.ID()
	cb.Status = domain.Failed
	mac, _ = payments.SignCallback(secret, cb)
	if e = store.Callback(ctx, secret, cb, mac); e == nil {
		t.Fatal("out-of-order callback regressed success")
	}
}
