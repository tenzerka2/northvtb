package postgres

import (
	"context"
	"github.com/tenzerka2/northvtb/internal/domain"
	"testing"
)

func TestExpirySweep(t *testing.T) {
	for _, revoked := range []bool{false, true} {
		db, s, a, m, tx, now := authSetup(t)
		ctx := context.Background()
		r, e := s.Issue(ctx, a.ID, "sweep", tx)
		if e != nil {
			t.Fatal(e)
		}
		want := domain.Expired
		if revoked {
			if e = s.Trust.RevokeAgent(ctx, a.Owner, a.ID); e != nil {
				t.Fatal(e)
			}
			want = domain.Revoked
		} else {
			*now = m.Terms.ExpiresAt
		}
		if e = db.Sweep(ctx, *now); e != nil {
			t.Fatal(e)
		}
		var state domain.MandateState
		var reserved int64
		if e = db.DB.QueryRow(`SELECT state,reserved_uses FROM north.mandates WHERE id=$1`, m.Terms.ID).Scan(&state, &reserved); e != nil || state != want || reserved != 0 {
			t.Fatal(state, reserved, e)
		}
		if _, e = s.Consume(ctx, a.ID, *r.Grant, tx); e == nil {
			t.Fatal("swept authority consumed")
		}
		if e = db.VerifyAudit(ctx, 0, nil); e != nil {
			t.Fatal(e)
		}
	}
}
