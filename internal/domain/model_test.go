package domain

import (
	"bytes"
	"math"
	"testing"
)

func tx() TransactionV1 {
	return TransactionV1{1, "mandate-1", "agent-1", "merchant-1", "offer-1", 1, "purchase", "console", "PS5-Pro", "gaming", "new", 1, 8299000, 0, 0, 8299000, "RUB"}
}
func TestTotalOverflow(t *testing.T) {
	for _, c := range []struct {
		a Amount
		q int64
	}{{0, 1}, {-1, 1}, {1, 0}, {1, -1}, {Amount(math.MaxInt64), 2}} {
		if _, err := Total(c.a, c.q); err == nil {
			t.Fatalf("accepted %+v", c)
		}
	}
	if n, err := Total(8299000, 1); err != nil || n != 8299000 {
		t.Fatal(n, err)
	}
}
func TestTransactionBinding(t *testing.T) {
	baseline := tx()
	hash, err := baseline.Digest()
	if err != nil {
		t.Fatal(err)
	}
	cases := []func(*TransactionV1){
		func(v *TransactionV1) { v.MandateID = "mandate-2" }, func(v *TransactionV1) { v.AgentID = "agent-2" },
		func(v *TransactionV1) { v.MerchantID = "merchant-2" }, func(v *TransactionV1) { v.OfferID = "offer-2" },
		func(v *TransactionV1) { v.OfferRevision++ }, func(v *TransactionV1) { v.Purpose = "different" },
		func(v *TransactionV1) { v.Product = "different" }, func(v *TransactionV1) { v.Category = "different" },
		func(v *TransactionV1) { v.Condition = "used" }, func(v *TransactionV1) { v.Quantity = 2; v.Amount *= 2 },
		func(v *TransactionV1) { v.UnitAmount = 9299000; v.Amount = 9299000 },
		func(v *TransactionV1) { v.Fees = 1; v.Amount++ }, func(v *TransactionV1) { v.Shipping = 1; v.Amount++ },
		func(v *TransactionV1) { v.Currency = "USD" },
	}
	for i, change := range cases {
		v := baseline
		change(&v)
		h, e := v.Digest()
		if e != nil || h == hash {
			t.Fatalf("unbound case %d: %v", i, e)
		}
	}
}
func TestCanonicalGolden(t *testing.T) {
	want := []byte(`{"schema_version":1,"mandate_id":"mandate-1","agent_id":"agent-1","merchant_id":"merchant-1","offer_id":"offer-1","offer_revision":1,"action":"purchase","purpose":"console","product":"PS5-Pro","category":"gaming","condition":"new","quantity":1,"unit_amount":8299000,"fees":0,"shipping":0,"amount":8299000,"currency":"RUB"}`)
	got, e := tx().Canonical()
	if e != nil || !bytes.Equal(got, want) {
		t.Fatalf("canonical version drift: %s %v", got, e)
	}
}
func TestInvalidTransaction(t *testing.T) {
	cases := []func(*TransactionV1){func(v *TransactionV1) { v.Amount++ }, func(v *TransactionV1) { v.Currency = "rub" }, func(v *TransactionV1) { v.Fees = -1 }, func(v *TransactionV1) { v.SchemaVersion = 2 }, func(v *TransactionV1) { v.Action = "refund" }, func(v *TransactionV1) { v.AgentID = "" }, func(v *TransactionV1) { v.Condition = "other" }, func(v *TransactionV1) { v.Product = string([]byte{255}) }, func(v *TransactionV1) { v.UnitAmount = Amount(math.MaxInt64); v.Fees = 1 }, func(v *TransactionV1) { v.UnitAmount = Amount(math.MaxInt64); v.Shipping = 1 }}
	for i, f := range cases {
		v := tx()
		f(&v)
		if _, err := v.Digest(); err == nil {
			t.Fatalf("accepted %d", i)
		}
	}
}
func TestAvailability(t *testing.T) {
	for _, c := range []struct {
		s                        MandateState
		now, exp, max, res, used int64
		want                     bool
	}{
		{Active, 9, 10, 1, 0, 0, true}, {Active, 10, 10, 1, 0, 0, false}, {Active, 11, 10, 1, 0, 0, false},
		{Revoked, 9, 10, 1, 0, 0, false}, {Expired, 9, 10, 1, 0, 0, false}, {Consumed, 9, 10, 1, 0, 0, false},
		{Draft, 9, 10, 1, 0, 0, false}, {Active, 9, 10, 1, 1, 0, false}, {Active, 9, 10, 1, 0, 1, false},
		{Active, 9, 10, 1, -1, 0, false}, {Active, 9, 10, math.MaxInt64, math.MaxInt64, 1, false},
	} {
		if got := Available(c.s, c.now, c.exp, c.max, c.res, c.used); got != c.want {
			t.Fatalf("%+v got %v", c, got)
		}
	}
}
func TestTerminalStatesCannotReactivate(t *testing.T) {
	for _, s := range []MandateState{Revoked, Expired, Consumed} {
		for _, n := range []MandateState{Draft, Active, Revoked, Expired, Consumed} {
			if s.Transition(n) == nil {
				t.Fatal(s, n)
			}
		}
	}
	for _, s := range []GrantState{GrantConsumed, GrantExpired, GrantRevoked} {
		if s.Transition(GrantIssued) == nil {
			t.Fatal(s)
		}
	}
	for _, s := range []PaymentState{Succeeded, Failed, Cancelled} {
		if s.Transition(Submitted) == nil {
			t.Fatal(s)
		}
	}
	if Submitted.Transition(Unknown) != nil || Unknown.Transition(Succeeded) != nil || Unknown.Transition(Pending) == nil {
		t.Fatal("ambiguous payment cannot be reset for retry")
	}
	if Draft.Transition(Active) != nil || Active.Transition(Consumed) != nil || GrantIssued.Transition(GrantConsumed) != nil {
		t.Fatal("valid transition rejected")
	}
}
