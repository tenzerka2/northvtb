package policy

import (
	"github.com/tenzerka2/northvtb/internal/domain"
	"github.com/tenzerka2/northvtb/internal/trust"
	"testing"
)

func input() Input {
	m := trust.Mandate{Terms: trust.Terms{ID: "m", AgentID: "a", Owner: "owner", Action: "purchase", Purpose: "console", Product: "PS5-Pro", Category: "gaming", Condition: "new", MaxAmount: 8500000, Currency: "RUB", MaxUses: 1, ExpiresAt: 200, RequireVerified: true, MaxRisk: 20}, State: domain.Active}
	tx := domain.TransactionV1{SchemaVersion: 1, MandateID: "m", AgentID: "a", MerchantID: "seller", OfferID: "offer", OfferRevision: 1, Action: "purchase", Purpose: "console", Product: "PS5-Pro", Category: "gaming", Condition: "new", Quantity: 1, UnitAmount: 8299000, Amount: 8299000, Currency: "RUB"}
	o := Offer{ID: "offer", Merchant: "seller", Product: "PS5-Pro", Category: "gaming", Condition: "new", Currency: "RUB", Revision: 1, Quantity: 1, UnitAmount: 8299000, Amount: 8299000, Verified: true, Risk: 0, Active: true}
	return Input{Agent: trust.Agent{ID: "a", Owner: "owner", Status: "ACTIVE"}, Mandate: m, Transaction: tx, Offer: o, Now: 100, Available: true}
}
func TestPolicy(t *testing.T) {
	for _, c := range []struct {
		name   string
		change func(*Input)
		want   Decision
	}{
		{"valid", func(i *Input) {}, Allow}, {"expensive", func(i *Input) {
			i.Transaction.Amount = 9690000
			i.Transaction.UnitAmount = 9690000
			i.Offer.Amount = 9690000
			i.Offer.UnitAmount = 9690000
		}, Deny},
		{"unverified-hard", func(i *Input) { i.Offer.Verified = false; i.OwnerRiskApproved = true }, Deny},
		{"risk-challenge", func(i *Input) { i.Mandate.Terms.AllowRiskApproval = true; i.Offer.Risk = 50 }, AskUser},
		{"consent", func(i *Input) {
			i.Mandate.Terms.AllowRiskApproval = true
			i.Offer.Risk = 50
			i.OwnerRiskApproved = true
		}, Allow},
		{"spoofed-merchant", func(i *Input) { i.Transaction.MerchantID = "attacker" }, Deny},
		{"forged-product", func(i *Input) { i.Offer.Product = "wrong" }, Deny}, {"expired", func(i *Input) { i.Now = 200 }, Deny},
		{"capacity", func(i *Input) { i.Available = false }, Deny}, {"revoked", func(i *Input) { i.Mandate.State = domain.Revoked }, Deny},
		{"wrong-agent", func(i *Input) { i.Agent.ID = "attacker" }, Deny},
	} {
		t.Run(c.name, func(t *testing.T) {
			i := input()
			c.change(&i)
			r := Evaluate(i)
			if r.Decision != c.want || len(r.Rules) < 15 {
				t.Fatalf("%+v", r)
			}
		})
	}
}

func TestMerchantConsentCannotBypassHardRules(t *testing.T) {
	for _, c := range []struct {
		name   string
		change func(*Input)
		want   Decision
	}{
		{"default-deny", func(i *Input) {}, Deny},
		{"explicit-opt-in", func(i *Input) { i.Mandate.Terms.AllowMerchantApproval = true }, AskUser},
		{"exact-consent", func(i *Input) { i.Mandate.Terms.AllowMerchantApproval = true; i.OwnerRiskApproved = true }, Allow},
		{"consent-cannot-enable-opt-in", func(i *Input) { i.OwnerRiskApproved = true }, Deny},
		{"consent-cannot-raise-budget", func(i *Input) {
			i.Mandate.Terms.AllowMerchantApproval = true
			i.OwnerRiskApproved = true
			i.Mandate.Terms.MaxAmount = 1
		}, Deny},
		{"consent-cannot-verify-seller", func(i *Input) {
			i.Mandate.Terms.AllowMerchantApproval = true
			i.OwnerRiskApproved = true
			i.Offer.Verified = false
		}, Deny},
		{"consent-cannot-revive-revocation", func(i *Input) {
			i.Mandate.Terms.AllowMerchantApproval = true
			i.OwnerRiskApproved = true
			i.Agent.Status = "REVOKED"
		}, Deny},
	} {
		t.Run(c.name, func(t *testing.T) {
			i := input()
			i.Mandate.Terms.Merchants = []string{"different-seller"}
			c.change(&i)
			if got := Evaluate(i).Decision; got != c.want {
				t.Fatalf("got %s, want %s", got, c.want)
			}
		})
	}
}
