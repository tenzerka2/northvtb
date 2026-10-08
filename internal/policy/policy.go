// Package policy makes deterministic decisions from authoritative inputs only.
package policy

import (
	"github.com/tenzerka2/northvtb/internal/domain"
	"github.com/tenzerka2/northvtb/internal/trust"
)

type Decision string

const (
	Allow   Decision = "ALLOW"
	Deny    Decision = "DENY"
	AskUser Decision = "ASK_USER"
)

type Rule struct {
	Code    string   `json:"code"`
	Passed  bool     `json:"passed"`
	Failure Decision `json:"failure"`
}
type Result struct {
	Decision Decision `json:"decision"`
	Rules    []Rule   `json:"rules"`
}
type Offer struct {
	ID         string        `json:"id"`
	Merchant   string        `json:"merchant_id"`
	Product    string        `json:"product"`
	Category   string        `json:"category"`
	Condition  string        `json:"condition"`
	Currency   string        `json:"currency"`
	Revision   int64         `json:"revision"`
	Quantity   int64         `json:"quantity"`
	UnitAmount domain.Amount `json:"unit_amount"`
	Fees       domain.Amount `json:"fees"`
	Shipping   domain.Amount `json:"shipping"`
	Amount     domain.Amount `json:"amount"`
	Verified   bool          `json:"verified"`
	Risk       int           `json:"risk"`
	Active     bool          `json:"active"`
}
type Input struct {
	Agent             trust.Agent
	Mandate           trust.Mandate
	Transaction       domain.TransactionV1
	Offer             Offer
	Now               int64
	Available         bool
	OwnerRiskApproved bool
}

func Evaluate(i Input) Result {
	r := Result{Decision: Allow, Rules: []Rule{}}
	m := i.Mandate
	t := i.Transaction
	o := i.Offer
	add := func(code string, ok bool, failure Decision) {
		r.Rules = append(r.Rules, Rule{code, ok, failure})
		if !ok {
			if failure == Deny {
				r.Decision = Deny
			} else if r.Decision != Deny {
				r.Decision = AskUser
			}
		}
	}
	add("AGENT_MATCH", i.Agent.ID == m.Terms.AgentID && t.AgentID == i.Agent.ID, Deny)
	add("AGENT_ACTIVE", i.Agent.Status == "ACTIVE", Deny)
	add("OWNER_MATCH", i.Agent.Owner == m.Terms.Owner, Deny)
	add("MANDATE_MATCH", t.MandateID == m.Terms.ID, Deny)
	add("MANDATE_ACTIVE", m.State == domain.Active, Deny)
	add("MANDATE_NOT_EXPIRED", i.Now < m.Terms.ExpiresAt, Deny)
	add("TRANSACTION_VALID", t.Validate() == nil, Deny)
	add("ACTION_MATCH", t.Action == m.Terms.Action, Deny)
	add("PURPOSE_MATCH", t.Purpose == m.Terms.Purpose, Deny)
	add("PRODUCT_MATCH", t.Product == m.Terms.Product, Deny)
	add("CATEGORY_MATCH", t.Category == m.Terms.Category, Deny)
	add("CONDITION_MATCH", t.Condition == m.Terms.Condition, Deny)
	add("AMOUNT_LIMIT_EXCEEDED", t.Amount <= m.Terms.MaxAmount, Deny)
	add("CURRENCY_MATCH", t.Currency == m.Terms.Currency, Deny)
	allowed := len(m.Terms.Merchants) == 0
	for _, id := range m.Terms.Merchants {
		if id == t.MerchantID {
			allowed = true
		}
	}
	add("MERCHANT_ALLOWED", allowed, Deny)
	add("OFFER_AUTHENTIC", o.Active && t.OfferID == o.ID && t.OfferRevision == o.Revision && t.MerchantID == o.Merchant && t.Product == o.Product && t.Category == o.Category && t.Condition == o.Condition && t.Currency == o.Currency && t.Quantity == o.Quantity && t.UnitAmount == o.UnitAmount && t.Fees == o.Fees && t.Shipping == o.Shipping && t.Amount == o.Amount, Deny)
	add("MERCHANT_TRUST_SUFFICIENT", !m.Terms.RequireVerified || o.Verified, Deny)
	riskOK := o.Risk >= 0 && o.Risk <= m.Terms.MaxRisk && i.Agent.Risk <= m.Terms.MaxRisk
	if m.Terms.AllowRiskApproval {
		add("RISK_ACCEPTABLE", riskOK || i.OwnerRiskApproved, AskUser)
	} else {
		add("RISK_ACCEPTABLE", riskOK, Deny)
	}
	add("USAGE_AVAILABLE", i.Available, Deny)
	return r
}
