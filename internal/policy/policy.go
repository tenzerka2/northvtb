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
	Reason  string   `json:"reason_code,omitempty"`
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
		reason := ""
		if !ok {
			reasons := map[string]string{"AGENT_MATCH": "AGENT_MISMATCH", "AGENT_ACTIVE": "AGENT_REVOKED", "OWNER_MATCH": "OWNER_MISMATCH", "MANDATE_MATCH": "MANDATE_MISMATCH", "MANDATE_ACTIVE": "MANDATE_INACTIVE", "MANDATE_NOT_EXPIRED": "MANDATE_EXPIRED", "TRANSACTION_VALID": "INVALID_TRANSACTION", "ACTION_MATCH": "ACTION_MISMATCH", "PURPOSE_MATCH": "PURPOSE_MISMATCH", "PRODUCT_MATCH": "PRODUCT_MISMATCH", "CATEGORY_MATCH": "CATEGORY_MISMATCH", "CONDITION_MATCH": "CONDITION_MISMATCH", "AMOUNT_WITHIN_LIMIT": "AMOUNT_LIMIT_EXCEEDED", "CURRENCY_MATCH": "CURRENCY_MISMATCH", "MERCHANT_ALLOWED": "MERCHANT_NOT_ALLOWED", "OFFER_AUTHENTIC": "OFFER_MISMATCH", "MERCHANT_TRUST_SUFFICIENT": "MERCHANT_NOT_VERIFIED", "RISK_ACCEPTABLE": "RISK_LIMIT_EXCEEDED", "USAGE_AVAILABLE": "USAGE_LIMIT_EXHAUSTED"}
			reason = reasons[code]
			if code == "RISK_ACCEPTABLE" && failure == AskUser {
				reason = "RISK_REQUIRES_APPROVAL"
			}
		}
		r.Rules = append(r.Rules, Rule{Code: code, Passed: ok, Failure: failure, Reason: reason})
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
	add("AMOUNT_WITHIN_LIMIT", t.Amount <= m.Terms.MaxAmount, Deny)
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
