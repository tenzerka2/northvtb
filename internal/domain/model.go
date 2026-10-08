// Package domain contains persistence-independent financial value objects.
package domain

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math"
	"strings"
	"unicode/utf8"
)

var ErrInvalid = errors.New("invalid domain value")
var ErrTransition = errors.New("invalid state transition")

// Amount is minor units. Float values are never accepted.
type Amount int64

func (a Amount) Valid() bool { return a > 0 }

func Total(unit Amount, quantity int64) (Amount, error) {
	if !unit.Valid() || quantity <= 0 || int64(unit) > math.MaxInt64/quantity {
		return 0, ErrInvalid
	}
	return unit * Amount(quantity), nil
}

func identifier(s string) bool {
	if len(s) < 1 || len(s) > 128 {
		return false
	}
	for _, c := range s {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_' || c == '.') {
			return false
		}
	}
	return true
}

// TransactionV1 is the exact financial payload, including fees and shipping.
// Field order and JSON tags form a versioned serialization contract.
type TransactionV1 struct {
	SchemaVersion int    `json:"schema_version"`
	MandateID     string `json:"mandate_id"`
	AgentID       string `json:"agent_id"`
	MerchantID    string `json:"merchant_id"`
	OfferID       string `json:"offer_id"`
	OfferRevision int64  `json:"offer_revision"`
	Action        string `json:"action"`
	Purpose       string `json:"purpose"`
	Product       string `json:"product"`
	Category      string `json:"category"`
	Condition     string `json:"condition"`
	Quantity      int64  `json:"quantity"`
	UnitAmount    Amount `json:"unit_amount"`
	Fees          Amount `json:"fees"`
	Shipping      Amount `json:"shipping"`
	Amount        Amount `json:"amount"`
	Currency      string `json:"currency"`
}

func (t TransactionV1) Validate() error {
	if t.SchemaVersion != 1 || !identifier(t.MandateID) || !identifier(t.AgentID) || !identifier(t.MerchantID) || !identifier(t.OfferID) || t.OfferRevision <= 0 || t.Action != "purchase" {
		return ErrInvalid
	}
	for _, s := range []string{t.Purpose, t.Product, t.Category} {
		if !utf8.ValidString(s) || strings.TrimSpace(s) == "" || len(s) > 512 {
			return ErrInvalid
		}
	}
	if t.Condition != "new" && t.Condition != "used" {
		return ErrInvalid
	}
	if len(t.Currency) != 3 {
		return ErrInvalid
	}
	for _, c := range t.Currency {
		if c < 'A' || c > 'Z' {
			return ErrInvalid
		}
	}
	subtotal, err := Total(t.UnitAmount, t.Quantity)
	if err != nil || t.Fees < 0 || t.Shipping < 0 {
		return ErrInvalid
	}
	if t.Fees > Amount(math.MaxInt64)-subtotal {
		return ErrInvalid
	}
	subtotal += t.Fees
	if t.Shipping > Amount(math.MaxInt64)-subtotal {
		return ErrInvalid
	}
	if subtotal+t.Shipping != t.Amount {
		return ErrInvalid
	}
	return nil
}

func (t TransactionV1) Canonical() ([]byte, error) {
	if err := t.Validate(); err != nil {
		return nil, err
	}
	return json.Marshal(t)
}

func (t TransactionV1) Digest() (string, error) {
	b, err := t.Canonical()
	if err != nil {
		return "", err
	}
	h := sha256.Sum256(append([]byte("north:transaction:v1\x00"), b...))
	return hex.EncodeToString(h[:]), nil
}

type MandateState string

const (
	Draft    MandateState = "DRAFT"
	Active   MandateState = "ACTIVE"
	Revoked  MandateState = "REVOKED"
	Expired  MandateState = "EXPIRED"
	Consumed MandateState = "CONSUMED"
)

func (s MandateState) Transition(next MandateState) error {
	if s == Draft && (next == Active || next == Revoked) {
		return nil
	}
	if s == Active && (next == Revoked || next == Expired || next == Consumed) {
		return nil
	}
	return ErrTransition
}

// Available checks effective expiration even if the expiry worker has not run.
func Available(state MandateState, now, expires int64, max, reserved, consumed int64) bool {
	return state == Active && now < expires && max > 0 && reserved >= 0 && consumed >= 0 && consumed <= max && reserved < max-consumed
}

type GrantState string

const (
	GrantIssued   GrantState = "ISSUED"
	GrantConsumed GrantState = "CONSUMED"
	GrantExpired  GrantState = "EXPIRED"
	GrantRevoked  GrantState = "REVOKED"
)

func (s GrantState) Transition(next GrantState) error {
	if s == GrantIssued && (next == GrantConsumed || next == GrantExpired || next == GrantRevoked) {
		return nil
	}
	return ErrTransition
}

type PaymentState string

const (
	Pending   PaymentState = "PENDING"
	Submitted PaymentState = "SUBMITTED"
	Unknown   PaymentState = "UNKNOWN"
	Succeeded PaymentState = "SUCCEEDED"
	Failed    PaymentState = "FAILED"
	Cancelled PaymentState = "CANCELLED"
)

func (s PaymentState) Transition(next PaymentState) error {
	if s == Pending && (next == Submitted || next == Cancelled) {
		return nil
	}
	if s == Submitted && (next == Succeeded || next == Failed || next == Unknown) {
		return nil
	}
	if s == Unknown && (next == Succeeded || next == Failed) {
		return nil
	}
	return ErrTransition
}
