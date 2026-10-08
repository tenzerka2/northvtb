package merchants

import (
	"context"
	"github.com/tenzerka2/northvtb/internal/domain"
	"github.com/tenzerka2/northvtb/internal/policy"
	"github.com/tenzerka2/northvtb/internal/trust"
)

type Catalogue interface {
	Offers(context.Context, string) ([]policy.Offer, error)
}

// Proposals only discovers offers and builds proposals; it has no provider port.
func Proposals(ctx context.Context, c Catalogue, m trust.Mandate) ([]domain.TransactionV1, error) {
	offers, e := c.Offers(ctx, m.Terms.Product)
	if e != nil {
		return nil, e
	}
	out := make([]domain.TransactionV1, 0, len(offers))
	for _, o := range offers {
		out = append(out, domain.TransactionV1{SchemaVersion: 1, MandateID: m.Terms.ID, AgentID: m.Terms.AgentID, MerchantID: o.Merchant, OfferID: o.ID, OfferRevision: o.Revision, Action: m.Terms.Action, Purpose: m.Terms.Purpose, Product: o.Product, Category: o.Category, Condition: o.Condition, Quantity: o.Quantity, UnitAmount: o.UnitAmount, Fees: o.Fees, Shipping: o.Shipping, Amount: o.Amount, Currency: o.Currency})
	}
	return out, nil
}
