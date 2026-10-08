package payments

import (
	"context"
	"errors"
	"github.com/tenzerka2/northvtb/internal/domain"
)

type ProviderStatus string

const (
	NotFound   ProviderStatus = "NOT_FOUND"
	Authorized ProviderStatus = "AUTHORIZED"
	Captured   ProviderStatus = "CAPTURED"
	Declined   ProviderStatus = "DECLINED"
	Refunded   ProviderStatus = "REFUNDED"
)

type Request struct {
	ID, Hash, Merchant, Currency string
	Amount                       domain.Amount
}
type Provider interface {
	Authorize(context.Context, Request) (ProviderStatus, error)
	Capture(context.Context, string) (ProviderStatus, error)
	Refund(context.Context, string, string) (ProviderStatus, error)
	GetStatus(context.Context, string) (ProviderStatus, error)
}
type Command struct {
	Request Request
	State   domain.PaymentState
}

// Prepare revalidates current authority and commits SUBMITTED before remote I/O.
// Settle atomically updates payment, mandate usage and audit. Unknown retains usage.
type Store interface {
	Prepare(context.Context, string) (Command, error)
	Settle(context.Context, string, domain.PaymentState) error
	BeginRefund(context.Context, string, string) (string, error)
	EndRefund(context.Context, string, bool) error
}
type Service struct {
	Store    Store
	Provider Provider
}

func (s Service) Execute(ctx context.Context, id string) (domain.PaymentState, error) {
	c, e := s.Store.Prepare(ctx, id)
	if e != nil {
		return "", e
	}
	switch c.State {
	case domain.Succeeded, domain.Failed, domain.Cancelled:
		return c.State, nil
	}
	status, e := s.Provider.GetStatus(ctx, id)
	if e == nil && status == NotFound {
		status, e = s.Provider.Authorize(ctx, c.Request)
	}
	if e == nil && status == Authorized {
		status, e = s.Provider.Capture(ctx, id)
	}
	if e != nil {
		if x := s.Store.Settle(ctx, id, domain.Unknown); x != nil {
			return domain.Unknown, x
		}
		return domain.Unknown, e
	}
	next := domain.Unknown
	switch status {
	case Captured, Refunded:
		next = domain.Succeeded
	case Declined:
		next = domain.Failed
	}
	if e = s.Store.Settle(ctx, id, next); e != nil {
		return next, e
	}
	return next, nil
}

// Full refunds only in the MVP; stable local refund IDs survive retries/timeouts.
func (s Service) Refund(ctx context.Context, owner, payment string) error {
	id, e := s.Store.BeginRefund(ctx, owner, payment)
	if e != nil {
		return e
	}
	status, e := s.Provider.Refund(ctx, id, payment)
	if e != nil {
		_ = s.Store.EndRefund(ctx, id, false)
		return e
	}
	if status != Refunded {
		return errors.New("refund unresolved")
	}
	return s.Store.EndRefund(ctx, id, true)
}
