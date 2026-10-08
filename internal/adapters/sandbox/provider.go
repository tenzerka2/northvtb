// Package sandbox implements a persistent simulated provider, not a real payment rail.
package sandbox

import (
	"context"
	"database/sql"
	"errors"
	"github.com/tenzerka2/northvtb/internal/payments"
)

type Provider struct {
	DB                  *sql.DB
	TimeoutAfterCapture bool
}

func (p Provider) Authorize(ctx context.Context, r payments.Request) (payments.ProviderStatus, error) {
	if r.ID == "" || r.Hash == "" || r.Amount <= 0 {
		return "", errors.New("invalid provider request")
	}
	_, e := p.DB.ExecContext(ctx, `INSERT INTO sandbox.payments(id,request_hash,merchant,currency,amount,state) VALUES($1,$2,$3,$4,$5,'AUTHORIZED') ON CONFLICT(id) DO NOTHING`, r.ID, r.Hash, r.Merchant, r.Currency, r.Amount)
	if e != nil {
		return "", e
	}
	var hash, merchant, currency string
	var amount int64
	var status payments.ProviderStatus
	e = p.DB.QueryRowContext(ctx, `SELECT request_hash,merchant,currency,amount,state FROM sandbox.payments WHERE id=$1`, r.ID).Scan(&hash, &merchant, &currency, &amount, &status)
	if e != nil {
		return "", e
	}
	if hash != r.Hash || merchant != r.Merchant || currency != r.Currency || amount != int64(r.Amount) {
		return "", errors.New("provider idempotency conflict")
	}
	return status, nil
}
func (p Provider) Capture(ctx context.Context, id string) (payments.ProviderStatus, error) {
	_, e := p.DB.ExecContext(ctx, `UPDATE sandbox.payments SET state='CAPTURED',captures=captures+1 WHERE id=$1 AND state='AUTHORIZED'`, id)
	if e != nil {
		return "", e
	}
	if p.TimeoutAfterCapture {
		return "", errors.New("injected sandbox timeout after commit")
	}
	return p.GetStatus(ctx, id)
}
func (p Provider) GetStatus(ctx context.Context, id string) (payments.ProviderStatus, error) {
	var status payments.ProviderStatus
	e := p.DB.QueryRowContext(ctx, `SELECT state FROM sandbox.payments WHERE id=$1`, id).Scan(&status)
	if errors.Is(e, sql.ErrNoRows) {
		return payments.NotFound, nil
	}
	return status, e
}
func (p Provider) Refund(ctx context.Context, id, payment string) (payments.ProviderStatus, error) {
	tx, e := p.DB.BeginTx(ctx, nil)
	if e != nil {
		return "", e
	}
	defer tx.Rollback()
	var state payments.ProviderStatus
	if e = tx.QueryRowContext(ctx, `SELECT state FROM sandbox.payments WHERE id=$1 FOR UPDATE`, payment).Scan(&state); e != nil {
		return "", e
	}
	if state != payments.Captured && state != payments.Refunded {
		return "", errors.New("payment not captured")
	}
	_, e = tx.ExecContext(ctx, `INSERT INTO sandbox.refunds VALUES($1,$2) ON CONFLICT(id) DO NOTHING`, id, payment)
	if e != nil {
		return "", e
	}
	var bound string
	if e = tx.QueryRowContext(ctx, `SELECT payment_id FROM sandbox.refunds WHERE id=$1`, id).Scan(&bound); e != nil {
		return "", e
	}
	if bound != payment {
		return "", errors.New("refund idempotency conflict")
	}
	if _, e = tx.ExecContext(ctx, `UPDATE sandbox.payments SET state='REFUNDED' WHERE id=$1`, payment); e != nil {
		return "", e
	}
	return payments.Refunded, tx.Commit()
}
