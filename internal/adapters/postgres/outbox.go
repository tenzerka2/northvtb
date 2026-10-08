package postgres

import (
	"bytes"
	"context"
	"github.com/tenzerka2/northvtb/internal/trust"
)

// DeliverOutbox relays to the MVP's durable local inbox. External transports must
// preserve the same event-ID dedupe contract and at-least-once delivery semantics.
func (s *Store) DeliverOutbox(ctx context.Context, limit int) (int, error) {
	if limit < 1 || limit > 256 {
		return 0, trust.ErrDenied
	}
	count := 0
	e := s.Atomic(ctx, func(tx *Tx) error {
		rows, e := tx.SQL.QueryContext(ctx, `SELECT o.event_id,a.canonical_event,a.hash FROM north.outbox o JOIN north.audit_events a USING(event_id) WHERE o.delivered_at IS NULL AND o.available_at<=clock_timestamp() ORDER BY a.sequence LIMIT $1 FOR UPDATE OF o SKIP LOCKED`, limit)
		if e != nil {
			return e
		}
		type event struct {
			id         string
			body, hash []byte
		}
		events := []event{}
		for rows.Next() {
			var v event
			if e = rows.Scan(&v.id, &v.body, &v.hash); e != nil {
				rows.Close()
				return e
			}
			events = append(events, v)
		}
		e = rows.Err()
		rows.Close()
		if e != nil {
			return e
		}
		for _, v := range events {
			if _, e = tx.SQL.ExecContext(ctx, `INSERT INTO north.event_inbox VALUES($1,$2,$3,clock_timestamp()) ON CONFLICT(event_id) DO NOTHING`, v.id, v.body, v.hash); e != nil {
				return e
			}
			var existing []byte
			if e = tx.SQL.QueryRowContext(ctx, `SELECT payload_hash FROM north.event_inbox WHERE event_id=$1`, v.id).Scan(&existing); e != nil {
				return e
			}
			if !bytes.Equal(existing, v.hash) {
				return trust.ErrDenied
			}
			if _, e = tx.SQL.ExecContext(ctx, `UPDATE north.outbox SET delivered_at=clock_timestamp(),attempts=attempts+1 WHERE event_id=$1`, v.id); e != nil {
				return e
			}
			count++
		}
		return nil
	})
	return count, e
}
