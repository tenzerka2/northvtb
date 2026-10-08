package postgres

import (
	"context"
	"github.com/tenzerka2/northvtb/internal/domain"
	"github.com/tenzerka2/northvtb/internal/trust"
	"time"
)

// Sweep releases unused grants and materializes effective expiry/revocation.
// Consumed grants keep their reservations until payment reconciliation finishes.
func (s *Store) Sweep(ctx context.Context, now int64) error {
	rows, e := s.DB.QueryContext(ctx, `SELECT m.id,m.agent_id FROM north.mandates m JOIN north.agents a ON a.id=m.agent_id WHERE (m.state='ACTIVE' AND (m.expires_at <= $1 OR a.status='REVOKED')) OR EXISTS(SELECT FROM north.grants g WHERE g.mandate_id=m.id AND g.state='ISSUED' AND (g.expires_at <= $1 OR m.state IN ('REVOKED','EXPIRED') OR a.status='REVOKED')) ORDER BY m.expires_at,m.id LIMIT 64`, time.Unix(now, 0))
	if e != nil {
		return e
	}
	type item struct{ id, agent string }
	items := []item{}
	for rows.Next() {
		var i item
		if e = rows.Scan(&i.id, &i.agent); e != nil {
			rows.Close()
			return e
		}
		items = append(items, i)
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return e
	}
	for _, i := range items {
		if e = s.Atomic(ctx, func(tx *Tx) error {
			a, e := tx.Agent(i.agent)
			if e != nil {
				return e
			}
			m, e := tx.Mandate(i.id)
			if e != nil {
				return e
			}
			old := m.State
			if m.State == domain.Active {
				if a.Status == "REVOKED" {
					m.State = domain.Revoked
				} else if now >= m.Terms.ExpiresAt {
					m.State = domain.Expired
				}
			}
			var n int64
			if m.State == domain.Revoked || m.State == domain.Expired {
				r, e := tx.SQL.ExecContext(ctx, `UPDATE north.grants SET state=$2 WHERE mandate_id=$1 AND state='ISSUED'`, i.id, string(m.State))
				if e != nil {
					return e
				}
				n, e = r.RowsAffected()
				if e != nil {
					return e
				}
			} else {
				n, e = tx.ExpireGrants(i.id, now)
				if e != nil {
					return e
				}
			}
			if n == 0 && old == m.State {
				return nil
			}
			m.Reserved -= n
			if m.Reserved < 0 {
				return trust.ErrConflict
			}
			if e = tx.SaveMandate(m); e != nil {
				return e
			}
			return tx.Emit("expiry-worker", "authority.expired-or-revoked", i.id, now)
		}); e != nil {
			return e
		}
	}
	return nil
}
