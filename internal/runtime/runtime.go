// Package runtime is the composition root for the explicitly enabled sandbox.
package runtime

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"github.com/tenzerka2/northvtb/internal/adapters/postgres"
	"github.com/tenzerka2/northvtb/internal/adapters/sandbox"
	"github.com/tenzerka2/northvtb/internal/authorization"
	"github.com/tenzerka2/northvtb/internal/cryptography"
	"github.com/tenzerka2/northvtb/internal/identity"
	"github.com/tenzerka2/northvtb/internal/payments"
	"github.com/tenzerka2/northvtb/internal/platform/httpapi"
	"github.com/tenzerka2/northvtb/internal/trust"
	"log/slog"
	"os"
	"time"
)

type Runtime struct {
	API        httpapi.API
	ProviderDB *postgres.Store
	Log        *slog.Logger
}

func Open(ctx context.Context, log *slog.Logger) (*Runtime, error) {
	if os.Getenv("NORTH_MODE") != "sandbox" {
		return nil, errors.New("explicit sandbox mode required")
	}
	token := os.Getenv("NORTH_OWNER_TOKEN")
	owner := os.Getenv("NORTH_OWNER_SUBJECT")
	if len(token) < 32 || owner == "" {
		return nil, errors.New("owner configuration missing")
	}
	path := os.Getenv("NORTH_SIGNING_SEED_FILE")
	info, e := os.Stat(path)
	if e != nil || info.Mode().Perm()&0077 != 0 {
		return nil, errors.New("private signing seed must have mode 0600")
	}
	seed, e := os.ReadFile(path)
	if e != nil || len(seed) != 32 {
		return nil, errors.New("32-byte signing seed required")
	}
	crypto, e := cryptography.NewEd25519("sandbox-v1", ed25519.NewKeyFromSeed(seed))
	if e != nil {
		return nil, e
	}
	callback, e := hex.DecodeString(os.Getenv("NORTH_CALLBACK_KEY"))
	if e != nil || len(callback) < 32 {
		return nil, errors.New("callback key missing")
	}
	db, e := postgres.Open(ctx, os.Getenv("NORTH_DATABASE_URL"))
	if e != nil {
		return nil, errors.New("application database unavailable")
	}
	ok := false
	defer func() {
		if !ok {
			db.DB.Close()
		}
	}()
	if e = db.SafeAppRole(ctx); e != nil {
		return nil, errors.New("unsafe application database role")
	}
	provider, e := postgres.Open(ctx, os.Getenv("NORTH_PROVIDER_DATABASE_URL"))
	if e != nil {
		return nil, errors.New("provider database unavailable")
	}
	var crossAccess bool
	if e = provider.DB.QueryRowContext(ctx, `SELECT has_table_privilege(current_user,c.oid,'SELECT') FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='north' AND c.relname='grants'`).Scan(&crossAccess); e != nil || crossAccess {
		provider.DB.Close()
		return nil, errors.New("provider role must be isolated")
	}
	now := func() int64 { return time.Now().UTC().Unix() }
	ts := trust.Service{Store: db, Crypto: crypto, Now: now}
	as := authorization.Service{Store: db, Trust: ts, Crypto: crypto, Now: now}
	ps := postgres.PaymentStore{Store: db, Trust: ts, Now: now}
	hash := sha256.Sum256([]byte(token))
	api := httpapi.API{Store: db, Trust: ts, Authorization: as, Payments: payments.Service{Store: ps, Provider: sandbox.Provider{DB: provider.DB}}, PaymentStore: ps, Identity: identity.SandboxAuth{OwnerHash: hash, Owner: owner, Registry: db}, AgentTokenKey: hash[:], CallbackKey: callback, Log: log}
	ok = true
	return &Runtime{api, provider, log}, nil
}
func (r *Runtime) Close() { r.API.Store.DB.Close(); r.ProviderDB.DB.Close() }
func (r *Runtime) Work(ctx context.Context) {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			r.Tick(ctx)
		}
	}
}
func (r *Runtime) Tick(ctx context.Context) {
	rows, e := r.API.Store.DB.QueryContext(ctx, `SELECT id FROM north.payments WHERE state IN ('PENDING','SUBMITTED','UNKNOWN') ORDER BY updated_at,id LIMIT 32`)
	if e != nil {
		return
	}
	ids := []string{}
	for rows.Next() {
		var id string
		if rows.Scan(&id) == nil {
			ids = append(ids, id)
		}
	}
	rows.Close()
	for _, id := range ids {
		step, cancel := context.WithTimeout(ctx, 15*time.Second)
		_, e = r.API.Payments.Execute(step, id)
		cancel()
		if e != nil {
			r.Log.Warn("payment.reconcile_pending", "payment_id", id)
		}
	}
	rows, e = r.API.Store.DB.QueryContext(ctx, `SELECT r.payment_id,a.owner_subject FROM north.refunds r JOIN north.payments p ON p.id=r.payment_id JOIN north.grants g ON g.id=p.grant_id JOIN north.agents a ON a.id=g.agent_id WHERE r.state IN ('PENDING','UNKNOWN') ORDER BY r.updated_at,r.id LIMIT 16`)
	if e != nil {
		return
	}
	type item struct{ id, owner string }
	refunds := []item{}
	for rows.Next() {
		var i item
		if rows.Scan(&i.id, &i.owner) == nil {
			refunds = append(refunds, i)
		}
	}
	rows.Close()
	for _, i := range refunds {
		step, cancel := context.WithTimeout(ctx, 15*time.Second)
		e = r.API.Payments.Refund(step, i.owner, i.id)
		cancel()
		if e != nil {
			r.Log.Warn("refund.reconcile_pending", "payment_id", i.id)
		}
	}
}
