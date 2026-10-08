package httpapi

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/tenzerka2/northvtb/internal/adapters/postgres"
	"github.com/tenzerka2/northvtb/internal/authorization"
	"github.com/tenzerka2/northvtb/internal/domain"
	"github.com/tenzerka2/northvtb/internal/identity"
	"github.com/tenzerka2/northvtb/internal/payments"
	"github.com/tenzerka2/northvtb/internal/trust"
)

type API struct {
	Store         *postgres.Store
	Trust         trust.Service
	Authorization authorization.Service
	Payments      payments.Service
	PaymentStore  postgres.PaymentStore
	Identity      identity.Authenticator
	AgentTokenKey []byte
	CallbackKey   []byte
	Log           *slog.Logger
}
type DraftRequest struct {
	Terms trust.Terms `json:"terms"`
}
type ApprovalRequest struct {
	AgentID   string `json:"agent_id"`
	MandateID string `json:"mandate_id"`
	Digest    string `json:"digest"`
}
type RevokeRequest struct {
	AgentID   string `json:"agent_id"`
	MandateID string `json:"mandate_id"`
}
type AuthorizationRequest struct {
	Transaction domain.TransactionV1 `json:"transaction"`
}
type ExecutionRequest struct {
	Grant       authorization.Grant  `json:"grant"`
	Transaction domain.TransactionV1 `json:"transaction"`
}
type RefundRequest struct {
	PaymentID string `json:"payment_id"`
}
type RiskRequest struct {
	AgentID     string `json:"agent_id"`
	MandateID   string `json:"mandate_id"`
	ChallengeID string `json:"challenge_id"`
	Hash        string `json:"transaction_hash"`
}

// strict rejects unknown fields, duplicate keys, multiple values and invalid UTF-8.
func strict(b []byte, v any) error {
	if !utf8.Valid(b) || len(bytes.TrimSpace(b)) == 0 || bytes.TrimSpace(b)[0] != '{' {
		return domain.ErrInvalid
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.UseNumber()
	if e := unique(d); e != nil {
		return e
	}
	if _, e := d.Token(); e != io.EOF {
		return domain.ErrInvalid
	}
	d = json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if e := d.Decode(v); e != nil {
		return domain.ErrInvalid
	}
	return nil
}
func unique(d *json.Decoder) error {
	t, e := d.Token()
	if e != nil {
		return domain.ErrInvalid
	}
	delim, ok := t.(json.Delim)
	if !ok {
		return nil
	}
	if delim == '{' {
		seen := map[string]bool{}
		for d.More() {
			key, e := d.Token()
			s, ok := key.(string)
			if e != nil || !ok || seen[s] {
				return domain.ErrInvalid
			}
			seen[s] = true
			if e = unique(d); e != nil {
				return e
			}
		}
	} else if delim == '[' {
		for d.More() {
			if e = unique(d); e != nil {
				return e
			}
		}
	} else {
		return domain.ErrInvalid
	}
	_, e = d.Token()
	return e
}
func (a API) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	started := time.Now()
	var entropy [16]byte
	if _, e := rand.Read(entropy[:]); e != nil {
		http.Error(w, "Unavailable", 503)
		return
	}
	id := hex.EncodeToString(entropy[:])
	w.Header().Set("X-Request-ID", id)
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	fail := func(e error) {
		status, code := 500, "INTERNAL_ERROR"
		switch {
		case errors.Is(e, domain.ErrInvalid):
			status, code = 400, "INVALID_REQUEST"
		case errors.Is(e, identity.ErrUnauthenticated):
			status, code = 401, "UNAUTHENTICATED"
		case errors.Is(e, trust.ErrDenied):
			status, code = 403, "DENIED"
		case errors.Is(e, trust.ErrNotFound):
			status, code = 404, "NOT_FOUND"
		case errors.Is(e, trust.ErrConflict):
			status, code = 409, "IDEMPOTENCY_OR_STATE_CONFLICT"
		case errors.Is(e, authorization.ErrReplay):
			status, code = 409, "GRANT_NOT_USABLE"
		case errors.Is(e, authorization.ErrHash):
			status, code = 422, "TRANSACTION_HASH_MISMATCH"
		}
		write(w, status, ErrorResponse{ErrorBody{code, "Request could not be completed"}, id})
	}
	defer func() {
		if recover() != nil {
			a.Log.Error("http.panic", "request_id", id)
			write(w, 500, ErrorResponse{ErrorBody{"INTERNAL_ERROR", "Request could not be completed"}, id})
		}
		a.Log.Info("http.request", "request_id", id, "duration_ms", time.Since(started).Milliseconds())
	}()
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	r = r.WithContext(ctx)
	if r.Method == "GET" && r.URL.Path == "/healthz" {
		write(w, 200, map[string]string{"status": "alive"})
		return
	}
	if r.Method == "GET" && r.URL.Path == "/readyz" {
		if e := a.Store.DB.PingContext(ctx); e != nil {
			write(w, 503, ErrorResponse{ErrorBody{"NOT_READY", "Dependency unavailable"}, id})
			return
		}
		write(w, 200, map[string]string{"status": "ready"})
		return
	}
	var body []byte
	if r.Method == "POST" {
		var e error
		body, e = io.ReadAll(http.MaxBytesReader(w, r.Body, 64*1024))
		if e != nil {
			fail(domain.ErrInvalid)
			return
		}
	}
	if r.Method == "POST" && r.URL.Path == "/v1/provider/callback" {
		var c payments.Callback
		if e := strict(body, &c); e != nil {
			fail(e)
			return
		}
		if e := a.PaymentStore.Callback(ctx, a.CallbackKey, c, r.Header.Get("X-Sandbox-Signature")); e != nil {
			fail(trust.ErrDenied)
			return
		}
		write(w, 200, map[string]string{"status": "accepted"})
		return
	}
	auth := r.Header.Get("Authorization")
	if !strings.HasPrefix(auth, "Bearer ") {
		fail(identity.ErrUnauthenticated)
		return
	}
	principal, e := a.Identity.Authenticate(ctx, strings.TrimPrefix(auth, "Bearer "))
	if e != nil {
		fail(e)
		return
	}
	actor := principal.Owner
	if principal.AgentID != "" {
		actor = principal.AgentID
	}
	if principal.AgentID != "" {
		if e = a.Store.Within(ctx, func(t trust.Tx) error { return t.Emit(actor, "agent.authenticated", actor, a.Trust.Now()) }); e != nil {
			fail(e)
			return
		}
	}
	if r.Method == "GET" {
		switch {
		case r.URL.Path == "/v1/offers":
			offers, e := a.Store.Offers(ctx, r.URL.Query().Get("product"))
			if e != nil {
				fail(e)
				return
			}
			write(w, 200, offers)
			return
		case strings.HasPrefix(r.URL.Path, "/v1/mandates/"):
			mid := strings.TrimPrefix(r.URL.Path, "/v1/mandates/")
			var m trust.Mandate
			e = a.Store.Within(ctx, func(tx trust.Tx) error {
				var e error
				m, e = tx.Mandate(mid)
				if e != nil {
					return e
				}
				if m.Terms.Owner != principal.Owner || principal.AgentID != "" && m.Terms.AgentID != principal.AgentID {
					return trust.ErrNotFound
				}
				return nil
			})
			if e != nil {
				fail(e)
				return
			}
			write(w, 200, m)
			return
		case strings.HasPrefix(r.URL.Path, "/v1/payments/"):
			pid := strings.TrimPrefix(r.URL.Path, "/v1/payments/")
			owner, agent, e := a.Store.PaymentOwner(ctx, pid)
			if e != nil || owner != principal.Owner || principal.AgentID != "" && agent != principal.AgentID {
				fail(trust.ErrNotFound)
				return
			}
			var state string
			if e = a.Store.DB.QueryRowContext(ctx, `SELECT state FROM north.payments WHERE id=$1`, pid).Scan(&state); e != nil {
				fail(e)
				return
			}
			write(w, 200, map[string]string{"payment_id": pid, "state": state})
			return
		default:
			fail(trust.ErrNotFound)
			return
		}
	}
	if r.Method != "POST" {
		fail(trust.ErrNotFound)
		return
	}
	key := r.Header.Get("Idempotency-Key")
	if len(key) < 1 || len(key) > 128 {
		fail(domain.ErrInvalid)
		return
	}
	operation := ""
	var payload any
	switch r.URL.Path {
	case "/v1/agents":
		operation = "http.register"
		payload = &struct{}{}
	case "/v1/mandates":
		operation = "http.draft"
		payload = &DraftRequest{}
	case "/v1/mandates/approve":
		operation = "http.approve"
		payload = &ApprovalRequest{}
	case "/v1/mandates/revoke":
		operation = "http.revoke"
		payload = &RevokeRequest{}
	case "/v1/agents/revoke":
		operation = "http.agent-revoke"
		payload = &struct {
			AgentID string `json:"agent_id"`
		}{}
	case "/v1/authorizations":
		operation = "http.authorize"
		payload = &AuthorizationRequest{}
	case "/v1/payments":
		operation = "http.execute"
		payload = &ExecutionRequest{}
	case "/v1/refunds":
		operation = "http.refund"
		payload = &RefundRequest{}
	case "/v1/challenges/approve":
		operation = "http.risk"
		payload = &RiskRequest{}
	default:
		fail(trust.ErrNotFound)
		return
	}
	agentAction := operation == "http.authorize" || operation == "http.execute"
	if agentAction != (principal.AgentID != "") {
		fail(trust.ErrDenied)
		return
	}
	if e = strict(body, payload); e != nil {
		fail(e)
		return
	}
	canonical, e := json.Marshal(payload)
	if e != nil {
		fail(e)
		return
	}
	var agentToken string
	if operation == "http.register" {
		h := hmac.New(sha256.New, a.AgentTokenKey)
		h.Write([]byte(principal.Owner + "\x00" + key))
		agentToken = hex.EncodeToString(h.Sum(nil))
	}
	response, e := a.Store.Request(ctx, actor, operation, key, canonical, func(ts postgres.RequestTx, as authorization.Store) (any, error) {
		trustService := a.Trust
		trustService.Store = ts
		authService := a.Authorization
		authService.Store = as
		authService.Trust = trustService
		switch v := payload.(type) {
		case *struct{}:
			ag, e := trustService.Register(ctx, principal.Owner, trust.Agent{Provider: "sandbox", CredentialRef: identity.Credential(agentToken)})
			if e != nil {
				return nil, e
			}
			return map[string]any{"agent_id": ag.ID, "agent": ag}, nil
		case *DraftRequest:
			m, e := trustService.Draft(ctx, principal.Owner, v.Terms)
			if e != nil {
				return nil, e
			}
			d, e := m.Terms.Digest()
			return map[string]any{"mandate_id": m.Terms.ID, "digest": d, "mandate": m}, e
		case *ApprovalRequest:
			return trustService.Approve(ctx, principal.Owner, v.AgentID, v.MandateID, v.Digest)
		case *RevokeRequest:
			if e := trustService.Revoke(ctx, principal.Owner, v.AgentID, v.MandateID); e != nil {
				return nil, e
			}
			return map[string]string{"status": "revoked"}, nil
		case *struct {
			AgentID string `json:"agent_id"`
		}:
			if e := trustService.RevokeAgent(ctx, principal.Owner, v.AgentID); e != nil {
				return nil, e
			}
			return map[string]string{"status": "revoked"}, nil
		case *AuthorizationRequest:
			return authService.Issue(ctx, principal.AgentID, key, v.Transaction)
		case *ExecutionRequest:
			pid, e := authService.Consume(ctx, principal.AgentID, v.Grant, v.Transaction)
			return map[string]string{"payment_id": pid, "state": "PENDING"}, e
		case *RefundRequest:
			rid, e := ts.StartRefund(principal.Owner, v.PaymentID, a.Trust.Now())
			return map[string]string{"refund_id": rid, "state": "PENDING"}, e
		case *RiskRequest:
			if e := authService.ApproveRisk(ctx, principal.Owner, v.AgentID, v.MandateID, v.ChallengeID, v.Hash); e != nil {
				return nil, e
			}
			return map[string]string{"status": "approved"}, nil
		}
		return nil, domain.ErrInvalid
	})
	if e != nil {
		// The mutation rolled back. Record denial independently rather than losing it.
		if errors.Is(e, trust.ErrDenied) || errors.Is(e, authorization.ErrHash) || errors.Is(e, authorization.ErrReplay) {
			auditErr := a.Store.Within(ctx, func(tx trust.Tx) error { return tx.Emit(actor, "request.denied", operation, a.Trust.Now()) })
			if auditErr != nil {
				fail(auditErr)
				return
			}
		}
		fail(e)
		return
	}
	if operation == "http.register" {
		var out map[string]any
		if e = json.Unmarshal(response, &out); e != nil {
			fail(e)
			return
		}
		out["agent_token"] = agentToken
		write(w, 200, out)
		return
	}
	w.WriteHeader(200)
	_, _ = w.Write(response)
}
