// Package webui serves the sandbox owner workspace on the API's origin.
// Owner and simulated agent credentials stay server-side after login.
package webui

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"embed"
	"encoding/hex"
	"encoding/json"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"time"

	"github.com/tenzerka2/northvtb/internal/adapters/postgres"
	"github.com/tenzerka2/northvtb/internal/domain"
	"github.com/tenzerka2/northvtb/internal/policy"
	"github.com/tenzerka2/northvtb/internal/trust"
)

//go:embed static
var assets embed.FS

type Handler struct {
	api           http.Handler
	store         *postgres.Store
	trust         trust.Service
	owner, token  string
	key           []byte
	files         http.Handler
	mu            sync.Mutex
	sessions      map[string]time.Time
	loginWindow   time.Time
	loginAttempts int
}

func New(api http.Handler, store *postgres.Store, ts trust.Service, owner, token string) *Handler {
	root, _ := fs.Sub(assets, "static")
	key := sha256.Sum256([]byte(token))
	return &Handler{api: api, store: store, trust: ts, owner: owner, token: token, key: key[:], files: http.FileServer(http.FS(root)), sessions: map[string]time.Time{}}
}
func respond(w http.ResponseWriter, code int, value any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(value)
}
func fail(w http.ResponseWriter, code int) {
	respond(w, code, map[string]string{"error": http.StatusText(code)})
}
func (h *Handler) signedIn(r *http.Request) bool {
	c, e := r.Cookie("north_session")
	if e != nil {
		return false
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	expiry, ok := h.sessions[c.Value]
	if !ok || time.Now().After(expiry) {
		delete(h.sessions, c.Value)
		return false
	}
	return true
}
func sameOrigin(r *http.Request) bool {
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	return r.Header.Get("X-North-UI") == "1" && (r.Header.Get("Origin") == "" || r.Header.Get("Origin") == scheme+"://"+r.Host) && r.Header.Get("Sec-Fetch-Site") != "cross-site"
}
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if strings.HasPrefix(r.URL.Path, "/v1/") || r.URL.Path == "/healthz" || r.URL.Path == "/readyz" || r.URL.Path == "/metrics" {
		h.api.ServeHTTP(w, r)
		return
	}
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self'; font-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
	w.Header().Set("Cache-Control", "no-store")
	if !strings.HasPrefix(r.URL.Path, "/ui/") {
		if r.Method != "GET" && r.Method != "HEAD" {
			fail(w, 405)
			return
		}
		h.files.ServeHTTP(w, r)
		return
	}
	if r.Method != "GET" && !sameOrigin(r) {
		fail(w, 403)
		return
	}
	if r.URL.Path == "/ui/session" {
		h.session(w, r)
		return
	}
	if !h.signedIn(r) {
		fail(w, 401)
		return
	}
	if r.URL.Path == "/ui/workspace" && r.Method == "GET" {
		h.workspace(w, r)
		return
	}
	if r.URL.Path == "/ui/offers" && r.Method == "GET" {
		h.offers(w, r)
		return
	}
	path := strings.TrimPrefix(r.URL.Path, "/ui/api")
	ownerPaths := map[string]bool{"/v1/agents": true, "/v1/agents/revoke": true, "/v1/mandates": true, "/v1/mandates/approve": true, "/v1/mandates/revoke": true, "/v1/challenges/approve": true, "/v1/refunds": true}
	if strings.HasPrefix(r.URL.Path, "/ui/api/") && r.Method == "POST" && ownerPaths[path] {
		h.forward(w, r, path, h.token)
		return
	}
	if r.URL.Path == "/ui/agent/authorizations" || r.URL.Path == "/ui/agent/payments" {
		if r.Method != "POST" {
			fail(w, 405)
			return
		}
		agent := r.Header.Get("X-North-Agent")
		// Recover the deterministic sandbox credential from its owner-scoped registration.
		var key string
		e := h.store.DB.QueryRowContext(r.Context(), `SELECT i.key FROM north.idempotency i JOIN north.agents a ON a.id=$2 AND a.owner_subject=$1 AND a.status='ACTIVE' WHERE i.principal=$1 AND i.operation='http.register' AND convert_from(i.response_body,'UTF8')::jsonb->>'agent_id'=a.id LIMIT 1`, h.owner, agent).Scan(&key)
		if e != nil {
			fail(w, 403)
			return
		}
		mac := hmac.New(sha256.New, h.key)
		mac.Write([]byte(h.owner + "\x00" + key))
		h.forward(w, r, "/v1/"+strings.TrimPrefix(r.URL.Path, "/ui/agent/"), hex.EncodeToString(mac.Sum(nil)))
		return
	}
	fail(w, 404)
}
func (h *Handler) session(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "GET":
		if !h.signedIn(r) {
			fail(w, 401)
			return
		}
		respond(w, 200, map[string]string{"owner": h.owner})
	case "DELETE":
		if c, e := r.Cookie("north_session"); e == nil {
			h.mu.Lock()
			delete(h.sessions, c.Value)
			h.mu.Unlock()
		}
		http.SetCookie(w, &http.Cookie{Name: "north_session", Path: "/ui", MaxAge: -1, HttpOnly: true, Secure: r.TLS != nil, SameSite: http.SameSiteStrictMode})
		respond(w, 200, map[string]bool{"ok": true})
	case "POST":
		h.mu.Lock()
		if time.Since(h.loginWindow) > time.Minute {
			h.loginWindow = time.Now()
			h.loginAttempts = 0
		}
		h.loginAttempts++
		limited := h.loginAttempts > 20
		h.mu.Unlock()
		if limited {
			fail(w, 429)
			return
		}
		var input struct {
			Token string `json:"token"`
		}
		if json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&input) != nil || subtle.ConstantTimeCompare([]byte(input.Token), []byte(h.token)) != 1 {
			fail(w, 401)
			return
		}
		var nonce [32]byte
		if _, e := rand.Read(nonce[:]); e != nil {
			fail(w, 500)
			return
		}
		id := hex.EncodeToString(nonce[:])
		h.mu.Lock()
		for k, v := range h.sessions {
			if time.Now().After(v) {
				delete(h.sessions, k)
			}
		}
		if len(h.sessions) >= 100 {
			h.mu.Unlock()
			fail(w, 429)
			return
		}
		h.sessions[id] = time.Now().Add(8 * time.Hour)
		h.mu.Unlock()
		http.SetCookie(w, &http.Cookie{Name: "north_session", Value: id, Path: "/ui", MaxAge: 28800, HttpOnly: true, Secure: r.TLS != nil, SameSite: http.SameSiteStrictMode})
		respond(w, 200, map[string]string{"owner": h.owner})
	default:
		fail(w, 405)
	}
}
func (h *Handler) forward(w http.ResponseWriter, r *http.Request, path, token string) {
	req := r.Clone(r.Context())
	req.URL.Path = path
	req.URL.RawQuery = ""
	req.RequestURI = path
	req.Header = r.Header.Clone()
	req.Header.Set("Authorization", "Bearer "+token)
	req.Body = http.MaxBytesReader(w, r.Body, 65536)
	out := httptest.NewRecorder()
	h.api.ServeHTTP(out, req)
	// Never return simulated-agent credentials to a browser.
	var body map[string]json.RawMessage
	if json.Unmarshal(out.Body.Bytes(), &body) == nil {
		delete(body, "agent_token")
		respond(w, out.Code, body)
		return
	}
	fail(w, out.Code)
}

type payment struct {
	ID          string               `json:"id"`
	State       string               `json:"state"`
	Transaction domain.TransactionV1 `json:"transaction"`
	CreatedAt   time.Time            `json:"created_at"`
}

func (h *Handler) workspace(w http.ResponseWriter, r *http.Request) {
	agents := []trust.Agent{}
	mandates := []trust.Mandate{}
	payments := []payment{}
	rows, e := h.store.DB.QueryContext(r.Context(), `SELECT id FROM north.agents WHERE owner_subject=$1 ORDER BY created_at DESC LIMIT 200`, h.owner)
	if e != nil {
		fail(w, 503)
		return
	}
	ids := []string{}
	for rows.Next() {
		var id string
		if e = rows.Scan(&id); e != nil {
			break
		}
		ids = append(ids, id)
	}
	if e == nil {
		e = rows.Err()
	}
	rows.Close()
	if e != nil {
		fail(w, 503)
		return
	}
	e = h.store.Within(r.Context(), func(tx trust.Tx) error {
		for _, id := range ids {
			a, e := tx.Agent(id)
			if e != nil {
				return e
			}
			agents = append(agents, a)
		}
		return nil
	})
	if e != nil {
		fail(w, 503)
		return
	}
	rows, e = h.store.DB.QueryContext(r.Context(), `SELECT id FROM north.mandates WHERE owner_subject=$1 ORDER BY created_at DESC LIMIT 200`, h.owner)
	if e != nil {
		fail(w, 503)
		return
	}
	ids = []string{}
	for rows.Next() {
		var id string
		if e = rows.Scan(&id); e != nil {
			break
		}
		ids = append(ids, id)
	}
	if e == nil {
		e = rows.Err()
	}
	rows.Close()
	if e != nil {
		fail(w, 503)
		return
	}
	e = h.store.Within(r.Context(), func(tx trust.Tx) error {
		for _, id := range ids {
			m, e := tx.Mandate(id)
			if e != nil {
				return e
			}
			mandates = append(mandates, m)
		}
		return nil
	})
	if e != nil {
		fail(w, 503)
		return
	}
	rows, e = h.store.DB.QueryContext(r.Context(), `SELECT p.id,p.state,g.canonical_transaction,p.created_at FROM north.payments p JOIN north.grants g ON g.id=p.grant_id JOIN north.mandates m ON m.id=g.mandate_id WHERE m.owner_subject=$1 ORDER BY p.created_at DESC LIMIT 200`, h.owner)
	if e != nil {
		fail(w, 503)
		return
	}
	for rows.Next() {
		var p payment
		var raw []byte
		if e = rows.Scan(&p.ID, &p.State, &raw, &p.CreatedAt); e != nil {
			break
		}
		if e = json.Unmarshal(raw, &p.Transaction); e != nil {
			break
		}
		payments = append(payments, p)
	}
	if e == nil {
		e = rows.Err()
	}
	rows.Close()
	if e != nil {
		fail(w, 503)
		return
	}
	digests := map[string]string{}
	for _, m := range mandates {
		digests[m.Terms.ID], _ = m.Terms.Digest()
	}
	events, e := h.store.OwnerAudit(r.Context(), h.owner)
	if e != nil {
		fail(w, 503)
		return
	}
	respond(w, 200, map[string]any{"owner": h.owner, "agents": agents, "mandates": mandates, "payments": payments, "events": events, "digests": digests})
}
func (h *Handler) offers(w http.ResponseWriter, r *http.Request) {
	var m trust.Mandate
	var a trust.Agent
	e := h.store.Within(r.Context(), func(tx trust.Tx) error {
		var e error
		m, e = tx.Mandate(r.URL.Query().Get("mandate"))
		if e != nil {
			return e
		}
		if m.Terms.Owner != h.owner {
			return trust.ErrDenied
		}
		a, e = tx.Agent(m.Terms.AgentID)
		return e
	})
	if e != nil {
		fail(w, 404)
		return
	}
	offers, e := h.store.Offers(r.Context(), m.Terms.Product)
	if e != nil {
		fail(w, 503)
		return
	}
	result := []any{}
	for _, o := range offers {
		t := domain.TransactionV1{SchemaVersion: 1, MandateID: m.Terms.ID, AgentID: a.ID, MerchantID: o.Merchant, OfferID: o.ID, OfferRevision: o.Revision, Action: m.Terms.Action, Purpose: m.Terms.Purpose, Product: o.Product, Category: o.Category, Condition: o.Condition, Quantity: o.Quantity, UnitAmount: o.UnitAmount, Fees: o.Fees, Shipping: o.Shipping, Amount: o.Amount, Currency: o.Currency}
		decision := policy.Evaluate(policy.Input{Agent: a, Mandate: m, Transaction: t, Offer: o, Now: time.Now().Unix(), Available: domain.Available(m.State, time.Now().Unix(), m.Terms.ExpiresAt, m.Terms.MaxUses, m.Reserved, m.Consumed)})
		if h.trust.Verify(r.Context(), a, m) != nil {
			decision.Decision = policy.Deny
		}
		hash, _ := t.Digest()
		result = append(result, map[string]any{"offer": o, "transaction": t, "transaction_hash": hash, "policy": decision})
	}
	respond(w, 200, result)
}
