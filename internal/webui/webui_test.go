package webui

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/tenzerka2/northvtb/internal/trust"
)

func TestSessionBoundaryAndCredentialRedaction(t *testing.T) {
	token := strings.Repeat("secret", 8)
	called := false
	api := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		if r.URL.Path != "/v1/agents" || r.Header.Get("Authorization") != "Bearer "+token {
			t.Fatal("incorrect owner forwarding")
		}
		respond(w, 200, map[string]string{"agent_id": "agent-1", "agent_token": "must-not-reach-browser"})
	})
	h := New(api, nil, trust.Service{}, "owner", token)
	call := func(method, path, origin, body string, cookie *http.Cookie) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, "http://localhost"+path, strings.NewReader(body))
		r.Header.Set("X-North-UI", "1")
		r.Header.Set("Origin", origin)
		if cookie != nil {
			r.AddCookie(cookie)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}
	if w := call("POST", "/ui/session", "https://attacker.example", `{"token":"`+token+`"}`, nil); w.Code != 403 {
		t.Fatal(w.Code)
	}
	if w := call("GET", "/ui/workspace", "", "", nil); w.Code != 401 {
		t.Fatal(w.Code)
	}
	if w := call("POST", "/ui/session", "http://localhost", `{"token":"wrong"}`, nil); w.Code != 401 {
		t.Fatal(w.Code)
	}
	w := call("POST", "/ui/session", "http://localhost", `{"token":"`+token+`"}`, nil)
	if w.Code != 200 {
		t.Fatal(w.Code)
	}
	cookies := w.Result().Cookies()
	if len(cookies) != 1 || !cookies[0].HttpOnly || cookies[0].SameSite != http.SameSiteStrictMode {
		t.Fatal("unsafe session cookie")
	}
	cookie := cookies[0]
	if w = call("POST", "/ui/api/v1/agents", "https://attacker.example", "{}", cookie); w.Code != 403 || called {
		t.Fatal("cross-site mutation accepted")
	}
	if w = call("POST", "/ui/api/v1/agents", "http://localhost", "{}", cookie); w.Code != 200 || !called || strings.Contains(w.Body.String(), "agent_token") || strings.Contains(w.Body.String(), "must-not-reach") {
		t.Fatal("credential redaction failed", w.Body.String())
	}
	if w = call("POST", "/ui/api/v1/unknown", "http://localhost", "{}", cookie); w.Code != 404 {
		t.Fatal("proxy route not restricted")
	}
	h.mu.Lock()
	h.sessions[cookie.Value] = time.Now().Add(-time.Second)
	h.mu.Unlock()
	if w = call("GET", "/ui/session", "", "", cookie); w.Code != 401 {
		t.Fatal("expired session accepted")
	}
}
func TestEmbeddedUI(t *testing.T) {
	h := New(http.NotFoundHandler(), nil, trust.Service{}, "owner", strings.Repeat("x", 32))
	for _, path := range []string{"/", "/app.js", "/style.css", "/assets/Manrope.woff", "/assets/monitor.svg"} {
		r := httptest.NewRequest("GET", path, nil)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != 200 || w.Body.Len() == 0 {
			t.Fatalf("%s: %d", path, w.Code)
		}
		if !strings.Contains(w.Header().Get("Content-Security-Policy"), "frame-ancestors 'none'") {
			t.Fatal("missing CSP")
		}
	}
}
