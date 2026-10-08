package httpapi

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http/httptest"
	"testing"
)

func TestFoundationFailClosed(t *testing.T) {
	h := Handler(slog.New(slog.NewJSONHandler(io.Discard, nil)))
	for _, c := range []struct {
		method, path string
		status       int
	}{{"GET", "/healthz", 200}, {"GET", "/readyz", 503}, {"POST", "/healthz", 405}, {"POST", "/v1/payments", 404}, {"GET", "/missing", 404}} {
		r := httptest.NewRequest(c.method, c.path, nil)
		r.Header.Set("X-Request-ID", "attacker-controlled")
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != c.status {
			t.Fatal(c, w.Code)
		}
		id := w.Header().Get("X-Request-ID")
		if len(id) != 32 || id == "attacker-controlled" {
			t.Fatal("request id must be server generated")
		}
		if c.status != 200 {
			var e ErrorResponse
			if err := json.Unmarshal(w.Body.Bytes(), &e); err != nil || e.Error.Code == "" || e.RequestID != id {
				t.Fatal(w.Body.String(), err)
			}
		}
	}
}
