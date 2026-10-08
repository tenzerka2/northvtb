package httpapi

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"time"
)

type ErrorBody struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}
type ErrorResponse struct {
	Error     ErrorBody `json:"error"`
	RequestID string    `json:"request_id"`
}

func write(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

// Handler intentionally exposes no business routes in foundation.
func Handler(log *slog.Logger) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		started := time.Now()
		var entropy [16]byte
		if _, err := io.ReadFull(rand.Reader, entropy[:]); err != nil {
			http.Error(w, "unavailable", 503)
			return
		}
		id := hex.EncodeToString(entropy[:])
		w.Header().Set("X-Request-ID", id)
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		r.Body = http.MaxBytesReader(w, r.Body, 64*1024)
		status := http.StatusOK
		if r.URL.Path != "/healthz" && r.URL.Path != "/readyz" {
			status = 404
			write(w, status, ErrorResponse{ErrorBody{"NOT_FOUND", "Resource not found"}, id})
		} else if r.Method != http.MethodGet {
			status = 405
			w.Header().Set("Allow", "GET")
			write(w, status, ErrorResponse{ErrorBody{"METHOD_NOT_ALLOWED", "Method not allowed"}, id})
		} else if r.URL.Path == "/healthz" {
			write(w, status, map[string]string{"status": "alive"})
		} else {
			status = 503
			write(w, status, ErrorResponse{ErrorBody{"NOT_READY", "Financial services are not initialized"}, id})
		}
		// Do not log URL paths, queries, authorization headers or bodies supplied by clients.
		log.Info("http.request", "request_id", id, "status", status, "duration_ms", time.Since(started).Milliseconds())
	})
}
