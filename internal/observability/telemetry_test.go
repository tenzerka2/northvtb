package observability

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestTraceExportAndMetrics(t *testing.T) {
	var exported atomic.Bool
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, e := io.ReadAll(r.Body)
		if e != nil || r.URL.Path != "/v1/traces" || len(b) == 0 || strings.Contains(string(b), "private-token") {
			t.Error("invalid or sensitive trace export")
		}
		exported.Store(true)
		w.Header().Set("Content-Type", "application/x-protobuf")
		w.WriteHeader(200)
	}))
	defer s.Close()
	t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", s.URL)
	t.Setenv("OTEL_EXPORTER_OTLP_PROTOCOL", "http/protobuf")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	telemetry, e := New(ctx)
	if e != nil {
		t.Fatal(e)
	}
	defer telemetry.Provider.Shutdown(ctx)
	handler := telemetry.Wrap(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(403) }))
	req := httptest.NewRequest("POST", "/v1/payments?secret=private-token", nil)
	req.Header.Set("Authorization", "Bearer private-token")
	handler.ServeHTTP(httptest.NewRecorder(), req)
	if e = telemetry.Provider.ForceFlush(ctx); e != nil {
		t.Fatal(e)
	}
	if !exported.Load() {
		t.Fatal("no exported spans")
	}
	w := httptest.NewRecorder()
	telemetry.ServeHTTP(w, req)
	if !strings.Contains(w.Body.String(), "north_http_denied_total 1") {
		t.Fatal(w.Body.String())
	}
}
