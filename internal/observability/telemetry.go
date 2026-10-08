package observability

import (
	"context"
	"fmt"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/propagation"
	sdk "go.opentelemetry.io/otel/sdk/trace"
	"net/http"
	"os"
	"strings"
	"sync/atomic"
	"time"
)

type Telemetry struct {
	Provider                        *sdk.TracerProvider
	requests, denied, failed, nanos atomic.Int64
}

func New(ctx context.Context) (*Telemetry, error) {
	opts := []sdk.TracerProviderOption{sdk.WithSampler(sdk.ParentBased(sdk.AlwaysSample()))}
	if os.Getenv("OTEL_EXPORTER_OTLP_ENDPOINT") != "" {
		exporter, e := otlptracehttp.New(ctx)
		if e != nil {
			return nil, e
		}
		opts = append(opts, sdk.WithBatcher(exporter))
	}
	p := sdk.NewTracerProvider(opts...)
	otel.SetTracerProvider(p)
	otel.SetTextMapPropagator(propagation.TraceContext{})
	return &Telemetry{Provider: p}, nil
}

type writer struct {
	http.ResponseWriter
	status int
}

func (w *writer) WriteHeader(n int) {
	if w.status == 0 {
		w.status = n
		w.ResponseWriter.WriteHeader(n)
	}
}
func (w *writer) Write(b []byte) (int, error) {
	if w.status == 0 {
		w.WriteHeader(200)
	}
	return w.ResponseWriter.Write(b)
}
func route(path string) string {
	switch path {
	case "/healthz", "/readyz", "/metrics", "/v1/agents", "/v1/agents/revoke", "/v1/mandates", "/v1/mandates/approve", "/v1/mandates/revoke", "/v1/authorizations", "/v1/payments", "/v1/refunds", "/v1/challenges/approve", "/v1/offers", "/v1/provider/callback":
		return path
	}
	for _, p := range []string{"/v1/mandates/", "/v1/payments/", "/v1/refunds/"} {
		if strings.HasPrefix(path, p) {
			return p + "{id}"
		}
	}
	return "/unknown"
}
func (t *Telemetry) Wrap(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		ctx := otel.GetTextMapPropagator().Extract(r.Context(), propagation.HeaderCarrier(r.Header))
		ctx, span := t.Provider.Tracer("north.http").Start(ctx, "http.request")
		defer span.End()
		out := &writer{ResponseWriter: w}
		next.ServeHTTP(out, r.WithContext(ctx))
		status := out.status
		if status == 0 {
			status = 200
		}
		span.SetAttributes(attribute.String("http.request.method", r.Method), attribute.String("http.route", route(r.URL.Path)), attribute.Int("http.response.status_code", status))
		t.requests.Add(1)
		if status >= 400 && status < 500 {
			t.denied.Add(1)
		}
		if status >= 500 {
			t.failed.Add(1)
		}
		t.nanos.Add(time.Since(start).Nanoseconds())
	})
}
func (t *Telemetry) ServeHTTP(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain; version=0.0.4")
	fmt.Fprintf(w, "# TYPE north_http_requests_total counter\nnorth_http_requests_total %d\n# TYPE north_http_denied_total counter\nnorth_http_denied_total %d\n# TYPE north_http_errors_total counter\nnorth_http_errors_total %d\n# TYPE north_http_duration_seconds_total counter\nnorth_http_duration_seconds_total %.9f\n", t.requests.Load(), t.denied.Load(), t.failed.Load(), float64(t.nanos.Load())/1e9)
}
