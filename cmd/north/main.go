package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/tenzerka2/northvtb/internal/platform/httpapi"
	"github.com/tenzerka2/northvtb/internal/runtime"
)

func main() {
	if len(os.Args) > 1 && os.Args[1] == "healthcheck" {
		client := http.Client{Timeout: 2 * time.Second}
		resp, e := client.Get("http://127.0.0.1:8080/readyz")
		if e != nil {
			os.Exit(1)
		}
		resp.Body.Close()
		if resp.StatusCode != 200 {
			os.Exit(1)
		}
		return
	}
	if mode := os.Getenv("NORTH_MODE"); mode != "" && mode != "sandbox" {
		os.Exit(1)
	}
	log := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	addr := os.Getenv("NORTH_LISTEN_ADDR")
	if addr == "" {
		addr = "127.0.0.1:8080"
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	var handler http.Handler = httpapi.Handler(log)
	if os.Getenv("NORTH_MODE") == "sandbox" {
		initCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
		app, e := runtime.Open(initCtx, log)
		cancel()
		if e != nil {
			log.Error("startup.failed", "reason", e.Error())
			os.Exit(1)
		}
		defer app.Close()
		handler = app.Handler()
		go app.Work(ctx)
	}
	server := &http.Server{Addr: addr, Handler: handler, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 15 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 16 * 1024}
	done := make(chan error, 1)
	go func() {
		log.Info("server.start", "address", addr, "mode", os.Getenv("NORTH_MODE"))
		done <- server.ListenAndServe()
	}()
	select {
	case err := <-done:
		if !errors.Is(err, http.ErrServerClosed) {
			log.Error("server.failed")
			os.Exit(1)
		}
	case <-ctx.Done():
		shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := server.Shutdown(shutdown); err != nil {
			_ = server.Close()
			log.Error("server.shutdown_failed")
			os.Exit(1)
		}
	}
}
