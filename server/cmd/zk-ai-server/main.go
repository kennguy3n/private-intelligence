// Package main is the entry point for the zk-ai server-side offload service.
//
// This server provides AI inference for managed_encrypted content when
// client devices are too low-end to run inference locally. It wraps the
// Rust zk-ai-core engine via cgo FFI.
//
// Privacy guardrails:
//   - No logging of input or output content
//   - Memory is zeroed after inference
//   - strict_zk content is rejected (403)
//   - Rate-limited per tenant
package main

import (
	"context"
	"flag"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"

	"github.com/kennguy3n/zk-ai/internal/api"
	"github.com/kennguy3n/zk-ai/internal/inference"
	"github.com/kennguy3n/zk-ai/internal/privacy"
)

func main() {
	addr := flag.String("addr", ":8090", "listen address")
	cacheDir := flag.String("cache-dir", "/tmp/zk-ai-models", "model cache directory")
	flag.Parse()

	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))
	slog.SetDefault(logger)

	// Initialize the inference engine (wraps Rust core via cgo)
	engine, err := inference.NewEngine(*cacheDir)
	if err != nil {
		slog.Error("failed to initialize inference engine", "err", err)
		os.Exit(1)
	}
	defer engine.Shutdown()

	// Privacy guard enforces managed_encrypted-only, no-log, memory wipe
	guard := privacy.NewGuard()

	// HTTP router
	r := chi.NewRouter()
	r.Use(middleware.RequestID)
	r.Use(middleware.RealIP)
	r.Use(middleware.Recoverer)
	r.Use(middleware.Timeout(60 * time.Second))

	// Health check
	r.Get("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"ok"}`))
	})

	// AI inference endpoint
	handler := api.NewHandler(engine, guard, logger)
	r.Post("/api/ai/infer", handler.Infer)
	r.Get("/api/ai/profile", handler.DeviceProfile)

	srv := &http.Server{
		Addr:         *addr,
		Handler:      r,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 60 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	// Graceful shutdown
	go func() {
		slog.Info("zk-ai server starting", "addr", *addr)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			slog.Error("server error", "err", err)
			os.Exit(1)
		}
	}()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	<-stop

	slog.Info("shutting down")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	srv.Shutdown(ctx)
}
