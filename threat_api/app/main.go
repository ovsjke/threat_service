package main

import (
	"context"
	"errors"
	"fmt"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"threat_api/internal/config"
	"threat_api/internal/database"
	"threat_api/internal/handler"
	"threat_api/internal/repository"
	"threat_api/internal/service"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"
)

func main() {
	var log *slog.Logger = slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))
	if err := run(log); err != nil {
		log.Error("Application error", "error", err)
		os.Exit(1)
	}
}

func run(log *slog.Logger) error {
	config, err := config.Load()
	if err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	repo, err := database.Open(ctx, config.DatabaseURL)
	if err != nil {
		return err
	}
	defer repo.Pool.Close()
	pgRepo := repository.NewPostgresStorage(repo.Pool)
	threatService := service.NewThreatService(pgRepo)
	threatHandler := handler.NewThreatHandler(threatService, log)

	r := chi.NewRouter()

	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)
	r.NotFound(func(w http.ResponseWriter, req *http.Request) {
		handler.WriteError(w, http.StatusNotFound, "Not found", "Requested endpoint does not exist", log)
	})
	threatHandler.RegisterRoutes(r)
	srv := &http.Server{
		Addr:              config.ApiPort,
		Handler:           r,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      120 * time.Second,
		IdleTimeout:       60 * time.Second}
	done := make(chan error, 1)
	go func() {
		log.Info("Starting server on url", "url", config.ApiURL)
		done <- srv.ListenAndServe()
	}()
	select {
	case err := <-done:
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			return fmt.Errorf("server error: %w", err)
		}
		return nil
	case <-ctx.Done():
		log.Info("Shutting down server...")
	}
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return srv.Shutdown(shutdownCtx)
}
