package main

import (
	"context"
	"errors"
	"fmt"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/ovsjke/threat_service/threat_api/internal/config"
	"github.com/ovsjke/threat_service/threat_api/internal/database"
	"github.com/ovsjke/threat_service/threat_api/internal/handler"
	"github.com/ovsjke/threat_service/threat_api/internal/repository"
	"github.com/ovsjke/threat_service/threat_api/internal/service"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"
	"net"
	"github.com/ovsjke/threat_service/threat_api/internal/grpcserver"
	threatv1 "github.com/ovsjke/threat_service/contracts/gen/go/threat/v1"
	"google.golang.org/grpc"
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

	grpcHandler := grpcserver.New(threatService)

	grpcSrv := grpc.NewServer()

	threatv1.RegisterThreatServiceServer(
		grpcSrv,
		grpcHandler,
	)

	grpcListener, err := net.Listen("tcp", ":50051")
	if err != nil {
		return fmt.Errorf("failed to listen for gRPC: %w", err)
	}
	defer grpcListener.Close()

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
	
	done := make(chan error, 2)

	// Запускаем HTTP-сервер.
	go func() {
		log.Info("Starting HTTP server", "addr", config.ApiPort)

		err := srv.ListenAndServe()
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			done <- fmt.Errorf("HTTP server: %w", err)
			return
		}

		done <- nil
	}()

	// Запускаем gRPC-сервер.
	go func() {
		log.Info("Starting gRPC server", "addr", ":50051")

		err := grpcSrv.Serve(grpcListener)
		if err != nil {
			done <- fmt.Errorf("gRPC server: %w", err)
			return
		}

		done <- nil
	}()

	// Ожидаем сигнал остановки или завершение одного из серверов.
	var serverErr error

	select {
	case serverErr = <-done:
		if serverErr != nil {
			log.Error("Server stopped unexpectedly", "error", serverErr)
		} else {
			log.Warn("Server stopped unexpectedly")
		}

	case <-ctx.Done():
		log.Info("Received shutdown signal")
	}

	// Останавливаем HTTP и gRPC параллельно.
	shutdownCtx, cancel := context.WithTimeout(
		context.Background(),
		5*time.Second,
	)
	defer cancel()

	httpShutdown := make(chan error, 1)
	go func() {
		httpShutdown <- srv.Shutdown(shutdownCtx)
	}()

	grpcShutdown := make(chan struct{})
	go func() {
		grpcSrv.GracefulStop()
		close(grpcShutdown)
	}()

	// Дожидаемся HTTP.
	if err := <-httpShutdown; err != nil {
		log.Error("HTTP shutdown failed", "error", err)
		_ = srv.Close()
		if serverErr == nil {
			serverErr = err
		}
	}

	// Дожидаемся gRPC с ограничением времени.
	select {
	case <-grpcShutdown:
		log.Info("gRPC server stopped gracefully")

	case <-shutdownCtx.Done():
		log.Warn("gRPC graceful shutdown timed out")
		grpcSrv.Stop()
		<-grpcShutdown
	}

	return serverErr

}
