package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/ovsjke/threat_service/scanner/internal/clamav"
	"github.com/ovsjke/threat_service/scanner/internal/config"
	"github.com/ovsjke/threat_service/scanner/internal/handler"
	"github.com/ovsjke/threat_service/scanner/internal/scanning"
	"github.com/ovsjke/threat_service/scanner/internal/threatclient"
	"github.com/redis/go-redis/v9"
)

func main() {
	log := slog.New(slog.NewJSONHandler(os.Stdout, nil)).With("service", "scanner")
	if err := run(log); err != nil {
		log.Error("scanner stopped with error", "error", err)
		os.Exit(1)
	}
}
func run(log *slog.Logger) error {
	cfg, err := config.Load()
	if err != nil {
		return err
	}
	signals, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	// Request contexts remain alive during graceful shutdown. Cancel only on forced exit.
	requests, cancelRequests := context.WithCancel(context.Background())
	defer cancelRequests()
	engine := &clamav.Client{Address: cfg.ClamAVAddress, DialTimeout: cfg.DialTimeout, Timeout: cfg.EngineTimeout}

	var redisClient *redis.Client

	if cfg.ScannerCacheEnabled {
		redisClient = redis.NewClient(&redis.Options{
			Addr:         cfg.RedisAddr,
			DialTimeout:  cfg.ScannerCacheRedisTimeout,
			ReadTimeout:  cfg.ScannerCacheRedisTimeout,
			WriteTimeout: cfg.ScannerCacheRedisTimeout,
			MaxRetries:   -1,
		})
		defer redisClient.Close()
		pingCtx, cancel := context.WithTimeout(
			signals,
			cfg.ScannerCacheRedisTimeout,
		)

		pingErr := redisClient.Ping(pingCtx).Err()
		cancel()

		if pingErr != nil {
			log.Warn(
				"Redis unavailable, scanner will use ClamAV",
				"error", pingErr,
			)
		} else {
			log.Info("Scanner Redis connected")
		}

		versionCtx, cancel := context.WithTimeout(
			signals,
			cfg.ScannerCacheVersionTimeout,
		)

		version, versionErr := engine.Version(versionCtx)
		cancel()

		if versionErr != nil {
			log.Warn(
				"Cannot obtain ClamAV version",
				"error", versionErr,
			)
		} else {
			log.Info(
				"ClamAV version detected",
				"version", version,
			)
		}
	}

	var catalog scanning.ThreatCatalog
	if cfg.ThreatGRPCAddress != "" {
		client, err := threatclient.New(cfg.ThreatGRPCAddress)
		if err != nil {
			return err
		}
		defer client.Close()
		catalog = client
	}

	scanEngine := scanning.NewCachedEngine(
		engine,
		engine,
		redisClient,
		cfg.ScannerCacheTTL,
		cfg.ScannerCacheRedisTimeout,
		cfg.ScannerCacheVersionTimeout,
		cfg.ScannerCachePolicyVersion,
		log,
	)

	service := scanning.NewWithCatalog(
		scanEngine,
		catalog,
		cfg.MaxFileBytes,
		cfg.MaxConcurrent,
	)

	srv := &http.Server{
		Addr:              ":" + cfg.Port,
		Handler:           &handler.Handler{Service: service, MaxFileBytes: cfg.MaxFileBytes, Timeout: cfg.ScanTimeout, Log: log},
		ReadHeaderTimeout: cfg.ReadHeaderTimeout, ReadTimeout: cfg.ScanTimeout,
		WriteTimeout: cfg.ScanTimeout + 5*time.Second, IdleTimeout: cfg.IdleTimeout,
		MaxHeaderBytes: 64 << 10,
		BaseContext:    func(_ net.Listener) context.Context { return requests },
	}
	done := make(chan error, 1)
	go func() {
		log.Info("starting scanner", "address", srv.Addr, "clamav", cfg.ClamAVAddress, "threat_catalog", cfg.ThreatGRPCAddress)
		done <- srv.ListenAndServe()
	}()
	select {
	case err := <-done:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return fmt.Errorf("HTTP server: %w", err)
	case <-signals.Done():
	}
	stop()
	log.Info("shutting down scanner")
	ctx, cancel := context.WithTimeout(context.Background(), cfg.ShutdownTimeout)
	defer cancel()
	shutdownErr := srv.Shutdown(ctx)
	if shutdownErr != nil {
		cancelRequests()
		closeErr := srv.Close()
		if closeErr != nil {
			shutdownErr = errors.Join(shutdownErr, closeErr)
		}
	}
	serveErr := <-done
	if serveErr != nil && !errors.Is(serveErr, http.ErrServerClosed) {
		return errors.Join(shutdownErr, serveErr)
	}
	if shutdownErr != nil {
		return fmt.Errorf("HTTP shutdown: %w", shutdownErr)
	}
	log.Info("scanner stopped")
	return nil
}
