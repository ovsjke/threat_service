package config

import (
	"fmt"
	"os"
	"strconv"
	"time"
)

type Config struct {
	ApiPort     string
	ApiURL      string
	DatabaseURL string

	ReadHeaderTimeout, ReadTimeout, WriteTimeout, IdleTimeout, ShutdownTimeout time.Duration

	RedisAddr          string
	ThreatCacheEnabled bool
	ThreatCacheTTL     time.Duration
}

func Load() (Config, error) {
	config := Config{ApiPort: os.Getenv("API_PORT"), ApiURL: os.Getenv("API_URL"), DatabaseURL: os.Getenv("DB_URL")}
	if config.ApiPort == "" {
		config.ApiPort = ":8080"
	}
	if config.ApiURL == "" {
		config.ApiURL = "http://localhost:8080"
	}
	if config.DatabaseURL == "" {
		return config, fmt.Errorf("DB_URL environment variable is not set")
	}
	config.ReadHeaderTimeout = 5 * time.Second
	config.ReadTimeout = 15 * time.Second
	config.WriteTimeout = 120 * time.Second
	config.IdleTimeout = 60 * time.Second
	config.ShutdownTimeout = 5 * time.Second
	for name, target := range map[string]*time.Duration{
		"API_READ_HEADER_TIMEOUT": &config.ReadHeaderTimeout,
		"API_READ_TIMEOUT":        &config.ReadTimeout,
		"API_WRITE_TIMEOUT":       &config.WriteTimeout,
		"API_IDLE_TIMEOUT":        &config.IdleTimeout,
		"API_SHUTDOWN_TIMEOUT":    &config.ShutdownTimeout,
	} {
		if value := os.Getenv(name); value != "" {
			duration, err := time.ParseDuration(value)
			if err != nil || duration <= 0 || duration > 24*time.Hour {
				return config, fmt.Errorf("invalid %s (positive duration, at most 24h)", name)
			}
			*target = duration
		}
	}
	config.RedisAddr = os.Getenv("REDIS_ADDR")
	if config.RedisAddr == "" {
		config.RedisAddr = "redis:6379"
	}

	enabled := os.Getenv("THREAT_CACHE_ENABLED")
	if enabled == "" {
		enabled = "false"
	}

	var err error

	config.ThreatCacheEnabled, err = strconv.ParseBool(enabled)
	if err != nil {
		return config, fmt.Errorf(
			"invalid THREAT_CACHE_ENABLED: %w", err,
		)
	}

	ttl := os.Getenv("THREAT_CACHE_TTL")
	if ttl == "" {
		ttl = "10m"
	}

	config.ThreatCacheTTL, err = time.ParseDuration(ttl)
	if err != nil {
		return config, fmt.Errorf(
			"invalid THREAT_CACHE_TTL: %w", err,
		)
	}

	if config.ThreatCacheTTL <= 0 {
		return config, fmt.Errorf(
			"THREAT_CACHE_TTL must be positive",
		)
	}
	return config, nil

}
