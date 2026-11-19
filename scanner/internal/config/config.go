package config

import (
	"fmt"
	"math"
	"net"
	"os"
	"strconv"
	"time"
)

type Config struct {
	Port                                                     string
	ClamAVAddress                                            string
	ThreatGRPCAddress                                        string
	MaxFileBytes                                             int64
	MaxConcurrent                                            int
	ScanTimeout, DialTimeout, EngineTimeout, ShutdownTimeout time.Duration
	ReadHeaderTimeout, IdleTimeout                           time.Duration
	RedisAddr                                                string
	ScannerCacheEnabled                                      bool
	ScannerCacheTTL                                          time.Duration
	ScannerCacheRedisTimeout                                 time.Duration
	ScannerCachePolicyVersion                                string
	ScannerCacheVersionTimeout                               time.Duration
}

func Load() (Config, error) {
	c := Config{Port: "8082", ClamAVAddress: "localhost:3310", MaxFileBytes: 10 << 20, MaxConcurrent: 4, ScanTimeout: 60 * time.Second, DialTimeout: 3 * time.Second, EngineTimeout: 60 * time.Second, ShutdownTimeout: 15 * time.Second, ReadHeaderTimeout: 5 * time.Second, IdleTimeout: 60 * time.Second}
	if v := os.Getenv("SCANNER_HTTP_PORT"); v != "" {
		c.Port = v
	}
	port, err := strconv.Atoi(c.Port)
	if err != nil || port < 1 || port > 65535 {
		return c, fmt.Errorf("invalid SCANNER_HTTP_PORT")
	}
	c.ThreatGRPCAddress = os.Getenv("THREAT_GRPC_ADDR")
	if v := os.Getenv("CLAMAV_ADDRESS"); v != "" {
		c.ClamAVAddress = v
	}
	if _, _, err := net.SplitHostPort(c.ClamAVAddress); err != nil {
		return c, fmt.Errorf("CLAMAV_ADDRESS: %w", err)
	}
	if v := os.Getenv("SCANNER_MAX_FILE_BYTES"); v != "" {
		n, err := strconv.ParseInt(v, 10, 64)
		if err != nil || n <= 0 || n > math.MaxInt64-(1<<20) {
			return c, fmt.Errorf("invalid SCANNER_MAX_FILE_BYTES")
		}
		c.MaxFileBytes = n
	}
	if v := os.Getenv("SCANNER_MAX_CONCURRENT"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n <= 0 || n > 1024 {
			return c, fmt.Errorf("invalid SCANNER_MAX_CONCURRENT (1..1024)")
		}
		c.MaxConcurrent = n
	}
	for name, target := range map[string]*time.Duration{"SCANNER_SCAN_TIMEOUT": &c.ScanTimeout, "CLAMAV_DIAL_TIMEOUT": &c.DialTimeout, "CLAMAV_TIMEOUT": &c.EngineTimeout, "SCANNER_SHUTDOWN_TIMEOUT": &c.ShutdownTimeout, "SCANNER_READ_HEADER_TIMEOUT": &c.ReadHeaderTimeout, "SCANNER_IDLE_TIMEOUT": &c.IdleTimeout} {
		if v := os.Getenv(name); v != "" {
			d, err := time.ParseDuration(v)
			if err != nil || d <= 0 || d > 24*time.Hour {
				return c, fmt.Errorf("invalid %s (positive duration, at most 24h)", name)
			}
			*target = d
		}
	}

	c.RedisAddr = os.Getenv("REDIS_ADDR")
	if c.RedisAddr == "" {
		c.RedisAddr = "redis:6379"
	}

	if _, _, err := net.SplitHostPort(c.RedisAddr); err != nil {
		return c, fmt.Errorf("invalid REDIS_ADDR: %w", err)
	}

	if v := os.Getenv("SCANNER_CACHE_ENABLED"); v != "" {
		enabled, err := strconv.ParseBool(v)
		if err != nil {
			return c, fmt.Errorf("invalid SCANNER_CACHE_ENABLED: %w", err)
		}
		c.ScannerCacheEnabled = enabled
	}

	c.ScannerCacheTTL = time.Hour
	if v := os.Getenv("SCANNER_CACHE_TTL"); v != "" {
		ttl, err := time.ParseDuration(v)
		if err != nil || ttl <= 0 || ttl > 24*time.Hour {
			return c, fmt.Errorf("invalid SCANNER_CACHE_TTL")
		}
		c.ScannerCacheTTL = ttl
	}

	c.ScannerCacheRedisTimeout = 80 * time.Millisecond
	if v := os.Getenv("SCANNER_CACHE_REDIS_TIMEOUT"); v != "" {
		timeout, err := time.ParseDuration(v)
		if err != nil || timeout <= 0 || timeout > time.Second {
			return c, fmt.Errorf("invalid SCANNER_CACHE_REDIS_TIMEOUT")
		}
		c.ScannerCacheRedisTimeout = timeout
	}

	c.ScannerCachePolicyVersion = os.Getenv("SCANNER_CACHE_POLICY_VERSION")
	if c.ScannerCachePolicyVersion == "" {
		c.ScannerCachePolicyVersion = "v1"
	}

	c.ScannerCacheVersionTimeout = 500 * time.Millisecond

	if v := os.Getenv("SCANNER_CACHE_VERSION_TIMEOUT"); v != "" {
		timeout, err := time.ParseDuration(v)
		if err != nil || timeout <= 0 || timeout > 5*time.Second {
			return c, fmt.Errorf(
				"invalid SCANNER_CACHE_VERSION_TIMEOUT",
			)
		}

		c.ScannerCacheVersionTimeout = timeout
	}
	return c, nil
}
