package config

import (
	"testing"
	"time"
)

func clearConfig(t *testing.T) {
	t.Helper()
	for _, key := range []string{"THREAT_GRPC_ADDR", "SCANNER_HTTP_PORT", "CLAMAV_ADDRESS", "SCANNER_MAX_FILE_BYTES", "SCANNER_MAX_CONCURRENT", "SCANNER_SCAN_TIMEOUT", "CLAMAV_DIAL_TIMEOUT", "CLAMAV_TIMEOUT", "SCANNER_SHUTDOWN_TIMEOUT", "SCANNER_READ_HEADER_TIMEOUT", "SCANNER_IDLE_TIMEOUT"} {
		t.Setenv(key, "")
	}
}
func TestDefaults(t *testing.T) {
	clearConfig(t)
	c, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if c.MaxFileBytes != 10<<20 || c.MaxConcurrent != 4 || c.ShutdownTimeout != 15*time.Second {
		t.Fatalf("%+v", c)
	}
}
func TestInvalidConfig(t *testing.T) {
	for _, tc := range []struct{ key, value string }{{"SCANNER_HTTP_PORT", "0"}, {"SCANNER_HTTP_PORT", "abc"}, {"CLAMAV_ADDRESS", "noport"}, {"SCANNER_MAX_FILE_BYTES", "0"}, {"SCANNER_MAX_FILE_BYTES", "9223372036854775807"}, {"SCANNER_MAX_CONCURRENT", "-1"}, {"SCANNER_MAX_CONCURRENT", "1025"}, {"SCANNER_SCAN_TIMEOUT", "0s"}, {"SCANNER_SHUTDOWN_TIMEOUT", "garbage"}, {"CLAMAV_TIMEOUT", "25h"}} {
		t.Run(tc.key+tc.value, func(t *testing.T) {
			clearConfig(t)
			t.Setenv(tc.key, tc.value)
			if _, err := Load(); err == nil {
				t.Fatal("expected invalid configuration")
			}
		})
	}
}
func TestOverrides(t *testing.T) {
	clearConfig(t)
	t.Setenv("SCANNER_HTTP_PORT", "8090")
	t.Setenv("SCANNER_MAX_FILE_BYTES", "1024")
	t.Setenv("SCANNER_MAX_CONCURRENT", "2")
	t.Setenv("SCANNER_SCAN_TIMEOUT", "2s")
	c, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if c.Port != "8090" || c.MaxFileBytes != 1024 || c.MaxConcurrent != 2 || c.ScanTimeout != 2*time.Second {
		t.Fatalf("%+v", c)
	}
}

func TestCatalogAddress(t *testing.T) {
	clearConfig(t)
	c, err := Load()
	if err != nil || c.ThreatGRPCAddress != "" {
		t.Fatalf("default: %+v %v", c, err)
	}
	t.Setenv("THREAT_GRPC_ADDR", "app_api:50051")
	c, err = Load()
	if err != nil || c.ThreatGRPCAddress != "app_api:50051" {
		t.Fatalf("override: %+v %v", c, err)
	}
}
