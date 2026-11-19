package config

import (
	"testing"
	"time"
)

func TestLoadConfig(t *testing.T) {
	tests := []struct {
		name        string
		envVars     map[string]string
		expected    Config
		expectError bool
	}{
		{
			name: "valid env",
			envVars: map[string]string{
				"API_PORT": ":8080",
				"API_URL":  "http://localhost:8080",
				"DB_URL":   "postgres://user:password@localhost:5432/dbname",
			},
			expected: Config{
				ApiPort:     ":8080",
				ApiURL:      "http://localhost:8080",
				DatabaseURL: "postgres://user:password@localhost:5432/dbname",
			},
			expectError: false,
		},
		{
			name: "missing DB_URL",
			envVars: map[string]string{
				"API_PORT": ":8080",
				"API_URL":  "http://localhost:8080",
			},
			expected:    Config{},
			expectError: true,
		},
		{
			name: "missing API_PORT and API_URL",
			envVars: map[string]string{
				"DB_URL": "postgres://user:password@localhost:5432/dbname",
			},
			expected: Config{
				ApiPort:     ":8080",
				ApiURL:      "http://localhost:8080",
				DatabaseURL: "postgres://user:password@localhost:5432/dbname",
			},
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for _, key := range []string{"API_PORT", "API_URL", "DB_URL"} {
				t.Setenv(key, "")
			}

			for key, value := range tt.envVars {
				t.Setenv(key, value)
			}

			config, err := Load()
			if (err != nil) != tt.expectError {
				t.Errorf("Load() error = %v, expectError %v", err, tt.expectError)
				return
			}

			if tt.expectError {
				return
			}

			if config.ApiPort != tt.expected.ApiPort ||
				config.ApiURL != tt.expected.ApiURL ||
				config.DatabaseURL != tt.expected.DatabaseURL {
				t.Errorf("Load() = %+v, expected %+v", config, tt.expected)
			}
		})
	}
}

func TestTimeoutConfiguration(t *testing.T) {
	t.Setenv("DB_URL", "postgres://test:test@localhost/test")
	for _, name := range []string{"API_READ_HEADER_TIMEOUT", "API_READ_TIMEOUT", "API_WRITE_TIMEOUT", "API_IDLE_TIMEOUT", "API_SHUTDOWN_TIMEOUT"} {
		t.Setenv(name, "")
	}
	defaults, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if defaults.ReadHeaderTimeout != 5*time.Second || defaults.ReadTimeout != 15*time.Second ||
		defaults.WriteTimeout != 120*time.Second || defaults.IdleTimeout != 60*time.Second || defaults.ShutdownTimeout != 5*time.Second {
		t.Fatal("timeout defaults changed")
	}
	for _, name := range []string{"API_READ_HEADER_TIMEOUT", "API_READ_TIMEOUT", "API_WRITE_TIMEOUT", "API_IDLE_TIMEOUT", "API_SHUTDOWN_TIMEOUT"} {
		t.Run(name, func(t *testing.T) {
			t.Setenv(name, "2s")
			cfg, err := Load()
			if err != nil {
				t.Fatal(err)
			}
			got := map[string]time.Duration{
				"API_READ_HEADER_TIMEOUT": cfg.ReadHeaderTimeout,
				"API_READ_TIMEOUT":        cfg.ReadTimeout,
				"API_WRITE_TIMEOUT":       cfg.WriteTimeout,
				"API_IDLE_TIMEOUT":        cfg.IdleTimeout,
				"API_SHUTDOWN_TIMEOUT":    cfg.ShutdownTimeout,
			}[name]
			if got != 2*time.Second {
				t.Fatalf("override not applied: %v", got)
			}
			for _, invalid := range []string{"invalid", "0s", "-1s", "25h"} {
				t.Setenv(name, invalid)
				if _, err := Load(); err == nil {
					t.Fatalf("accepted invalid timeout %q", invalid)
				}
			}
		})
	}
}
