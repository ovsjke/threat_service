package config

import (
	"testing"
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
