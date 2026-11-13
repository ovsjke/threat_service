package config

import (
	"fmt"
	"os"
)

type Config struct {
	ApiPort, ApiURL, DatabaseURL string
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
	return config, nil

}
