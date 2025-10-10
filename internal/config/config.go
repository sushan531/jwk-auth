package config

import (
	"os"
	"strconv"

	"github.com/sushan531/jwk-auth/internal/database"
)

type Config struct {
	Database database.Config
}

func LoadConfig() *Config {
	return &Config{
		Database: database.Config{
			Host:     getEnv("DB_HOST", "localhost"),
			Port:     getEnvAsInt("DB_PORT", 5432),
			User:     getEnv("DB_USER", "myuser"),
			Password: getEnv("DB_PASSWORD", "mypassword"),
			DBName:   getEnv("DB_NAME", "mydb"),
			SSLMode:  getEnv("DB_SSLMODE", "disable"),
		},
	}
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func getEnvAsInt(key string, defaultValue int) int {
	if value := os.Getenv(key); value != "" {
		if intValue, err := strconv.Atoi(value); err == nil {
			return intValue
		}
	}
	return defaultValue
}
