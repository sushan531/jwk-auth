package config

import (
	"os"
	"strconv"
	"time"

	"github.com/sushan531/jwk-auth/internal/database"
)

type Config struct {
	Database database.Config
	JWT      JWTConfig
}

type JWTConfig struct {
	AccessTokenDuration  time.Duration
	RefreshTokenDuration time.Duration
	RSAKeySize           int
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
		JWT: JWTConfig{
			AccessTokenDuration:  getEnvAsDuration("JWT_ACCESS_TOKEN_DURATION", 15*time.Minute),
			RefreshTokenDuration: getEnvAsDuration("JWT_REFRESH_TOKEN_DURATION", 7*24*time.Hour),
			RSAKeySize:           getEnvAsInt("JWT_RSA_KEY_SIZE", 2048),
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

func getEnvAsDuration(key string, defaultValue time.Duration) time.Duration {
	if value := os.Getenv(key); value != "" {
		if duration, err := time.ParseDuration(value); err == nil {
			return duration
		}
	}
	return defaultValue
}
