package core

import "time"

type Config struct {
	TokenExpiry        time.Duration
	RefreshTokenExpiry time.Duration
	KeySize            int
	Algorithm          string
}

func DefaultConfig() *Config {
	return &Config{
		TokenExpiry:        24 * time.Hour,     // 1 day
		RefreshTokenExpiry: 7 * 24 * time.Hour, // 7 days
		KeySize:            2048,
		Algorithm:          "RS256",
	}
}
