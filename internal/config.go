package internal

import "time"

type Config struct {
	TokenExpiry time.Duration
	KeySize     int
	Algorithm   string
}

func DefaultConfig() *Config {
	return &Config{
		TokenExpiry: 24 * time.Hour,
		KeySize:     2048,
		Algorithm:   "RS256",
	}
}
