package core

import "time"

type Config struct {
	TokenExpiry        time.Duration
	RefreshTokenExpiry time.Duration
	KeySize            int
	Algorithm          string
	MaxCacheSize       int
	CleanupInterval    time.Duration
	EnableMetrics      bool
}

// ConfigBuilder provides a fluent interface for building Config
type ConfigBuilder struct {
	config *Config
}

// NewConfigBuilder creates a new config builder with defaults
func NewConfigBuilder() *ConfigBuilder {
	return &ConfigBuilder{
		config: &Config{
			TokenExpiry:        24 * time.Hour,
			RefreshTokenExpiry: 7 * 24 * time.Hour,
			KeySize:            2048,
			Algorithm:          "RS256",
			MaxCacheSize:       100,
			CleanupInterval:    time.Hour,
			EnableMetrics:      false,
		},
	}
}

// WithTokenExpiry sets the access token expiry
func (cb *ConfigBuilder) WithTokenExpiry(expiry time.Duration) *ConfigBuilder {
	cb.config.TokenExpiry = expiry
	return cb
}

// WithRefreshTokenExpiry sets the refresh token expiry
func (cb *ConfigBuilder) WithRefreshTokenExpiry(expiry time.Duration) *ConfigBuilder {
	cb.config.RefreshTokenExpiry = expiry
	return cb
}

// WithKeySize sets the RSA key size
func (cb *ConfigBuilder) WithKeySize(size int) *ConfigBuilder {
	cb.config.KeySize = size
	return cb
}

// WithAlgorithm sets the signing algorithm
func (cb *ConfigBuilder) WithAlgorithm(algorithm string) *ConfigBuilder {
	cb.config.Algorithm = algorithm
	return cb
}

// WithCacheSettings configures caching
func (cb *ConfigBuilder) WithCacheSettings(maxSize int, cleanupInterval time.Duration) *ConfigBuilder {
	cb.config.MaxCacheSize = maxSize
	cb.config.CleanupInterval = cleanupInterval
	return cb
}

// WithMetrics enables or disables metrics collection
func (cb *ConfigBuilder) WithMetrics(enabled bool) *ConfigBuilder {
	cb.config.EnableMetrics = enabled
	return cb
}

// Build creates the final configuration
func (cb *ConfigBuilder) Build() *Config {
	// Validate configuration
	if cb.config.TokenExpiry <= 0 {
		cb.config.TokenExpiry = 24 * time.Hour
	}
	if cb.config.RefreshTokenExpiry <= 0 {
		cb.config.RefreshTokenExpiry = 7 * 24 * time.Hour
	}
	if cb.config.KeySize < 2048 {
		cb.config.KeySize = 2048
	}

	return cb.config
}

// DefaultConfig returns a default configuration
func DefaultConfig() *Config {
	return NewConfigBuilder().Build()
}

// ProductionConfig returns a production-ready configuration
func ProductionConfig() *Config {
	return NewConfigBuilder().
		WithTokenExpiry(2*time.Hour).
		WithRefreshTokenExpiry(30*24*time.Hour).
		WithKeySize(4096).
		WithCacheSettings(1000, 30*time.Minute).
		WithMetrics(true).
		Build()
}
