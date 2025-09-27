package core

import (
	"fmt"
	"regexp"
	"time"
)

const (
	MaxKeyPrefixLength = 50
	MinKeyPrefixLength = 1
	MaxClaimsSize      = 1024 * 10 // 10KB max claims size
)

var keyPrefixRegex = regexp.MustCompile(`^[a-zA-Z0-9-_]+$`)

// Validator provides validation methods
type Validator struct{}

// NewValidator creates a new validator instance
func NewValidator() *Validator {
	return &Validator{}
}

// ValidateKeyPrefix validates key prefix format and length
func (v *Validator) ValidateKeyPrefix(keyPrefix string) error {
	if len(keyPrefix) < MinKeyPrefixLength || len(keyPrefix) > MaxKeyPrefixLength {
		return fmt.Errorf("%w: length must be between %d and %d characters",
			ErrInvalidKeyPrefix, MinKeyPrefixLength, MaxKeyPrefixLength)
	}

	if !keyPrefixRegex.MatchString(keyPrefix) {
		return fmt.Errorf("%w: only alphanumeric characters, hyphens, and underscores allowed",
			ErrInvalidKeyPrefix)
	}

	return nil
}

// ValidateTokenPurpose validates token purpose
func (v *Validator) ValidateTokenPurpose(purpose string) error {
	if purpose != "access" && purpose != "refresh" {
		return fmt.Errorf("%w: must be 'access' or 'refresh'", ErrInvalidTokenPurpose)
	}
	return nil
}

// ValidateClaims validates token claims
func (v *Validator) ValidateClaims(claims map[string]any) error {
	if claims == nil {
		return fmt.Errorf("claims cannot be nil")
	}

	// Estimate claims size (rough approximation)
	claimsSize := 0
	for k, v := range claims {
		claimsSize += len(k) + estimateValueSize(v)
	}

	if claimsSize > MaxClaimsSize {
		return fmt.Errorf("claims size exceeds maximum allowed size of %d bytes", MaxClaimsSize)
	}

	return nil
}

// ValidateExpiry validates token expiry duration
func (v *Validator) ValidateExpiry(expiry time.Duration) error {
	if expiry <= 0 {
		return fmt.Errorf("expiry must be positive")
	}

	if expiry > 365*24*time.Hour { // Max 1 year
		return fmt.Errorf("expiry cannot exceed 1 year")
	}

	return nil
}

func estimateValueSize(v any) int {
	switch val := v.(type) {
	case string:
		return len(val)
	case int, int32, int64, float32, float64:
		return 8
	case bool:
		return 1
	default:
		return 50 // rough estimate for complex types
	}
}
