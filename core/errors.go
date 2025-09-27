package core

import (
	"errors"
	"fmt"
)

// Custom error types for better error handling
var (
	ErrInvalidKeyPrefix     = errors.New("invalid key prefix format")
	ErrKeyNotFound          = errors.New("key not found in JWK set")
	ErrJWKSetNotInitialized = errors.New("JWK set not initialized")
	ErrInvalidTokenPurpose  = errors.New("invalid token purpose")
	ErrTokenExpired         = errors.New("token has expired")
	ErrInvalidTokenFormat   = errors.New("invalid token format")
	ErrMissingKidClaim      = errors.New("token missing required 'kid' claim")
	ErrInvalidKidClaim      = errors.New("'kid' claim must be a non-empty string")
)

// AuthError wraps errors with additional context
type AuthError struct {
	Op  string // operation that failed
	Err error  // underlying error
}

func (e *AuthError) Error() string {
	return fmt.Sprintf("auth: %s: %v", e.Op, e.Err)
}

func (e *AuthError) Unwrap() error {
	return e.Err
}

// NewAuthError creates a new AuthError
func NewAuthError(op string, err error) *AuthError {
	return &AuthError{Op: op, Err: err}
}
