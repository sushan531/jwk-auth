package service

import (
	"github.com/sushan531/jwk-auth/core"
)

// TokenService handles token-specific operations
type TokenService interface {
	CreateAccessToken(claims map[string]any, keyPrefix string) (string, error)
	CreateRefreshToken(claims map[string]any, keyPrefix string) (string, error)
	RefreshAccessToken(refreshToken string, newClaims map[string]any, keyPrefix string) (string, error)
	ValidateAccessToken(token string) (*TokenClaims, error)
	ValidateRefreshToken(token string) (*TokenClaims, error)
}

type tokenService struct {
	auth   Auth
	config *core.Config
}

func NewTokenService(auth Auth, config *core.Config) TokenService {
	return &tokenService{
		auth:   auth,
		config: config,
	}
}

func (ts *tokenService) CreateAccessToken(claims map[string]any, keyPrefix string) (string, error) {
	if claims == nil {
		claims = make(map[string]any)
	}
	claims["purpose"] = "access"
	return ts.auth.GenerateToken(claims, keyPrefix, ts.config.TokenExpiry, "access")
}

func (ts *tokenService) CreateRefreshToken(claims map[string]any, keyPrefix string) (string, error) {
	if claims == nil {
		claims = make(map[string]any)
	}
	claims["purpose"] = "refresh"
	return ts.auth.GenerateToken(claims, keyPrefix, ts.config.RefreshTokenExpiry, "refresh")
}

func (ts *tokenService) RefreshAccessToken(refreshToken string, newClaims map[string]any, keyPrefix string) (string, error) {
	// Validate refresh token first
	_, err := ts.ValidateRefreshToken(refreshToken)
	if err != nil {
		return "", err
	}

	return ts.auth.GenerateTokenFromRefreshToken(newClaims, keyPrefix, ts.config.TokenExpiry)
}

func (ts *tokenService) ValidateAccessToken(token string) (*TokenClaims, error) {
	return ts.auth.ValidateToken(token, "access")
}

func (ts *tokenService) ValidateRefreshToken(token string) (*TokenClaims, error) {
	return ts.auth.ValidateToken(token, "refresh")
}
