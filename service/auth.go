package service

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jws"
	"github.com/lestrrat-go/jwx/v3/jwt"
	"github.com/sushan531/jwk-auth/core"
)

type Auth interface {
	GenerateAccessRefreshTokenPair(input map[string]any, refresh map[string]any, keyPrefix string) (string, string, error)
	GenerateToken(input map[string]any, keyPrefix string, expiry time.Duration, purpose string) (string, error)
	GenerateTokenFromRefreshToken(input map[string]any, keyPrefix string, expiry time.Duration) (string, error)
	MarshalJwkSet() ([]byte, error)
	ParseJsonBytes(jwkSetJSON string) error
	VerifyTokenSignatureAndGetClaims(token string) (map[string]any, error)
	// New methods for better functionality
	ValidateToken(token string, expectedPurpose string) (*TokenClaims, error)
	RevokeTokensForDevice(keyPrefix string) error
}

type TokenClaims struct {
	Claims    map[string]any `json:"claims"`
	Purpose   string         `json:"purpose"`
	ExpiresAt time.Time      `json:"expires_at"`
	IssuedAt  time.Time      `json:"issued_at"`
	KeyID     string         `json:"key_id"`
}

type auth struct {
	config     *core.Config
	jwkManager core.JwkManager
	jwtManager core.JwtManager
	validator  *core.Validator
}

func NewAuth(jwkManager core.JwkManager, jwtManager core.JwtManager, config *core.Config) Auth {
	return &auth{
		config:     config,
		jwkManager: jwkManager,
		jwtManager: jwtManager,
		validator:  core.NewValidator(),
	}
}

// Refactored to eliminate duplication
func (a *auth) generateSignedToken(claims map[string]any, keyPrefix string, expiry time.Duration, rotateKey bool) (string, error) {
	// Validate inputs
	if err := a.validator.ValidateKeyPrefix(keyPrefix); err != nil {
		return "", core.NewAuthError("generateSignedToken", err)
	}

	if err := a.validator.ValidateClaims(claims); err != nil {
		return "", core.NewAuthError("generateSignedToken", err)
	}

	if err := a.validator.ValidateExpiry(expiry); err != nil {
		return "", core.NewAuthError("generateSignedToken", err)
	}

	// Rotate key if needed (for access tokens)
	if rotateKey {
		if err := a.jwkManager.AddOrReplaceKeyToSet(keyPrefix); err != nil {
			return "", core.NewAuthError("generateSignedToken", fmt.Errorf("failed to rotate key for device '%s': %w", keyPrefix, err))
		}
	}

	// Generate unsigned token
	unsignedToken, err := a.jwtManager.GenerateUnsignedToken(claims, expiry)
	if err != nil {
		return "", core.NewAuthError("generateSignedToken", err)
	}

	// Get private key and sign
	privateKey, kid, err := a.jwkManager.GetPrivateKeyWithId(keyPrefix)
	if err != nil {
		return "", core.NewAuthError("generateSignedToken", err)
	}

	if err := unsignedToken.Set("kid", kid); err != nil {
		return "", core.NewAuthError("generateSignedToken", fmt.Errorf("failed to set key id in token: %w", err))
	}

	signedToken, err := jwt.Sign(unsignedToken, jwt.WithKey(jwa.RS256(), privateKey))
	if err != nil {
		return "", core.NewAuthError("generateSignedToken", fmt.Errorf("failed to sign token: %w", err))
	}

	return string(signedToken), nil
}

func (a *auth) GenerateAccessRefreshTokenPair(input map[string]any, refresh map[string]any, keyPrefix string) (string, string, error) {
	// Generate access token (with key rotation)
	accessToken, err := a.generateSignedToken(input, keyPrefix, a.config.TokenExpiry, true)
	if err != nil {
		return "", "", fmt.Errorf("failed to generate access token: %w", err)
	}

	// Generate refresh token (without key rotation)
	refreshToken, err := a.generateSignedToken(refresh, keyPrefix, a.config.RefreshTokenExpiry, false)
	if err != nil {
		return "", "", fmt.Errorf("failed to generate refresh token: %w", err)
	}

	return accessToken, refreshToken, nil
}

func (a *auth) GenerateToken(input map[string]any, keyPrefix string, expiry time.Duration, purpose string) (string, error) {
	if err := a.validator.ValidateTokenPurpose(purpose); err != nil {
		return "", core.NewAuthError("GenerateToken", err)
	}

	// Add purpose to claims
	if input == nil {
		input = make(map[string]any)
	}
	input["purpose"] = purpose

	// Rotate key only for access tokens
	rotateKey := purpose == "access"
	return a.generateSignedToken(input, keyPrefix, expiry, rotateKey)
}

func (a *auth) GenerateTokenFromRefreshToken(input map[string]any, keyPrefix string, expiry time.Duration) (string, error) {
	// Add purpose to claims
	if input == nil {
		input = make(map[string]any)
	}
	input["purpose"] = "access"

	// Don't rotate key when generating from refresh token
	return a.generateSignedToken(input, keyPrefix, expiry, false)
}

// Enhanced token validation with structured response
func (a *auth) ValidateToken(token string, expectedPurpose string) (*TokenClaims, error) {
	claims, err := a.VerifyTokenSignatureAndGetClaims(token)
	if err != nil {
		return nil, err
	}
	// Extract and validate purpose
	purpose, ok := claims["purpose"].(string)
	if !ok {
		purpose = "access" // Default for backward compatibility
	}

	if expectedPurpose != "" && purpose != expectedPurpose {
		return nil, core.NewAuthError("ValidateToken", fmt.Errorf("expected purpose '%s', got '%s'", expectedPurpose, purpose))
	}

	// Extract timing information
	var expiresAt, issuedAt time.Time
	if exp, exists := claims["exp"]; exists {
		if expFloat, ok := exp.(float64); ok {
			expiresAt = time.Unix(int64(expFloat), 0)
		}
	}
	if iat, exists := claims["iat"]; exists {
		if iatFloat, ok := iat.(float64); ok {
			issuedAt = time.Unix(int64(iatFloat), 0)
		}
	}

	keyID, _ := claims["kid"].(string)

	return &TokenClaims{
		Claims:    claims,
		Purpose:   purpose,
		ExpiresAt: expiresAt,
		IssuedAt:  issuedAt,
		KeyID:     keyID,
	}, nil
}

func (a *auth) RevokeTokensForDevice(keyPrefix string) error {
	return a.jwkManager.AddOrReplaceKeyToSet(keyPrefix)
}

// MarshalJwkSet marshals the JWK set to JSON for storage purpose
// Do I need encryption here ?
func (a *auth) MarshalJwkSet() ([]byte, error) {
	jwkSet, err := a.jwkManager.GetJwkSetForStorage()
	if err != nil {
		return nil, err
	}
	return jwkSet, nil
}

// ParseJsonBytes parses the JWK set JSON string and updates the JWK set
// Do I need decryption here ? i.e First decrypt then parse and initialize the jwk set
func (a *auth) ParseJsonBytes(jwkSetJSON string) error {
	err := a.jwkManager.GetJwkSetFromStorage(jwkSetJSON)
	if err != nil {
		return err
	}
	return nil
}

// VerifyTokenSignatureAndGetClaims verifies the token signature and returns the claims if valid
func (a *auth) VerifyTokenSignatureAndGetClaims(jwtToken string) (map[string]any, error) {
	parsedToken, err := jws.Parse([]byte(jwtToken))
	if err != nil {
		return nil, fmt.Errorf("failed to parse JWT: %w", err)
	}

	var payload map[string]any
	payloadInBytes := parsedToken.Payload()

	errUnmarshallingData := json.Unmarshal(payloadInBytes, &payload)
	if errUnmarshallingData != nil {
		return nil, errUnmarshallingData
	}

	// Safe type assertion with validation
	kidInterface, exists := payload["kid"]
	if !exists {
		return nil, fmt.Errorf("token missing required 'kid' claim")
	}

	kid, ok := kidInterface.(string)
	if !ok {
		return nil, fmt.Errorf("'kid' claim must be a string, got %T", kidInterface)
	}

	if kid == "" {
		return nil, fmt.Errorf("'kid' claim cannot be empty")
	}

	publicKey, errFindingPublicKey := a.jwkManager.GetPublicKeyBy(kid)
	if errFindingPublicKey != nil {
		return nil, errFindingPublicKey
	}

	_, errValidatingToken := jwt.Parse([]byte(jwtToken), jwt.WithKey(jwa.RS256(), publicKey))
	if errValidatingToken != nil {
		return nil, fmt.Errorf("failed to verify token signature: %w", errValidatingToken)
	}

	// Validate expiration
	if exp, exists := payload["exp"]; exists {
		if expFloat, ok := exp.(float64); ok {
			expTime := time.Unix(int64(expFloat), 0)
			if time.Now().After(expTime) {
				return nil, fmt.Errorf("token has expired")
			}
		}
	}

	return payload, nil
}
