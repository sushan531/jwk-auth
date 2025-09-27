package service

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jws"
	"github.com/lestrrat-go/jwx/v3/jwt"
	"github.com/sushan531/jwk-auth/core"
	"github.com/sushan531/jwk-auth/helpers"
)

type Auth interface {
	GenerateAccessRefreshTokenPair(input map[string]any, refresh map[string]any, keyPrefix string) (string, string, error)
	GenerateToken(input map[string]any, keyPrefix string, expiry time.Duration, purpose string) (string, error)
	GenerateTokenFromRefreshToken(input map[string]any, keyPrefix string, expiry time.Duration) (string, error)
	MarshalJwkSet() ([]byte, error)
	ParseJsonBytes(jwkSetJSON string) error
	VerifyTokenSignatureAndGetClaims(token string) (map[string]any, error)
}

type auth struct {
	config     *core.Config
	jwkManager core.JwkManager
	jwtManager core.JwtManager
}

func NewAuth(jwkManager core.JwkManager, jwtManager core.JwtManager, config *core.Config) Auth {
	return &auth{
		config:     config,
		jwkManager: jwkManager,
		jwtManager: jwtManager,
	}
}

// GenerateAccessRefreshTokenPair is used when user login or register, it will generate access token and refresh token
func (a *auth) GenerateAccessRefreshTokenPair(input map[string]any, refresh map[string]any, keyPrefix string) (string, string, error) {
	accessToken, accessTokenGenErr := a.GenerateToken(input, keyPrefix, a.config.TokenExpiry, "access")
	if accessTokenGenErr != nil {
		return "", "", accessTokenGenErr
	}
	refreshToken, refreshTokenGenErr := a.GenerateToken(refresh, keyPrefix, a.config.RefreshTokenExpiry, "refresh")
	if refreshTokenGenErr != nil {
		return "", "", refreshTokenGenErr
	}
	return accessToken, refreshToken, nil
}

// GenerateTokenFromRefreshToken generates token from refresh token so no need to delete old private key, Directly create a new token and return
func (a *auth) GenerateTokenFromRefreshToken(input map[string]any, keyPrefix string, expiry time.Duration) (string, error) {

	// Sanitize keyPrefix to prevent injection
	if !helpers.IsValidKeyPrefix(keyPrefix) {
		return "", fmt.Errorf("invalid keyPrefix format")
	}

	if input == nil {
		return "", fmt.Errorf("input claims cannot be nil")
	}
	unsignedToken, err := a.jwtManager.GenerateUnsignedToken(input, expiry)
	if err != nil {
		return "", err
	}
	privateKey, kid, err := a.jwkManager.GetPrivateKeyWithId(keyPrefix)

	errSettingKeyId := unsignedToken.Set("kid", kid)
	if errSettingKeyId != nil {
		return "", fmt.Errorf("failed to set key id in token: %w", errSettingKeyId)
	}

	signedToken, err := jwt.Sign(unsignedToken, jwt.WithKey(jwa.RS256(), privateKey))
	if err != nil {
		return "", fmt.Errorf("failed to sign token: %w", err)
	}

	return string(signedToken), nil

}

// GenerateToken generates token for user login or register, it will generate access token or refresh token
// This will delete old private key and generate new one for access token.
// For refresh token it will generate using existing private key
func (a *auth) GenerateToken(input map[string]any, keyPrefix string, expiry time.Duration, purpose string) (string, error) {
	// Validate inputs
	if keyPrefix == "" {
		return "", fmt.Errorf("keyPrefix cannot be empty")
	}

	// Sanitize keyPrefix to prevent injection
	if !helpers.IsValidKeyPrefix(keyPrefix) {
		return "", fmt.Errorf("invalid keyPrefix format")
	}

	if input == nil {
		return "", fmt.Errorf("input claims cannot be nil")
	}
	// This will invalidate any existing tokens for this device type
	if purpose != "access" && purpose != "refresh" {
		return "", fmt.Errorf("purpose must be 'access' or 'refresh'")
	}
	if purpose == "access" {
		err := a.jwkManager.AddOrReplaceKeyToSet(keyPrefix)
		if err != nil {
			return "", fmt.Errorf("failed to rotate key for device '%s' (this invalidates previous sessions): %w", keyPrefix, err)
		}
	}
	unsignedToken, err := a.jwtManager.GenerateUnsignedToken(input, expiry)
	if err != nil {
		return "", err
	}
	privateKey, kid, err := a.jwkManager.GetPrivateKeyWithId(keyPrefix)

	errSettingKeyId := unsignedToken.Set("kid", kid)
	if errSettingKeyId != nil {
		return "", fmt.Errorf("failed to set key id in token: %w", errSettingKeyId)
	}

	signedToken, err := jwt.Sign(unsignedToken, jwt.WithKey(jwa.RS256(), privateKey))
	if err != nil {
		return "", fmt.Errorf("failed to sign token: %w", err)
	}

	return string(signedToken), nil

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
