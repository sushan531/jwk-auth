package service

import (
	"crypto/rsa"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/sushan531/jwk-auth/core/config"
	"github.com/sushan531/jwk-auth/core/manager"
)

// TokenPair represents an access/refresh token pair
type TokenPair struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int64  `json:"expires_in"`
}

type TokenService interface {
	// Flexible claims methods
	GenerateTokenPairWithKeyID(claims map[string]interface{}, keyID string) (*TokenPair, error)
	RefreshTokensWithKeyID(refreshToken string, newClaims map[string]interface{}, keyID string) (*TokenPair, error)

	// Token verification methods
	GetPublicKeys() ([]*rsa.PublicKey, error)
	VerifyToken(token string) (map[string]interface{}, error)
	VerifyRefreshToken(token string) (map[string]interface{}, error)
	ExtractKeyIDFromToken(token string) (string, error)
}

type tokenService struct {
	jwtManager manager.JwtManager
	jwkManager manager.JwkManager
	config     *config.Config
}

func NewTokenService(jwtManager manager.JwtManager, jwkManager manager.JwkManager, cfg *config.Config) TokenService {
	return &tokenService{
		jwtManager: jwtManager,
		jwkManager: jwkManager,
		config:     cfg,
	}
}

func (a tokenService) GetPublicKeys() ([]*rsa.PublicKey, error) {
	return a.jwkManager.GetPublicKeys()
}

// Session-based token generation with flexible claims
func (a tokenService) GenerateTokenPairWithKeyID(claims map[string]interface{}, keyID string) (*TokenPair, error) {
	// Prepare access token claims
	accessClaims := make(map[string]interface{})
	for k, v := range claims {
		accessClaims[k] = v
	}
	accessClaims["token_type"] = "access"

	accessToken, err := a.jwtManager.GenerateAccessTokenWithKeyID(accessClaims, keyID)
	if err != nil {
		return nil, fmt.Errorf("failed to generate access token: %w", err)
	}

	// Prepare refresh token claims (typically minimal - just user identifier)
	refreshClaims := make(map[string]interface{})
	// Copy only essential claims for refresh token (you can customize this logic)
	if userID, exists := claims["user_id"]; exists {
		refreshClaims["user_id"] = userID
	}
	refreshClaims["device_fingerprint"] = claims["device_fingerprint"]
	refreshClaims["token_type"] = "refresh"

	refreshToken, err := a.jwtManager.GenerateRefreshTokenWithKeyID(refreshClaims, keyID)
	if err != nil {
		return nil, fmt.Errorf("failed to generate refresh token: %w", err)
	}

	return &TokenPair{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		TokenType:    "Bearer",
		ExpiresIn:    int64(a.config.JWT.AccessTokenDuration.Seconds()), // Duration in seconds
	}, nil
}

func (a tokenService) RefreshTokensWithKeyID(refreshToken string, newClaims map[string]interface{}, keyID string) (*TokenPair, error) {
	// Verify the refresh token (this validates the token and extracts claims)
	tokenClaims, err := a.VerifyRefreshToken(refreshToken)
	if err != nil {
		return nil, fmt.Errorf("invalid refresh token: %w", err)
	}

	// Extract device type from keyID (format: deviceType-userID-timestamp)
	deviceType, err := a.extractDeviceTypeFromKeyID(keyID)
	if err != nil {
		return nil, fmt.Errorf("failed to extract device type from keyID: %w", err)
	}

	// Get user identifier from token claims (try both user_id and id)
	var userID uuid.UUID
	if uid, exists := tokenClaims["user_id"]; exists {
		if uidStr, ok := uid.(string); ok {
			userID, _ = uuid.Parse(uidStr)
		}
	} else if id, exists := tokenClaims["id"]; exists {
		if idStr, ok := id.(string); ok {
			userID, _ = uuid.Parse(idStr)
		}
	}

	if userID == uuid.Nil {
		return nil, fmt.Errorf("no valid user identifier found in refresh token")
	}

	// Create a new session key for the same device type (this will replace the old key)
	newKeyID, err := a.jwkManager.CreateSessionKey(userID.String(), deviceType)
	if err != nil {
		return nil, fmt.Errorf("failed to create new session key: %w", err)
	}

	// Merge original token claims with new claims (new claims take precedence)
	finalClaims := make(map[string]interface{})
	for k, v := range tokenClaims {
		finalClaims[k] = v
	}
	for k, v := range newClaims {
		finalClaims[k] = v
	}

	// Generate new token pair with the new key ID
	return a.GenerateTokenPairWithKeyID(finalClaims, newKeyID)
}

func (a tokenService) VerifyToken(token string) (map[string]interface{}, error) {
	return a.verifyTokenWithType(token, "access")
}

func (a tokenService) VerifyRefreshToken(token string) (map[string]interface{}, error) {
	return a.verifyTokenWithType(token, "refresh")
}

func (a tokenService) verifyTokenWithType(token string, expectedType string) (map[string]interface{}, error) {
	claimsInMap, err := a.jwtManager.VerifyTokenSignatureAndGetClaims(token)
	if err != nil {
		return nil, fmt.Errorf("failed to verify token signature: %w", err)
	}

	// Check token type
	tokenType, ok := claimsInMap["token_type"].(string)
	if !ok || tokenType != expectedType {
		return nil, fmt.Errorf("invalid token type: expected %s, got %s", expectedType, tokenType)
	}

	// Check expiration
	exp, ok := claimsInMap["exp"].(float64)
	if !ok {
		return nil, fmt.Errorf("missing or invalid expiration claim")
	}

	if time.Now().Unix() > int64(exp) {
		return nil, fmt.Errorf("token has expired")
	}

	return claimsInMap, nil
}

func (a tokenService) ExtractKeyIDFromToken(token string) (string, error) {
	return a.jwtManager.ExtractKeyIDFromToken(token)
}

// extractDeviceTypeFromKeyID extracts the device type from a keyID
// KeyID format: deviceType-userID-timestamp
func (a tokenService) extractDeviceTypeFromKeyID(keyID string) (string, error) {
	// Split the keyID by '-' to extract components
	parts := strings.Split(keyID, "-")
	if len(parts) < 3 {
		return "", fmt.Errorf("invalid keyID format: expected deviceType-userID-timestamp, got %s", keyID)
	}

	// The device type is the first part
	return parts[0], nil
}
