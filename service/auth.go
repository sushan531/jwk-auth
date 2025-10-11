package service

import (
	"crypto/rsa"
	"fmt"
	"strings"
	"time"

	"github.com/sushan531/jwk-auth/internal/config"
	"github.com/sushan531/jwk-auth/internal/manager"
	"github.com/sushan531/jwk-auth/model"
)

type AuthService interface {
	// Session-based methods
	GenerateTokenPairWithKeyID(user *model.User, keyID string) (*model.TokenPair, error)
	RefreshTokensWithKeyID(refreshToken string, username string, keyID string) (*model.TokenPair, error)

	// Common methods
	GetPublicKeys() ([]*rsa.PublicKey, error)
	VerifyToken(token string) (*model.User, error)
	VerifyRefreshToken(token string) (*model.User, error)
	ExtractKeyIDFromToken(token string) (string, error)
}

type authService struct {
	jwtManager manager.JwtManager
	jwkManager manager.JwkManager
	config     *config.Config
}

func NewAuthService(jwtManager manager.JwtManager, jwkManager manager.JwkManager, cfg *config.Config) AuthService {
	return &authService{
		jwtManager: jwtManager,
		jwkManager: jwkManager,
		config:     cfg,
	}
}

func (a authService) GetPublicKeys() ([]*rsa.PublicKey, error) {
	return a.jwkManager.GetPublicKeys()
}

// Session-based token generation
func (a authService) GenerateTokenPairWithKeyID(user *model.User, keyID string) (*model.TokenPair, error) {
	// Generate access token claims (includes username)
	accessClaims := model.NewTokenClaims(user, "access", a.config.JWT.AccessTokenDuration)
	accessToken, err := a.jwtManager.GenerateAccessTokenWithKeyID(accessClaims.ToMap(), keyID)
	if err != nil {
		return nil, fmt.Errorf("failed to generate access token: %w", err)
	}

	// Generate refresh token claims (only user_id)
	refreshClaims := model.NewRefreshTokenClaims(user.Id, a.config.JWT.RefreshTokenDuration)
	refreshToken, err := a.jwtManager.GenerateRefreshTokenWithKeyID(refreshClaims.ToMap(), keyID)
	if err != nil {
		return nil, fmt.Errorf("failed to generate refresh token: %w", err)
	}

	return &model.TokenPair{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		TokenType:    "Bearer",
		ExpiresIn:    int64(a.config.JWT.AccessTokenDuration.Seconds()), // Duration in seconds
	}, nil
}

func (a authService) RefreshTokensWithKeyID(refreshToken string, username string, keyID string) (*model.TokenPair, error) {
	// Verify the refresh token (this only validates the token and extracts user_id)
	userFromToken, err := a.VerifyRefreshToken(refreshToken)
	if err != nil {
		return nil, fmt.Errorf("invalid refresh token: %w", err)
	}

	// Extract device type from keyID (format: deviceType-userID-timestamp)
	deviceType, err := a.extractDeviceTypeFromKeyID(keyID)
	if err != nil {
		return nil, fmt.Errorf("failed to extract device type from keyID: %w", err)
	}

	// Create a new session key for the same device type (this will replace the old key)
	newKeyID, err := a.jwkManager.CreateSessionKey(userFromToken.Id, deviceType)
	if err != nil {
		return nil, fmt.Errorf("failed to create new session key: %w", err)
	}

	// Create user object with provided username for new access token
	user := &model.User{
		Id:       userFromToken.Id,
		Username: username,
	}

	// Generate new token pair with the new key ID
	return a.GenerateTokenPairWithKeyID(user, newKeyID)
}

func (a authService) VerifyToken(token string) (*model.User, error) {
	return a.verifyTokenWithType(token, "access")
}

func (a authService) VerifyRefreshToken(token string) (*model.User, error) {
	return a.verifyTokenWithType(token, "refresh")
}

func (a authService) verifyTokenWithType(token string, expectedType string) (*model.User, error) {
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

	// Extract user information
	userID, ok := claimsInMap["user_id"].(float64)
	if !ok {
		return nil, fmt.Errorf("missing or invalid user_id claim")
	}

	// For refresh tokens, username is optional (not included)
	// For access tokens, username is required
	var username string
	if expectedType == "access" {
		username, ok = claimsInMap["username"].(string)
		if !ok {
			return nil, fmt.Errorf("missing or invalid username claim for access token")
		}
	} else {
		// For refresh tokens, username might not be present
		if usernameVal, exists := claimsInMap["username"]; exists {
			username, _ = usernameVal.(string)
		}
	}

	return &model.User{
		Id:       int(userID),
		Username: username,
	}, nil
}
func (a authService) ExtractKeyIDFromToken(token string) (string, error) {
	return a.jwtManager.ExtractKeyIDFromToken(token)
}

// extractDeviceTypeFromKeyID extracts the device type from a keyID
// KeyID format: deviceType-userID-timestamp
func (a authService) extractDeviceTypeFromKeyID(keyID string) (string, error) {
	// Split the keyID by '-' to extract components
	parts := strings.Split(keyID, "-")
	if len(parts) < 3 {
		return "", fmt.Errorf("invalid keyID format: expected deviceType-userID-timestamp, got %s", keyID)
	}

	// The device type is the first part
	return parts[0], nil
}
