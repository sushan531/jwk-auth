package service

import (
	"crypto/rsa"
	"fmt"
	"time"

	"github.com/sushan531/jwk-auth/internal/manager"
	"github.com/sushan531/jwk-auth/model"
)

type AuthService interface {
	GenerateJwt(user *model.User) (string, error)
	GenerateTokenPair(user *model.User) (*model.TokenPair, error)
	RefreshTokens(refreshToken string, username string) (*model.TokenPair, error)
	GetPublicKeys() ([]*rsa.PublicKey, error)
	VerifyToken(token string) (*model.User, error)
	VerifyRefreshToken(token string) (*model.User, error)
}

type authService struct {
	jwtManager manager.JwtManager
	jwkManager manager.JwkManager
}

func NewAuthService(jwtManager manager.JwtManager, jwkManager manager.JwkManager) AuthService {
	return &authService{
		jwtManager: jwtManager,
		jwkManager: jwkManager,
	}
}

func (a authService) GenerateJwt(user *model.User) (string, error) {
	var userAsMap = user.ToMap()
	return a.jwtManager.GenerateToken(userAsMap)
}

func (a authService) GetPublicKeys() ([]*rsa.PublicKey, error) {
	return a.jwkManager.GetPublicKeys()
}

func (a authService) GenerateTokenPair(user *model.User) (*model.TokenPair, error) {
	// Generate access token claims (includes username)
	accessClaims := model.NewTokenClaims(user, "access", 15*time.Minute)
	accessToken, err := a.jwtManager.GenerateAccessToken(accessClaims.ToMap())
	if err != nil {
		return nil, fmt.Errorf("failed to generate access token: %w", err)
	}

	// Generate refresh token claims (only user_id)
	refreshClaims := model.NewRefreshTokenClaims(user.Id, 7*24*time.Hour)
	refreshToken, err := a.jwtManager.GenerateRefreshToken(refreshClaims.ToMap())
	if err != nil {
		return nil, fmt.Errorf("failed to generate refresh token: %w", err)
	}

	return &model.TokenPair{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		TokenType:    "Bearer",
		ExpiresIn:    15 * 60, // 15 minutes in seconds
	}, nil
}

func (a authService) RefreshTokens(refreshToken string, username string) (*model.TokenPair, error) {
	// Verify the refresh token (this only validates the token and extracts user_id)
	userFromToken, err := a.VerifyRefreshToken(refreshToken)
	if err != nil {
		return nil, fmt.Errorf("invalid refresh token: %w", err)
	}

	// Create user object with provided username for new access token
	user := &model.User{
		Id:       userFromToken.Id,
		Username: username,
	}

	// Generate new token pair
	return a.GenerateTokenPair(user)
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
