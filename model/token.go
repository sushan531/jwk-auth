package model

import "time"

type TokenPair struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int64  `json:"expires_in"`
}

type TokenClaims struct {
	UserID    int    `json:"user_id"`
	Username  string `json:"username"`
	TokenType string `json:"token_type"` // "access" or "refresh"
	IssuedAt  int64  `json:"iat"`
	ExpiresAt int64  `json:"exp"`
}

func NewTokenClaims(user *User, tokenType string, duration time.Duration) *TokenClaims {
	now := time.Now()
	return &TokenClaims{
		UserID:    user.Id,
		Username:  user.Username,
		TokenType: tokenType,
		IssuedAt:  now.Unix(),
		ExpiresAt: now.Add(duration).Unix(),
	}
}

func NewRefreshTokenClaims(userID int, duration time.Duration) *TokenClaims {
	now := time.Now()
	return &TokenClaims{
		UserID:    userID,
		Username:  "", // Empty for refresh tokens
		TokenType: "refresh",
		IssuedAt:  now.Unix(),
		ExpiresAt: now.Add(duration).Unix(),
	}
}

func (tc *TokenClaims) ToMap() map[string]interface{} {
	claims := map[string]interface{}{
		"user_id":    tc.UserID,
		"token_type": tc.TokenType,
		"iat":        tc.IssuedAt,
		"exp":        tc.ExpiresAt,
	}

	// Only include username for access tokens
	if tc.TokenType == "access" && tc.Username != "" {
		claims["username"] = tc.Username
	}

	return claims
}
