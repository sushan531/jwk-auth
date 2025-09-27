package main

import (
	"fmt"
	"time"

	"github.com/sushan531/jwk-auth/core"
	"github.com/sushan531/jwk-auth/service"
)

func main() {
	// Use builder pattern for configuration
	config := core.NewConfigBuilder().
		WithTokenExpiry(2*time.Hour).
		WithRefreshTokenExpiry(7*24*time.Hour).
		WithKeySize(2048).
		WithCacheSettings(100, time.Hour).
		Build()

	// Use factory pattern for service creation
	factory := service.NewServiceFactory(config)
	authService, tokenService, keyService := factory.CreateAllServices()

	// Example usage with improved error handling
	accessClaims := map[string]any{
		"username": "testuser",
		"user_id":  "12345",
		"scope":    "read:data write:data",
	}

	refreshClaims := map[string]any{
		"username": "testuser",
		"user_id":  "12345",
		"purpose":  "refresh",
	}

	// Generate token pair
	accessToken, refreshToken, err := authService.GenerateAccessRefreshTokenPair(
		accessClaims,
		refreshClaims,
		"android",
	)
	if err != nil {
		fmt.Printf("Error generating tokens: %v\n", err)
		return
	}

	// Validate tokens using the token service
	accessTokenClaims, err := tokenService.ValidateAccessToken(accessToken)
	if err != nil {
		fmt.Printf("Error validating access token: %v\n", err)
		return
	}

	refreshTokenClaims, err := tokenService.ValidateRefreshToken(refreshToken)
	if err != nil {
		fmt.Printf("Error validating refresh token: %v\n", err)
		return
	}

	fmt.Printf("Access token validated successfully: %+v\n", accessTokenClaims)
	fmt.Printf("Refresh token validated successfully: %+v\n", refreshTokenClaims)

	// Get key metadata
	metadata, err := keyService.GetKeyMetadata("android")
	if err != nil {
		fmt.Printf("Error getting key metadata: %v\n", err)
		return
	}

	fmt.Printf("Key metadata: %+v\n", metadata)

	// Refresh access token
	newAccessToken, err := tokenService.RefreshAccessToken(refreshToken, accessClaims, "android")
	if err != nil {
		fmt.Printf("Error refreshing access token: %v\n", err)
		return
	}

	fmt.Printf("New access token generated: %s\n", newAccessToken)

	oldAccessToken, err := tokenService.ValidateAccessToken(accessToken)
	if err != nil {
		fmt.Printf("Error validating access token: %v\n", err)
		return
	}
	fmt.Printf("Access token validated successfully: %+v\n", oldAccessToken)

}
