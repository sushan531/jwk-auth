package main

import (
	"fmt"

	"github.com/sushan531/jwt-auth/internal"
	"github.com/sushan531/jwt-auth/service"
)

func main() {
	// Create managers
	jwkManager := internal.NewJwkManager()
	jwtManager := internal.NewJwtManager(
		internal.DefaultConfig(),
	)

	// Create auth service
	authService := service.NewAuth(jwkManager, jwtManager)

	// Define claims for the token
	claims := map[string]interface{}{
		"username": "testuser",
		"scope":    "read:data",
	}
	claims2 := map[string]interface{}{
		"username": "testuser",
		"scope":    "read:data",
	}
	// Generate a token
	token, err := authService.GenerateToken(claims, "android")
	if err != nil {
		fmt.Printf("Error generating token: %v\n", err)
		return
	}

	token2, err := authService.GenerateToken(claims2, "ios")
	if err != nil {
		fmt.Printf("Error generating token: %v\n", err)
		return
	}
	// Generate a token
	token3, err := authService.GenerateToken(claims, "android")
	if err != nil {
		fmt.Printf("Error generating token: %v\n", err)
		return
	}

	fmt.Printf("Generated Token: %s\n", token)
	fmt.Printf("Generated Token: %s\n", token2)
	fmt.Printf("Generated Token: %s\n", token3)
	// Marshal JWK set
	jwkSetJSON, err := authService.MarshalJwkSet()
	if err != nil {
		fmt.Printf("Error marshaling JWK set: %v\n", err)
		return
	}
	fmt.Printf("Marshaled JWK Set: %s\n", jwkSetJSON)

	// Here you could add more test logic, like trying to parse and verify the token.
	err = authService.ParseJsonBytes(
		string(jwkSetJSON),
	)
	if err != nil {
		fmt.Printf("Error parsing JWK set: %v\n", err)
		return
	}
	for _, v := range []string{token, token2, token3} {
		data, err := authService.VerifyTokenSignatureAndGetClaims(v)
		if err != nil {
			fmt.Printf("Error parsing JWK set: %v\n", err)
		}
		fmt.Printf("data: %v\n", data)

	}
}
