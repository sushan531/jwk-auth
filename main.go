package main

import (
	"fmt"

	"github.com/sushan531/jwk-auth/core"
	"github.com/sushan531/jwk-auth/service"
)

func main() {

	// Create auth service
	authService := service.NewAuth(
		core.NewJwkManager(),
		core.NewJwtManager(),
		core.DefaultConfig(),
	)

	// Define claims for the token
	claims := map[string]any{
		"username": "testuser",
		"scope":    "read:data",
	}
	refreshClaims := map[string]any{
		"username": "testuser",
		"purpose":  "access",
	}
	claims2 := map[string]any{
		"username": "testuser",
		"scope":    "read:data",
	}
	refreshClaims2 := map[string]any{
		"username": "testuser",
		"purpose":  "access",
	}

	// Generate a token
	token, refresh, err := authService.GenerateAccessRefreshTokenPair(claims, refreshClaims, "android")
	if err != nil {
		fmt.Printf("Error generating token: %v\n", err)
		return
	}

	token2, refresh2, err := authService.GenerateAccessRefreshTokenPair(claims2, refreshClaims2, "ios")
	if err != nil {
		fmt.Printf("Error generating token: %v\n", err)
		return
	}
	// Generate a token
	token3, refresh3, err := authService.GenerateAccessRefreshTokenPair(claims, refreshClaims, "android")
	if err != nil {
		fmt.Printf("Error generating token: %v\n", err)
		return
	}

	//fmt.Printf("Generated Token: %s\n, Refresh Token: %s\n", token, refresh)
	//fmt.Printf("Generated Token: %s\n, Refresh Token: %s\n", token2, refresh2)
	//fmt.Printf("Generated Token: %s\n, Refresh Token: %s\n", token3, refresh3)
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
	for _, v := range []string{refresh, refresh2, refresh3} {
		data, err := authService.VerifyTokenSignatureAndGetClaims(v)
		if err != nil {
			fmt.Printf("Error parsing JWK set: %v\n", err)
		}
		fmt.Printf("data: %v\n", data)
	}
	fmt.Println("\n")
	for _, v := range []string{token, token2, token3} {
		data, err := authService.VerifyTokenSignatureAndGetClaims(v)
		if err != nil {
			fmt.Printf("Error parsing JWK set: %v\n", err)
		}
		fmt.Printf("data: %v\n", data)
	}
}
