package main

import (
	"fmt"
	"jwk-auth/internal"
	"jwk-auth/service"
)

func main() {
	// Create managers
	jwkManager := internal.NewJwkManager()
	jwtManager := internal.NewJwtManager()

	// Create auth service
	authService := service.NewAuth(jwkManager, jwtManager)

	// Define claims for the token
	claims := map[string]interface{}{
		"username": "testuser",
		"scope":    "read:data",
	}

	// Generate a token
	token, err := authService.GenerateToken(claims, "android")
	if err != nil {
		fmt.Printf("Error generating token: %v\n", err)
		return
	}

	fmt.Printf("Generated Token: %s\n", token)

	// Here you could add more test logic, like trying to parse and verify the token.
}
