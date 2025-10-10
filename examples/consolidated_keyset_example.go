package main

import (
	"fmt"
	"log"
	"time"

	"github.com/sushan531/jwk-auth/internal/config"
	"github.com/sushan531/jwk-auth/internal/database"
	"github.com/sushan531/jwk-auth/internal/manager"
	"github.com/sushan531/jwk-auth/internal/repository"
	"github.com/sushan531/jwk-auth/model"
	"github.com/sushan531/jwk-auth/service"
)

func main() {
	fmt.Println("=== Consolidated Keyset Management Example ===")

	// Initialize database connection
	cfg := config.LoadConfig()
	db, err := database.NewConnection(cfg.Database)
	if err != nil {
		log.Fatalf("Failed to connect to database: %v", err)
	}
	defer db.Close()

	// Create tables if they don't exist
	if err := database.CreateTables(db); err != nil {
		log.Fatalf("Failed to create tables: %v", err)
	}

	// Initialize components
	userRepo := repository.NewUserAuthRepository(db)
	jwkManager := manager.NewJwkManager(userRepo)
	jwtManager := manager.NewJwtManager(jwkManager)
	authService := service.NewAuthService(jwtManager, jwkManager)

	// Example users
	users := []model.User{
		{ID: 1, Username: "alice", Email: "alice@example.com"},
		{ID: 2, Username: "bob", Email: "bob@example.com"},
		{ID: 3, Username: "charlie", Email: "charlie@example.com"},
	}

	fmt.Println("\n1. Demonstrating Consolidated Key Storage")
	fmt.Println("========================================")

	// Create sessions for multiple users and devices
	for _, user := range users {
		fmt.Printf("\nUser: %s (ID: %d)\n", user.Username, user.ID)

		// Login from web
		webKeyID, err := jwkManager.CreateSessionKey(user.ID, "web")
		if err != nil {
			log.Printf("Failed to create web session for %s: %v", user.Username, err)
			continue
		}
		fmt.Printf("  ✓ Web session created: %s", webKeyID)

		// Generate tokens for web session
		tokenPair, err := authService.GenerateTokenPairWithKeyID(user, webKeyID)
		if err != nil {
			log.Printf("Failed to generate tokens for %s: %v", user.Username, err)
		} else {
			fmt.Printf(" (tokens generated)")
		}
		fmt.Println()

		// Login from android
		androidKeyID, err := jwkManager.CreateSessionKey(user.ID, "android")
		if err != nil {
			log.Printf("Failed to create android session for %s: %v", user.Username, err)
			continue
		}
		fmt.Printf("  ✓ Android session created: %s\n", androidKeyID)

		// Login from iOS
		iosKeyID, err := jwkManager.CreateSessionKey(user.ID, "ios")
		if err != nil {
			log.Printf("Failed to create iOS session for %s: %v", user.Username, err)
			continue
		}
		fmt.Printf("  ✓ iOS session created: %s\n", iosKeyID)

		// Show consolidated keyset
		keyset, err := userRepo.GetUserKeyset(user.ID)
		if err != nil {
			log.Printf("Failed to get keyset for %s: %v", user.Username, err)
			continue
		}

		fmt.Printf("  📦 Consolidated keyset contains %d device keys:\n", len(keyset.KeyData))
		for deviceType := range keyset.KeyData {
			fmt.Printf("    - %s\n", deviceType)
		}
	}

	fmt.Println("\n2. Demonstrating Single Device Login")
	fmt.Println("===================================")

	user := users[0] // Use Alice for this demo
	fmt.Printf("User: %s\n", user.Username)

	// Create first web session
	webKey1, err := jwkManager.CreateSessionKey(user.ID, "web")
	if err != nil {
		log.Fatalf("Failed to create first web session: %v", err)
	}
	fmt.Printf("  ✓ First web session: %s\n", webKey1)

	// Wait a moment
	time.Sleep(100 * time.Millisecond)

	// Create second web session (should replace first)
	webKey2, err := jwkManager.CreateSessionKey(user.ID, "web")
	if err != nil {
		log.Fatalf("Failed to create second web session: %v", err)
	}
	fmt.Printf("  ✓ Second web session: %s (should replace first)\n", webKey2)

	// Verify first key is no longer accessible
	_, err = jwkManager.GetPrivateKeyByID(webKey1)
	if err != nil {
		fmt.Printf("  ✓ First web key correctly invalidated: %v\n", err)
	} else {
		fmt.Printf("  ✗ First web key should be invalidated\n")
	}

	// Verify second key is accessible
	_, err = jwkManager.GetPrivateKeyByID(webKey2)
	if err != nil {
		fmt.Printf("  ✗ Second web key should be accessible: %v\n", err)
	} else {
		fmt.Printf("  ✓ Second web key is accessible\n")
	}

	fmt.Println("\n3. Demonstrating Cross-Device Sessions")
	fmt.Println("=====================================")

	// Show that android session still exists alongside new web session
	sessions, err := jwkManager.GetSessionKeys(user.ID)
	if err != nil {
		log.Printf("Failed to get sessions: %v", err)
	} else {
		fmt.Printf("Active sessions for %s: %v\n", user.Username, sessions)
	}

	fmt.Println("\n4. Demonstrating Efficient Key Lookup")
	fmt.Println("====================================")

	// Test reverse lookup (key ID to user)
	for _, user := range users {
		sessions, err := jwkManager.GetSessionKeys(user.ID)
		if err != nil {
			continue
		}

		for _, keyID := range sessions {
			// Use the repository's reverse lookup
			keyset, err := userRepo.FindKeysetByKeyID(keyID)
			if err != nil {
				fmt.Printf("  ✗ Failed to find keyset for key %s: %v\n", keyID, err)
			} else {
				fmt.Printf("  ✓ Key %s belongs to user %d\n", keyID, keyset.UserID)
			}
		}
	}

	fmt.Println("\n5. Demonstrating Keyset Operations")
	fmt.Println("=================================")

	// Get all keysets
	allKeysets, err := userRepo.GetAllUserKeysets()
	if err != nil {
		log.Printf("Failed to get all keysets: %v", err)
	} else {
		fmt.Printf("Total users with active keysets: %d\n", len(allKeysets))
		for _, keyset := range allKeysets {
			fmt.Printf("  User %d: %d device keys\n", keyset.UserID, len(keyset.KeyData))
		}
	}

	fmt.Println("\n6. Demonstrating Selective Logout")
	fmt.Println("=================================")

	user = users[1] // Use Bob for this demo
	fmt.Printf("User: %s\n", user.Username)

	// Get current sessions
	sessions, _ = jwkManager.GetSessionKeys(user.ID)
	fmt.Printf("Sessions before logout: %v\n", sessions)

	// Logout from android only
	if len(sessions) > 0 {
		// Find android session
		for _, keyID := range sessions {
			// This is a simplified approach - in real implementation,
			// you'd track which key belongs to which device
			err := jwkManager.DeleteSessionKey(user.ID, keyID)
			if err != nil {
				fmt.Printf("  Failed to delete session %s: %v\n", keyID, err)
			} else {
				fmt.Printf("  ✓ Deleted session: %s\n", keyID)
				break // Delete only one session for demo
			}
		}
	}

	// Show remaining sessions
	sessions, _ = jwkManager.GetSessionKeys(user.ID)
	fmt.Printf("Sessions after logout: %v\n", sessions)

	fmt.Println("\n7. Demonstrating Token Verification")
	fmt.Println("==================================")

	// Generate and verify tokens using consolidated keysets
	user = users[2] // Use Charlie
	sessions, _ = jwkManager.GetSessionKeys(user.ID)

	if len(sessions) > 0 {
		keyID := sessions[0]

		// Generate token pair
		tokenPair, err := authService.GenerateTokenPairWithKeyID(user, keyID)
		if err != nil {
			fmt.Printf("Failed to generate tokens: %v\n", err)
		} else {
			fmt.Printf("Generated tokens for user %s with key %s\n", user.Username, keyID)

			// Verify access token
			verifiedUser, err := authService.VerifyToken(tokenPair.AccessToken)
			if err != nil {
				fmt.Printf("  ✗ Token verification failed: %v\n", err)
			} else {
				fmt.Printf("  ✓ Token verified for user: %s\n", verifiedUser.Username)
			}
		}
	}

	fmt.Println("\n=== Consolidated Keyset Management Example Completed ===")
}
