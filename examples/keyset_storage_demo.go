package main

import (
	"fmt"
	"log"

	"github.com/sushan531/jwk-auth/internal/config"
	"github.com/sushan531/jwk-auth/internal/database"
	"github.com/sushan531/jwk-auth/internal/repository"
)

func main() {
	fmt.Println("=== Consolidated Keyset Storage Demo ===")

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

	// Initialize repository
	userRepo := repository.NewUserAuthRepository(db)

	fmt.Println("\n1. Demonstrating Consolidated Storage Efficiency")
	fmt.Println("==============================================")

	// Show how multiple device keys are stored in a single row
	userID := 100

	// Simulate adding device keys to consolidated keyset
	deviceTypes := []string{"web", "android", "ios", "desktop"}

	fmt.Printf("Adding device keys for user %d:\n", userID)

	for i, deviceType := range deviceTypes {
		// Create a mock JWK key data (in real implementation, this would be proper JWK JSON)
		mockKeyData := fmt.Sprintf(`{"kty":"RSA","kid":"%s-%d-key","use":"sig","n":"mock_n_value","e":"AQAB"}`, deviceType, userID)

		err := userRepo.UpdateDeviceKeyInKeyset(userID, deviceType, fmt.Sprintf("%s-%d-key", deviceType, userID), mockKeyData)
		if err != nil {
			log.Printf("Failed to add %s key: %v", deviceType, err)
			continue
		}

		fmt.Printf("  ✓ Added %s key\n", deviceType)

		// Show keyset after each addition
		keyset, err := userRepo.GetUserKeyset(userID)
		if err != nil {
			log.Printf("Failed to get keyset: %v", err)
			continue
		}

		fmt.Printf("    Keyset now contains %d device keys in single database row\n", len(keyset.KeyData))
	}

	fmt.Println("\n2. Demonstrating Single Query Efficiency")
	fmt.Println("=======================================")

	// Show how all user keys are retrieved in a single query
	keyset, err := userRepo.GetUserKeyset(userID)
	if err != nil {
		log.Printf("Failed to get keyset: %v", err)
	} else {
		fmt.Printf("Single query retrieved all %d device keys for user %d:\n", len(keyset.KeyData), userID)
		for deviceType := range keyset.KeyData {
			fmt.Printf("  - %s\n", deviceType)
		}
		fmt.Printf("Database queries: 1 (vs %d in old schema)\n", len(keyset.KeyData))
	}

	fmt.Println("\n3. Demonstrating Device Key Management")
	fmt.Println("====================================")

	// Remove a specific device key
	fmt.Printf("Removing 'android' key from user %d keyset...\n", userID)
	err = userRepo.RemoveDeviceKeyFromKeyset(userID, "android")
	if err != nil {
		log.Printf("Failed to remove android key: %v", err)
	} else {
		fmt.Println("  ✓ Android key removed")

		// Show updated keyset
		keyset, _ := userRepo.GetUserKeyset(userID)
		fmt.Printf("  Keyset now contains %d device keys:\n", len(keyset.KeyData))
		for deviceType := range keyset.KeyData {
			fmt.Printf("    - %s\n", deviceType)
		}
	}

	fmt.Println("\n4. Demonstrating Reverse Key Lookup")
	fmt.Println("==================================")

	// Test finding keyset by key ID
	keyID := fmt.Sprintf("web-%d-key", userID)
	fmt.Printf("Looking up keyset for key ID: %s\n", keyID)

	foundKeyset, err := userRepo.FindKeysetByKeyID(keyID)
	if err != nil {
		fmt.Printf("  ✗ Key lookup failed: %v\n", err)
	} else {
		fmt.Printf("  ✓ Found keyset for user %d\n", foundKeyset.UserID)
		fmt.Printf("  ✓ Keyset contains %d device keys\n", len(foundKeyset.KeyData))
	}

	fmt.Println("\n5. Demonstrating Multi-User Keysets")
	fmt.Println("==================================")

	// Create keysets for multiple users
	users := []int{101, 102, 103}

	for _, uid := range users {
		// Add a couple of device keys for each user
		for _, deviceType := range []string{"web", "mobile"} {
			mockKeyData := fmt.Sprintf(`{"kty":"RSA","kid":"%s-%d-key","use":"sig"}`, deviceType, uid)
			err := userRepo.UpdateDeviceKeyInKeyset(uid, deviceType, fmt.Sprintf("%s-%d-key", deviceType, uid), mockKeyData)
			if err != nil {
				log.Printf("Failed to add key for user %d: %v", uid, err)
			}
		}
	}

	// Show all keysets
	allKeysets, err := userRepo.GetAllUserKeysets()
	if err != nil {
		log.Printf("Failed to get all keysets: %v", err)
	} else {
		fmt.Printf("Total users with keysets: %d\n", len(allKeysets))
		for _, keyset := range allKeysets {
			fmt.Printf("  User %d: %d device keys\n", keyset.UserID, len(keyset.KeyData))
		}
	}

	fmt.Println("\n6. Demonstrating Automatic Cleanup")
	fmt.Println("=================================")

	// Remove all keys from a user (simulates logout from all devices)
	testUserID := 101
	fmt.Printf("Removing all device keys for user %d...\n", testUserID)

	err = userRepo.DeleteUserKeyset(testUserID)
	if err != nil {
		log.Printf("Failed to delete keyset: %v", err)
	} else {
		fmt.Printf("  ✓ User %d keyset deleted (automatic cleanup)\n", testUserID)

		// Verify deletion
		_, err = userRepo.GetUserKeyset(testUserID)
		if err != nil {
			fmt.Printf("  ✓ Confirmed: keyset no longer exists\n")
		} else {
			fmt.Printf("  ✗ Keyset still exists (unexpected)\n")
		}
	}

	fmt.Println("\n=== Storage Demo Completed ===")
	fmt.Println("\nKey Benefits Demonstrated:")
	fmt.Println("• Single database row per user (vs multiple rows in old schema)")
	fmt.Println("• Single query retrieves all user keys")
	fmt.Println("• Efficient device key management within keyset")
	fmt.Println("• Fast reverse lookup (key ID to user)")
	fmt.Println("• Automatic cleanup when keyset becomes empty")
	fmt.Println("• JSONB storage enables efficient queries and indexing")
}
