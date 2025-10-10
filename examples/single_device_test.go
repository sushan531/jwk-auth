package main

import (
	"fmt"
	"log"
	"time"

	"github.com/sushan531/jwk-auth/internal/config"
	"github.com/sushan531/jwk-auth/internal/database"
	"github.com/sushan531/jwk-auth/internal/manager"
	"github.com/sushan531/jwk-auth/internal/repository"
)

func main() {
	// Load configuration
	cfg := config.LoadConfig()

	// Initialize database connection
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

	userID := 1

	fmt.Println("=== Single Device Login Test ===")

	// Test 1: Create first web session
	fmt.Println("\n1. Creating first web session...")
	webKey1, err := jwkManager.CreateSessionKey(userID, "web")
	if err != nil {
		log.Fatalf("Failed to create first web session: %v", err)
	}
	fmt.Printf("Created web session 1: %s\n", webKey1)

	// Check active sessions
	sessions, _ := jwkManager.GetSessionKeys(userID)
	fmt.Printf("Active sessions: %v\n", sessions)

	// Wait a moment to ensure different timestamps
	time.Sleep(1 * time.Second)

	// Test 2: Create second web session (should invalidate first)
	fmt.Println("\n2. Creating second web session (should invalidate first)...")
	webKey2, err := jwkManager.CreateSessionKey(userID, "web")
	if err != nil {
		log.Fatalf("Failed to create second web session: %v", err)
	}
	fmt.Printf("Created web session 2: %s\n", webKey2)

	// Check active sessions
	sessions, _ = jwkManager.GetSessionKeys(userID)
	fmt.Printf("Active sessions after second web login: %v\n", sessions)

	// Test 3: Create android session (should coexist with web)
	fmt.Println("\n3. Creating android session (should coexist with web)...")
	androidKey, err := jwkManager.CreateSessionKey(userID, "android")
	if err != nil {
		log.Fatalf("Failed to create android session: %v", err)
	}
	fmt.Printf("Created android session: %s\n", androidKey)

	// Check active sessions
	sessions, _ = jwkManager.GetSessionKeys(userID)
	fmt.Printf("Active sessions after android login: %v\n", sessions)

	// Test 4: Create another web session (should invalidate previous web, keep android)
	time.Sleep(1 * time.Second)
	fmt.Println("\n4. Creating third web session (should invalidate second web, keep android)...")
	webKey3, err := jwkManager.CreateSessionKey(userID, "web")
	if err != nil {
		log.Fatalf("Failed to create third web session: %v", err)
	}
	fmt.Printf("Created web session 3: %s\n", webKey3)

	// Check final active sessions
	sessions, _ = jwkManager.GetSessionKeys(userID)
	fmt.Printf("Final active sessions: %v\n", sessions)

	// Verify we can't use the old web keys
	fmt.Println("\n5. Testing old key access...")
	_, err = jwkManager.GetPrivateKeyByID(webKey1)
	if err != nil {
		fmt.Printf("✓ Old web key 1 correctly invalidated: %v\n", err)
	} else {
		fmt.Printf("✗ Old web key 1 should be invalidated but still accessible\n")
	}

	_, err = jwkManager.GetPrivateKeyByID(webKey2)
	if err != nil {
		fmt.Printf("✓ Old web key 2 correctly invalidated: %v\n", err)
	} else {
		fmt.Printf("✗ Old web key 2 should be invalidated but still accessible\n")
	}

	// Verify current keys work
	_, err = jwkManager.GetPrivateKeyByID(webKey3)
	if err != nil {
		fmt.Printf("✗ Current web key should be accessible: %v\n", err)
	} else {
		fmt.Printf("✓ Current web key is accessible\n")
	}

	_, err = jwkManager.GetPrivateKeyByID(androidKey)
	if err != nil {
		fmt.Printf("✗ Android key should be accessible: %v\n", err)
	} else {
		fmt.Printf("✓ Android key is accessible\n")
	}

	fmt.Println("\n=== Single Device Login Test Completed ===")
}
