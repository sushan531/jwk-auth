package main

import (
	"fmt"
	"log"
	"time"

	"github.com/sushan531/jwk-auth/internal/database"
	"github.com/sushan531/jwk-auth/internal/manager"
	"github.com/sushan531/jwk-auth/internal/repository"
)

func main() {
	// Initialize database connection
	db, err := database.Connect()
	if err != nil {
		log.Fatal("Failed to connect to database:", err)
	}
	defer db.Close()

	// Create repository and JWK manager with optimized caching for consolidated keysets
	userRepo := repository.NewUserAuthRepository(db)
	jwkManager := manager.NewJwkManager(userRepo)

	// Create cache manager for automatic cleanup
	cacheManager := manager.NewCacheManager(jwkManager, 5*time.Minute)
	cacheManager.Start()
	defer cacheManager.Stop()

	// Example: Create session keys for multiple users and devices (consolidated keysets)
	fmt.Println("Creating consolidated keysets...")

	users := []int{1, 2, 3, 4, 5}
	devices := []string{"web", "android", "ios"}

	var keyIDs []string

	for _, userID := range users {
		fmt.Printf("Creating keyset for user %d:\n", userID)
		for _, deviceType := range devices {
			keyID, err := jwkManager.CreateSessionKey(userID, deviceType)
			if err != nil {
				log.Printf("Failed to create key for user %d, device %s: %v", userID, deviceType, err)
				continue
			}
			keyIDs = append(keyIDs, keyID)
			fmt.Printf("  ✓ %s key: %s\n", deviceType, keyID)
		}

		// Show consolidated keyset for this user
		keyset, err := userRepo.GetUserKeyset(userID)
		if err != nil {
			log.Printf("Failed to get keyset for user %d: %v", userID, err)
		} else {
			fmt.Printf("  📦 Consolidated keyset contains %d device keys\n", len(keyset.KeyData))
		}
	}

	// Example: Demonstrate consolidated keyset cache performance
	fmt.Println("\nTesting consolidated keyset cache performance...")

	start := time.Now()

	// First round - cache misses (keysets not in cache yet)
	fmt.Println("First lookup round (cache misses - loads entire keysets):")
	for i, keyID := range keyIDs {
		if i >= 5 {
			break
		} // Test first 5 keys

		lookupStart := time.Now()
		_, err := jwkManager.GetPrivateKeyByID(keyID)
		lookupDuration := time.Since(lookupStart)

		if err != nil {
			log.Printf("Failed to get key %s: %v", keyID, err)
			continue
		}
		fmt.Printf("  Key %s lookup: %v (loads entire user keyset)\n", keyID, lookupDuration)
	}

	// Second round - cache hits (entire keysets now cached)
	fmt.Println("Second lookup round (cache hits - keysets in memory):")
	for i, keyID := range keyIDs {
		if i >= 5 {
			break
		} // Test same 5 keys

		lookupStart := time.Now()
		_, err := jwkManager.GetPrivateKeyByID(keyID)
		lookupDuration := time.Since(lookupStart)

		if err != nil {
			log.Printf("Failed to get key %s: %v", keyID, err)
			continue
		}
		fmt.Printf("  Key %s lookup: %v (from cached keyset)\n", keyID, lookupDuration)
	}

	totalDuration := time.Since(start)
	fmt.Printf("Total lookup time: %v\n", totalDuration)

	// Display cache metrics
	fmt.Println("\nCache Performance Metrics:")
	metrics := jwkManager.GetCacheMetrics()
	total := metrics.hits + metrics.misses

	if total > 0 {
		hitRate := float64(metrics.hits) / float64(total) * 100
		fmt.Printf("  Hit Rate: %.1f%% (%d hits, %d misses)\n", hitRate, metrics.hits, metrics.misses)
		fmt.Printf("  Total Operations: %d\n", total)
		fmt.Printf("  Evictions: %d\n", metrics.evictions)
		fmt.Printf("  Expired Cleanups: %d\n", metrics.expiredCleanups)
	}

	// Display cache health
	fmt.Println("\nCache Health Status:")
	health := cacheManager.GetCacheHealth()
	fmt.Printf("  Overall Hit Rate: %.1f%%\n", health.HitRate)
	fmt.Printf("  Total Operations: %d\n", health.TotalOperations)
	fmt.Printf("  Evictions: %d\n", health.Evictions)
	fmt.Printf("  Expired Cleanups: %d\n", health.ExpiredCleanups)

	if health.IsHealthy() {
		fmt.Println("  Status: ✅ Healthy")
	} else if health.NeedsAttention() {
		fmt.Println("  Status: ⚠️  Needs Attention")
	} else {
		fmt.Println("  Status: ℹ️  Normal")
	}

	// Example: Manual cache cleanup
	fmt.Println("\nPerforming manual cache cleanup...")
	expired := jwkManager.CleanupExpiredCache()
	fmt.Printf("Cleaned up %d expired items\n", expired)

	// Example: Reset metrics for fresh monitoring
	fmt.Println("\nResetting cache metrics...")
	jwkManager.ResetCacheMetrics()

	newMetrics := jwkManager.GetCacheMetrics()
	fmt.Printf("Metrics after reset: hits=%d, misses=%d\n", newMetrics.hits, newMetrics.misses)

	fmt.Println("\nOptimized consolidated keyset cache example completed successfully!")
	fmt.Println("\nKey Performance Benefits:")
	fmt.Println("• Entire user keysets cached in memory (not individual keys)")
	fmt.Println("• Single database query loads all user device keys")
	fmt.Println("• Reverse lookup cache maps key IDs to users efficiently")
	fmt.Println("• LRU eviction manages memory usage automatically")
	fmt.Println("• Cache metrics help monitor performance")
}
