package manager

import (
	"context"
	"log"
	"time"
)

// CacheManager handles automatic cache maintenance operations
type CacheManager struct {
	jwkManager      JwkManager
	cleanupInterval time.Duration
	ctx             context.Context
	cancel          context.CancelFunc
}

// NewCacheManager creates a new cache manager with automatic cleanup
func NewCacheManager(jwkManager JwkManager, cleanupInterval time.Duration) *CacheManager {
	ctx, cancel := context.WithCancel(context.Background())

	return &CacheManager{
		jwkManager:      jwkManager,
		cleanupInterval: cleanupInterval,
		ctx:             ctx,
		cancel:          cancel,
	}
}

// Start begins the automatic cache cleanup routine
func (cm *CacheManager) Start() {
	go cm.cleanupRoutine()
}

// Stop stops the automatic cache cleanup routine
func (cm *CacheManager) Stop() {
	cm.cancel()
}

// cleanupRoutine runs periodic cache cleanup operations
func (cm *CacheManager) cleanupRoutine() {
	ticker := time.NewTicker(cm.cleanupInterval)
	defer ticker.Stop()

	for {
		select {
		case <-cm.ctx.Done():
			return
		case <-ticker.C:
			cm.performCleanup()
		}
	}
}

// performCleanup executes cache maintenance operations
func (cm *CacheManager) performCleanup() {
	// Clean up expired cache items
	expired := cm.jwkManager.CleanupExpiredCache()

	// Log cleanup statistics if items were removed
	if expired > 0 {
		log.Printf("Cache cleanup: removed %d expired items", expired)
	}

	// Get and log cache metrics periodically (every 10 cleanups)
	metrics := cm.jwkManager.GetCacheMetrics()
	total := metrics.hits + metrics.misses

	if total > 0 {
		hitRate := float64(metrics.hits) / float64(total) * 100
		log.Printf("Cache metrics - Hit rate: %.1f%%, Total ops: %d, Evictions: %d",
			hitRate, total, metrics.evictions)
	}
}

// GetCacheHealth returns current cache health statistics
func (cm *CacheManager) GetCacheHealth() CacheHealth {
	metrics := cm.jwkManager.GetCacheMetrics()
	total := metrics.hits + metrics.misses

	var hitRate float64
	if total > 0 {
		hitRate = float64(metrics.hits) / float64(total) * 100
	}

	return CacheHealth{
		HitRate:         hitRate,
		TotalOperations: total,
		Evictions:       metrics.evictions,
		ExpiredCleanups: metrics.expiredCleanups,
	}
}

// CacheHealth represents cache performance health metrics
type CacheHealth struct {
	HitRate         float64 `json:"hit_rate"`
	TotalOperations int64   `json:"total_operations"`
	Evictions       int64   `json:"evictions"`
	ExpiredCleanups int64   `json:"expired_cleanups"`
}

// IsHealthy returns true if cache performance is within acceptable ranges
func (ch CacheHealth) IsHealthy() bool {
	// Consider cache healthy if:
	// - Hit rate is above 70% (good cache effectiveness)
	// - We have some operations (cache is being used)
	return ch.HitRate >= 70.0 && ch.TotalOperations > 0
}

// NeedsAttention returns true if cache performance indicates issues
func (ch CacheHealth) NeedsAttention() bool {
	// Cache needs attention if:
	// - Hit rate is below 50% (poor cache effectiveness)
	// - Excessive evictions relative to operations (memory pressure)
	evictionRate := float64(ch.Evictions) / float64(ch.TotalOperations) * 100

	return ch.HitRate < 50.0 || evictionRate > 20.0
}
