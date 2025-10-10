package manager

import (
	"container/list"
	"fmt"
	"sync"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/sushan531/jwk-auth/model"
)

// LRUCache implements a thread-safe LRU cache with TTL support
type LRUCache struct {
	capacity  int
	ttl       time.Duration
	mutex     sync.RWMutex
	items     map[string]*list.Element
	evictList *list.List
}

// CacheItem represents an item in the LRU cache
type CacheItem struct {
	key       string
	value     interface{}
	timestamp time.Time
}

// NewLRUCache creates a new LRU cache with specified capacity and TTL
func NewLRUCache(capacity int, ttl time.Duration) *LRUCache {
	return &LRUCache{
		capacity:  capacity,
		ttl:       ttl,
		items:     make(map[string]*list.Element),
		evictList: list.New(),
	}
}

// Get retrieves an item from the cache
func (c *LRUCache) Get(key string) (interface{}, bool) {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	if element, exists := c.items[key]; exists {
		item := element.Value.(*CacheItem)

		// Check if item has expired
		if c.ttl > 0 && time.Since(item.timestamp) > c.ttl {
			c.removeElement(element)
			return nil, false
		}

		// Move to front (most recently used)
		c.evictList.MoveToFront(element)
		return item.value, true
	}

	return nil, false
}

// Put adds or updates an item in the cache
func (c *LRUCache) Put(key string, value interface{}) {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	// If key already exists, update it
	if element, exists := c.items[key]; exists {
		item := element.Value.(*CacheItem)
		item.value = value
		item.timestamp = time.Now()
		c.evictList.MoveToFront(element)
		return
	}

	// Add new item
	item := &CacheItem{
		key:       key,
		value:     value,
		timestamp: time.Now(),
	}

	element := c.evictList.PushFront(item)
	c.items[key] = element

	// Evict oldest items if capacity exceeded
	if c.evictList.Len() > c.capacity {
		c.evictOldest()
	}
}

// Remove removes an item from the cache
func (c *LRUCache) Remove(key string) {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	if element, exists := c.items[key]; exists {
		c.removeElement(element)
	}
}

// Clear removes all items from the cache
func (c *LRUCache) Clear() {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	c.items = make(map[string]*list.Element)
	c.evictList.Init()
}

// Size returns the current number of items in the cache
func (c *LRUCache) Size() int {
	c.mutex.RLock()
	defer c.mutex.RUnlock()
	return c.evictList.Len()
}

// CleanupExpired removes all expired items from the cache
func (c *LRUCache) CleanupExpired() int {
	if c.ttl <= 0 {
		return 0
	}

	c.mutex.Lock()
	defer c.mutex.Unlock()

	var toRemove []*list.Element
	now := time.Now()

	// Collect expired items
	for element := c.evictList.Back(); element != nil; element = element.Prev() {
		item := element.Value.(*CacheItem)
		if now.Sub(item.timestamp) > c.ttl {
			toRemove = append(toRemove, element)
		} else {
			// Since we're iterating from back to front (oldest to newest),
			// once we find a non-expired item, all items in front are also non-expired
			break
		}
	}

	// Remove expired items
	for _, element := range toRemove {
		c.removeElement(element)
	}

	return len(toRemove)
}

// evictOldest removes the oldest item from the cache
func (c *LRUCache) evictOldest() {
	if element := c.evictList.Back(); element != nil {
		c.removeElement(element)
	}
}

// removeElement removes a specific element from the cache
func (c *LRUCache) removeElement(element *list.Element) {
	item := element.Value.(*CacheItem)
	delete(c.items, item.key)
	c.evictList.Remove(element)
}

// OptimizedKeyCache provides optimized caching for JWK operations
type OptimizedKeyCache struct {
	// Parsed JWK cache with LRU eviction
	parsedKeys *LRUCache
	// User keyset cache with LRU eviction
	userKeysets *LRUCache
	// Reverse lookup cache: keyID -> userID
	keyToUser *LRUCache
	// Performance metrics
	metrics *CacheMetrics
}

// CacheMetrics tracks cache performance statistics
type CacheMetrics struct {
	mutex           sync.RWMutex
	hits            int64
	misses          int64
	evictions       int64
	expiredCleanups int64
}

// NewOptimizedKeyCache creates a new optimized cache with specified capacities and TTL
func NewOptimizedKeyCache(keyCapacity, keysetCapacity, lookupCapacity int, ttl time.Duration) *OptimizedKeyCache {
	return &OptimizedKeyCache{
		parsedKeys:  NewLRUCache(keyCapacity, ttl),
		userKeysets: NewLRUCache(keysetCapacity, ttl),
		keyToUser:   NewLRUCache(lookupCapacity, ttl),
		metrics:     &CacheMetrics{},
	}
}

// GetParsedKey retrieves a parsed JWK key from cache
func (c *OptimizedKeyCache) GetParsedKey(keyID string) (jwk.Key, bool) {
	if value, exists := c.parsedKeys.Get(keyID); exists {
		c.recordHit()
		return value.(jwk.Key), true
	}
	c.recordMiss()
	return nil, false
}

// PutParsedKey stores a parsed JWK key in cache
func (c *OptimizedKeyCache) PutParsedKey(keyID string, key jwk.Key) {
	c.parsedKeys.Put(keyID, key)
}

// GetUserKeyset retrieves a user keyset from cache
func (c *OptimizedKeyCache) GetUserKeyset(userID int) (*model.UserKeyset, bool) {
	key := formatUserKeysetKey(userID)
	if value, exists := c.userKeysets.Get(key); exists {
		c.recordHit()
		return value.(*model.UserKeyset), true
	}
	c.recordMiss()
	return nil, false
}

// PutUserKeyset stores a user keyset in cache
func (c *OptimizedKeyCache) PutUserKeyset(userID int, keyset *model.UserKeyset) {
	key := formatUserKeysetKey(userID)
	c.userKeysets.Put(key, keyset)
}

// GetUserIDByKeyID retrieves userID for a given keyID from reverse lookup cache
func (c *OptimizedKeyCache) GetUserIDByKeyID(keyID string) (int, bool) {
	if value, exists := c.keyToUser.Get(keyID); exists {
		c.recordHit()
		return value.(int), true
	}
	c.recordMiss()
	return 0, false
}

// PutUserIDByKeyID stores a keyID -> userID mapping in reverse lookup cache
func (c *OptimizedKeyCache) PutUserIDByKeyID(keyID string, userID int) {
	c.keyToUser.Put(keyID, userID)
}

// RemoveParsedKey removes a parsed key from cache
func (c *OptimizedKeyCache) RemoveParsedKey(keyID string) {
	c.parsedKeys.Remove(keyID)
}

// RemoveUserKeyset removes a user keyset from cache
func (c *OptimizedKeyCache) RemoveUserKeyset(userID int) {
	key := formatUserKeysetKey(userID)
	c.userKeysets.Remove(key)
}

// RemoveUserIDByKeyID removes a keyID -> userID mapping from cache
func (c *OptimizedKeyCache) RemoveUserIDByKeyID(keyID string) {
	c.keyToUser.Remove(keyID)
}

// CleanupExpired removes expired items from all caches and returns the total count
func (c *OptimizedKeyCache) CleanupExpired() int {
	expired := c.parsedKeys.CleanupExpired()
	expired += c.userKeysets.CleanupExpired()
	expired += c.keyToUser.CleanupExpired()

	c.metrics.mutex.Lock()
	c.metrics.expiredCleanups += int64(expired)
	c.metrics.mutex.Unlock()

	return expired
}

// GetMetrics returns current cache performance metrics
func (c *OptimizedKeyCache) GetMetrics() CacheMetrics {
	c.metrics.mutex.RLock()
	defer c.metrics.mutex.RUnlock()
	return *c.metrics
}

// ResetMetrics resets all performance metrics
func (c *OptimizedKeyCache) ResetMetrics() {
	c.metrics.mutex.Lock()
	defer c.metrics.mutex.Unlock()
	c.metrics.hits = 0
	c.metrics.misses = 0
	c.metrics.evictions = 0
	c.metrics.expiredCleanups = 0
}

// recordHit increments the cache hit counter
func (c *OptimizedKeyCache) recordHit() {
	c.metrics.mutex.Lock()
	c.metrics.hits++
	c.metrics.mutex.Unlock()
}

// recordMiss increments the cache miss counter
func (c *OptimizedKeyCache) recordMiss() {
	c.metrics.mutex.Lock()
	c.metrics.misses++
	c.metrics.mutex.Unlock()
}

// formatUserKeysetKey creates a consistent key format for user keyset caching
func formatUserKeysetKey(userID int) string {
	return fmt.Sprintf("user:%d", userID)
}
