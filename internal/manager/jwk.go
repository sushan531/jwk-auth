package manager

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/sushan531/jwk-auth/internal/repository"
	"github.com/sushan531/jwk-auth/model"
)

type JwkManager interface {
	// Session-based key management
	CreateSessionKey(userID int, deviceType string) (keyID string, err error)
	DeleteSessionKey(userID int, keyID string) error
	GetSessionKeys(userID int) ([]string, error)

	// Key retrieval for token operations
	GetPrivateKeyByID(keyID string) (*rsa.PrivateKey, error)
	GetPublicKeyBy(keyID string) (*rsa.PublicKey, error)
	GetPublicKeys() ([]*rsa.PublicKey, error)
	GetUserPublicKeys(userID int) ([]*rsa.PublicKey, error)

	// Database operations
	LoadUserKeysFromDB(userID int) error

	// Cache management operations
	CleanupExpiredCache() int
	GetCacheMetrics() CacheMetrics
	ResetCacheMetrics()
}

type jwkManager struct {
	userRepo repository.UserAuthRepository
	// Optimized cache with LRU eviction and TTL support
	cache *OptimizedKeyCache
	// Legacy maps for backward compatibility (deprecated)
	userKeysets map[int]*model.UserKeyset
	parsedKeys  map[string]jwk.Key
	keyToUser   map[string]int
}

func NewJwkManager(userRepo repository.UserAuthRepository) JwkManager {
	// Configure cache with reasonable defaults:
	// - 1000 parsed keys (most frequently accessed)
	// - 500 user keysets (moderate capacity for user data)
	// - 2000 reverse lookups (larger capacity for key->user mapping)
	// - 30 minute TTL to balance performance and memory usage
	cache := NewOptimizedKeyCache(1000, 500, 2000, 30*time.Minute)

	return &jwkManager{
		userRepo:    userRepo,
		cache:       cache,
		userKeysets: make(map[int]*model.UserKeyset), // Legacy compatibility
		parsedKeys:  make(map[string]jwk.Key),        // Legacy compatibility
		keyToUser:   make(map[string]int),            // Legacy compatibility
	}
}

// CreateSessionKey creates a new RSA key for a user session using consolidated keyset storage
// Implements single device login - invalidates existing sessions for the same device type
func (j *jwkManager) CreateSessionKey(userID int, deviceType string) (string, error) {
	// Generate new RSA private key using rsa.GenerateKey()
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return "", fmt.Errorf("failed to generate private key: %w", err)
	}

	// Use jwk.Import(privateKey) to create JWK from RSA key
	key, err := jwk.Import(privateKey)
	if err != nil {
		return "", fmt.Errorf("failed to import RSA key into JWK: %w", err)
	}

	// Generate unique key ID using nanoseconds for uniqueness
	keyID := fmt.Sprintf("%s-%d-%d", deviceType, userID, time.Now().UnixNano())

	// Set key ID using key.Set(jwk.KeyIDKey, keyID)
	if err := key.Set(jwk.KeyIDKey, keyID); err != nil {
		return "", fmt.Errorf("failed to set key ID: %w", err)
	}

	// Load user's existing keyset from database
	keyset, err := j.userRepo.GetUserKeyset(userID)
	if err != nil {
		// If no keyset exists, create a new one
		keyset = &model.UserKeyset{
			UserID:  userID,
			KeyData: make(map[string]string),
			Created: time.Now(),
			Updated: time.Now(),
		}
	}

	// Remove old device key if exists (single device login)
	if keyset.HasDeviceKey(deviceType) {
		// Get the old key to remove it from caches
		if oldKey, err := keyset.GetDeviceKey(deviceType); err == nil {
			if oldKeyID, exists := oldKey.KeyID(); exists {
				// Remove from optimized caches
				j.cache.RemoveParsedKey(oldKeyID)
				j.cache.RemoveUserIDByKeyID(oldKeyID)

				// Remove from legacy caches for backward compatibility
				delete(j.parsedKeys, oldKeyID)
				delete(j.keyToUser, oldKeyID)
			}
		}
		keyset.RemoveDeviceKey(deviceType)
	}

	// Use UserKeyset.SetDeviceKey() to add new JWK key to keyset
	if err := keyset.SetDeviceKey(deviceType, key); err != nil {
		return "", fmt.Errorf("failed to set device key in keyset: %w", err)
	}

	// Save updated keyset to database using json.Marshal(key)
	keysetJSON, err := json.Marshal(keyset.KeyData)
	if err != nil {
		return "", fmt.Errorf("failed to marshal keyset: %w", err)
	}

	if err := j.userRepo.SaveUserKeyset(userID, string(keysetJSON)); err != nil {
		return "", fmt.Errorf("failed to save keyset to database: %w", err)
	}

	// Update optimized caches for performance
	j.cache.PutUserKeyset(userID, keyset)
	j.cache.PutParsedKey(keyID, key)
	j.cache.PutUserIDByKeyID(keyID, userID)

	// Update legacy caches for backward compatibility
	j.userKeysets[userID] = keyset
	j.parsedKeys[keyID] = key
	j.keyToUser[keyID] = userID

	return keyID, nil
}

// DeleteSessionKey removes a session key for a user using consolidated keyset storage
// Implements requirements: 2.4, 3.2, 3.4
func (j *jwkManager) DeleteSessionKey(userID int, keyID string) error {
	// Load user's keyset from database
	keyset, err := j.userRepo.GetUserKeyset(userID)
	if err != nil {
		return fmt.Errorf("failed to load user keyset: %w", err)
	}

	// Find and remove the specified device key from keyset
	var deviceTypeToRemove string
	found := false

	// Search through all device keys to find the one with matching keyID
	for deviceType, keyData := range keyset.KeyData {
		// Parse the JWK key to get its key ID
		key, err := jwk.ParseKey([]byte(keyData))
		if err != nil {
			continue // Skip invalid keys
		}

		// Check if this is the key we're looking for
		if storedKeyID, exists := key.KeyID(); exists && storedKeyID == keyID {
			deviceTypeToRemove = deviceType
			found = true
			break
		}
	}

	if !found {
		return fmt.Errorf("key ID %s not found in user %d's keyset", keyID, userID)
	}

	// Remove the device key from the keyset
	keyset.RemoveDeviceKey(deviceTypeToRemove)

	// Save updated keyset or delete if empty
	if keyset.IsEmpty() {
		// If keyset is empty, delete the entire keyset from database
		if err := j.userRepo.DeleteUserKeyset(userID); err != nil {
			return fmt.Errorf("failed to delete empty keyset: %w", err)
		}
		// Remove from optimized cache
		j.cache.RemoveUserKeyset(userID)
		// Remove from legacy cache for backward compatibility
		delete(j.userKeysets, userID)
	} else {
		// Save the updated keyset to database
		keysetJSON, err := json.Marshal(keyset.KeyData)
		if err != nil {
			return fmt.Errorf("failed to marshal updated keyset: %w", err)
		}

		if err := j.userRepo.SaveUserKeyset(userID, string(keysetJSON)); err != nil {
			return fmt.Errorf("failed to save updated keyset: %w", err)
		}
		// Update optimized cache
		j.cache.PutUserKeyset(userID, keyset)
		// Update legacy cache for backward compatibility
		j.userKeysets[userID] = keyset
	}

	// Update optimized caches - remove the specific key
	j.cache.RemoveParsedKey(keyID)
	j.cache.RemoveUserIDByKeyID(keyID)

	// Update legacy caches for backward compatibility
	delete(j.parsedKeys, keyID)
	delete(j.keyToUser, keyID)

	return nil
}

// GetSessionKeys returns all active key IDs for a user using consolidated keyset storage
// Extracts key IDs from user's keyset using jwk library
func (j *jwkManager) GetSessionKeys(userID int) ([]string, error) {
	// Get user's consolidated keyset from database
	keyset, err := j.userRepo.GetUserKeyset(userID)
	if err != nil {
		// If no keyset exists, return empty list (not an error)
		if err.Error() == fmt.Sprintf("no keyset found for user %d", userID) {
			return []string{}, nil
		}
		return nil, fmt.Errorf("failed to get user keyset from database: %w", err)
	}

	var keyIDs []string
	// Extract key IDs from each device key in the keyset using jwk library
	for _, keyData := range keyset.KeyData {
		// Parse the JWK key to extract its key ID
		key, err := jwk.ParseKey([]byte(keyData))
		if err != nil {
			continue // Skip invalid keys
		}

		// Get the key ID from the parsed JWK
		if keyID, exists := key.KeyID(); exists {
			keyIDs = append(keyIDs, keyID)
		}
	}

	return keyIDs, nil
}

// GetPrivateKeyByID retrieves a private key by its ID using optimized caching and efficient reverse lookup
// Uses jwk.ParseKey() when loading from database and jwk.Export() to extract RSA key for JWT signing
func (j *jwkManager) GetPrivateKeyByID(keyID string) (*rsa.PrivateKey, error) {
	// Check optimized cache first - cache parsed jwk.Key objects for performance
	if key, exists := j.cache.GetParsedKey(keyID); exists {
		var rsaPrivateKey rsa.PrivateKey
		if err := jwk.Export(key, &rsaPrivateKey); err != nil {
			return nil, fmt.Errorf("failed to export private key from cache: %w", err)
		}
		return &rsaPrivateKey, nil
	}

	// Try efficient reverse lookup to find userID first
	var keyset *model.UserKeyset
	var err error

	if userID, exists := j.cache.GetUserIDByKeyID(keyID); exists {
		// We know which user owns this key, try to get their keyset from cache
		if cachedKeyset, found := j.cache.GetUserKeyset(userID); found {
			keyset = cachedKeyset
		} else {
			// Load from database and cache it
			keyset, err = j.userRepo.GetUserKeyset(userID)
			if err != nil {
				// Key might have been deleted, fall back to full search
				keyset = nil
			} else {
				j.cache.PutUserKeyset(userID, keyset)
			}
		}
	}

	// If reverse lookup failed or keyset not found, fall back to database search
	if keyset == nil {
		keyset, err = j.userRepo.FindKeysetByKeyID(keyID)
		if err != nil {
			return nil, fmt.Errorf("key not found in consolidated storage: %w", err)
		}
		// Cache the keyset for future use
		j.cache.PutUserKeyset(keyset.UserID, keyset)
	}

	// Find the specific key within the keyset
	var foundKey jwk.Key
	for _, keyData := range keyset.KeyData {
		// Use jwk.ParseKey() when loading from database
		key, err := jwk.ParseKey([]byte(keyData))
		if err != nil {
			continue // Skip invalid keys
		}

		// Check if this is the key we're looking for
		if storedKeyID, exists := key.KeyID(); exists && storedKeyID == keyID {
			foundKey = key
			break
		}
	}

	if foundKey == nil {
		return nil, fmt.Errorf("key ID %s not found in keyset for user %d", keyID, keyset.UserID)
	}

	// Cache parsed jwk.Key object and reverse lookup for performance
	j.cache.PutParsedKey(keyID, foundKey)
	j.cache.PutUserIDByKeyID(keyID, keyset.UserID)

	// Update legacy caches for backward compatibility
	j.parsedKeys[keyID] = foundKey
	j.keyToUser[keyID] = keyset.UserID

	// Use jwk.Export(key, &rsaPrivateKey) to extract RSA key for JWT signing
	var rsaPrivateKey rsa.PrivateKey
	if err := jwk.Export(foundKey, &rsaPrivateKey); err != nil {
		return nil, fmt.Errorf("failed to export private key: %w", err)
	}

	return &rsaPrivateKey, nil
}

// GetPublicKeyBy retrieves a public key by its ID
func (j *jwkManager) GetPublicKeyBy(keyID string) (*rsa.PublicKey, error) {
	// Use GetPrivateKeyByID which handles database fallback
	privateKey, err := j.GetPrivateKeyByID(keyID)
	if err != nil {
		return nil, fmt.Errorf("failed to get private key: %w", err)
	}

	return &privateKey.PublicKey, nil
}

// GetPublicKeys returns all public keys from all users using consolidated keyset storage
func (j *jwkManager) GetPublicKeys() ([]*rsa.PublicKey, error) {
	// Get all user keysets from consolidated storage
	allKeysets, err := j.userRepo.GetAllUserKeysets()
	if err != nil {
		return nil, fmt.Errorf("failed to get all user keysets: %w", err)
	}

	var publicKeys []*rsa.PublicKey
	for _, keyset := range allKeysets {
		// Process each device key in the keyset
		for _, keyData := range keyset.KeyData {
			// Parse key using jwk.ParseKey()
			key, err := jwk.ParseKey([]byte(keyData))
			if err != nil {
				continue // Skip invalid keys
			}

			// Export to RSA using jwk.Export()
			var rsaPrivateKey rsa.PrivateKey
			if err := jwk.Export(key, &rsaPrivateKey); err != nil {
				continue // Skip keys that can't be exported
			}

			publicKeys = append(publicKeys, &rsaPrivateKey.PublicKey)
		}
	}

	return publicKeys, nil
}

// GetUserPublicKeys returns all public keys for a specific user using consolidated keyset storage
func (j *jwkManager) GetUserPublicKeys(userID int) ([]*rsa.PublicKey, error) {
	// Get user's consolidated keyset from database
	keyset, err := j.userRepo.GetUserKeyset(userID)
	if err != nil {
		// If no keyset exists, return empty list (not an error)
		if err.Error() == fmt.Sprintf("no keyset found for user %d", userID) {
			return []*rsa.PublicKey{}, nil
		}
		return nil, fmt.Errorf("failed to get user keyset: %w", err)
	}

	var publicKeys []*rsa.PublicKey
	// Process each device key in the user's keyset
	for _, keyData := range keyset.KeyData {
		// Parse key using jwk.ParseKey()
		key, err := jwk.ParseKey([]byte(keyData))
		if err != nil {
			continue // Skip invalid keys
		}

		// Export to RSA using jwk.Export()
		var rsaPrivateKey rsa.PrivateKey
		if err := jwk.Export(key, &rsaPrivateKey); err != nil {
			continue // Skip keys that can't be exported
		}

		publicKeys = append(publicKeys, &rsaPrivateKey.PublicKey)
	}

	return publicKeys, nil
}

// LoadUserKeysFromDB loads all keys for a specific user from consolidated keyset storage into memory cache
func (j *jwkManager) LoadUserKeysFromDB(userID int) error {
	// Get user's consolidated keyset from database
	keyset, err := j.userRepo.GetUserKeyset(userID)
	if err != nil {
		// If no keyset exists, just clear the cache for this user
		if err.Error() == fmt.Sprintf("no keyset found for user %d", userID) {
			// Clear existing cache for this user
			for keyID, cachedUserID := range j.keyToUser {
				if cachedUserID == userID {
					delete(j.keyToUser, keyID)
					delete(j.parsedKeys, keyID)
				}
			}
			delete(j.userKeysets, userID)
			return nil
		}
		return fmt.Errorf("failed to load user keyset from database: %w", err)
	}

	// Clear existing cache for this user from optimized cache
	j.cache.RemoveUserKeyset(userID)

	// Clear existing cache for this user from legacy caches
	// Remove from reverse lookup cache
	for keyID, cachedUserID := range j.keyToUser {
		if cachedUserID == userID {
			j.cache.RemoveParsedKey(keyID)
			j.cache.RemoveUserIDByKeyID(keyID)
			delete(j.keyToUser, keyID)
			delete(j.parsedKeys, keyID)
		}
	}
	delete(j.userKeysets, userID)

	// Load fresh data from consolidated keyset into cache
	// Cache parsed jwk.Key objects for performance, not raw JSON
	for _, keyData := range keyset.KeyData {
		// Parse the JWK key using jwk.ParseKey()
		key, err := jwk.ParseKey([]byte(keyData))
		if err != nil {
			continue // Skip invalid keys
		}

		// Get the key ID for caching
		if keyID, exists := key.KeyID(); exists {
			// Cache parsed jwk.Key objects in optimized cache for performance
			j.cache.PutParsedKey(keyID, key)
			j.cache.PutUserIDByKeyID(keyID, userID)

			// Cache in legacy caches for backward compatibility
			j.parsedKeys[keyID] = key
			j.keyToUser[keyID] = userID
		}
	}

	// Cache the entire keyset for future operations in optimized cache
	j.cache.PutUserKeyset(userID, keyset)
	// Cache in legacy cache for backward compatibility
	j.userKeysets[userID] = keyset

	return nil
}

// Helper method to remove key from user's key list
// TODO: This is a temporary compatibility method - will be updated in task 3.3
func (j *jwkManager) removeKeyFromUser(userID int, keyID string) {
	// Remove from reverse lookup cache
	delete(j.keyToUser, keyID)
	delete(j.parsedKeys, keyID)

	// Remove from user keyset cache if it exists
	if keyset, exists := j.userKeysets[userID]; exists {
		// Find device type for this keyID and remove it
		for deviceType, keyData := range keyset.KeyData {
			// Parse key to get its ID
			if key, err := jwk.ParseKey([]byte(keyData)); err == nil {
				var storedKeyID string
				if err := key.Get(jwk.KeyIDKey, &storedKeyID); err == nil && storedKeyID == keyID {
					keyset.RemoveDeviceKey(deviceType)
					break
				}
			}
		}
		// If keyset is empty, remove it
		if keyset.IsEmpty() {
			delete(j.userKeysets, userID)
		}
	}
}

// CleanupExpiredCache removes expired items from all caches and returns the number of items removed
func (j *jwkManager) CleanupExpiredCache() int {
	return j.cache.CleanupExpired()
}

// GetCacheMetrics returns current cache performance metrics
func (j *jwkManager) GetCacheMetrics() CacheMetrics {
	return j.cache.GetMetrics()
}

// ResetCacheMetrics resets all cache performance metrics
func (j *jwkManager) ResetCacheMetrics() {
	j.cache.ResetMetrics()
}
