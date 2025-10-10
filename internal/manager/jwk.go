package manager

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/sushan531/jwk-auth/internal/repository"
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
}

type jwkManager struct {
	userRepo repository.UserAuthRepository
	// Session-based key storage: keyID -> jwk.Key
	sessionKeys map[string]jwk.Key
	// User to keys mapping: userID -> []keyID
	userKeys map[int][]string
}

func NewJwkManager(userRepo repository.UserAuthRepository) JwkManager {
	return &jwkManager{
		userRepo:    userRepo,
		sessionKeys: make(map[string]jwk.Key),
		userKeys:    make(map[int][]string),
	}
}

// CreateSessionKey creates a new RSA key for a user session
// Implements single device login - invalidates existing sessions for the same device type
func (j *jwkManager) CreateSessionKey(userID int, deviceType string) (string, error) {
	// First, invalidate any existing sessions for this device type (database operation)
	existingSessions, err := j.userRepo.DeleteUserSessionsByDeviceType(userID, deviceType)
	if err != nil {
		return "", fmt.Errorf("failed to invalidate existing sessions: %w", err)
	}

	// Remove invalidated sessions from memory cache
	for _, session := range existingSessions {
		delete(j.sessionKeys, session.KeyID)
		j.removeKeyFromUser(userID, session.KeyID)
	}

	// Generate new RSA private key
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return "", fmt.Errorf("failed to generate private key: %w", err)
	}

	// Import into JWK
	key, err := jwk.Import(privateKey)
	if err != nil {
		return "", fmt.Errorf("failed to import RSA key into JWK: %w", err)
	}

	// Generate unique key ID
	keyID := fmt.Sprintf("%s-%d-%d", deviceType, userID, time.Now().Unix())
	if err := key.Set(jwk.KeyIDKey, keyID); err != nil {
		return "", fmt.Errorf("failed to set key ID: %w", err)
	}

	// Convert key to JSON for database storage
	keyBytes, err := json.Marshal(key)
	if err != nil {
		return "", fmt.Errorf("failed to marshal key: %w", err)
	}

	// Save to database FIRST (primary storage)
	if err := j.userRepo.SaveSessionKey(userID, keyID, string(keyBytes), deviceType); err != nil {
		return "", fmt.Errorf("failed to save key to database: %w", err)
	}

	// Cache in memory for performance (secondary storage)
	j.sessionKeys[keyID] = key
	j.userKeys[userID] = append(j.userKeys[userID], keyID)

	return keyID, nil
}

// DeleteSessionKey removes a session key for a user
func (j *jwkManager) DeleteSessionKey(userID int, keyID string) error {
	// Remove from database FIRST (primary storage)
	if err := j.userRepo.DeleteSessionKey(userID, keyID); err != nil {
		return fmt.Errorf("failed to delete key from database: %w", err)
	}

	// Remove from memory cache (secondary storage)
	delete(j.sessionKeys, keyID)
	j.removeKeyFromUser(userID, keyID)

	return nil
}

// GetSessionKeys returns all active key IDs for a user (from database)
func (j *jwkManager) GetSessionKeys(userID int) ([]string, error) {
	// Always fetch from database to ensure consistency
	sessionKeys, err := j.userRepo.GetUserSessionKeys(userID)
	if err != nil {
		return nil, fmt.Errorf("failed to get session keys from database: %w", err)
	}

	var keyIDs []string
	for _, sessionKey := range sessionKeys {
		keyIDs = append(keyIDs, sessionKey.KeyID)
	}

	return keyIDs, nil
}

// GetPrivateKeyByID retrieves a private key by its ID
func (j *jwkManager) GetPrivateKeyByID(keyID string) (*rsa.PrivateKey, error) {
	// Check memory cache first
	if key, exists := j.sessionKeys[keyID]; exists {
		var rsaPrivateKey rsa.PrivateKey
		if err := jwk.Export(key, &rsaPrivateKey); err != nil {
			return nil, fmt.Errorf("failed to export private key from cache: %w", err)
		}
		return &rsaPrivateKey, nil
	}

	// If not in cache, fetch from database
	sessionKey, err := j.userRepo.GetSessionKey(keyID)
	if err != nil {
		return nil, fmt.Errorf("key not found in database: %w", err)
	}

	// Parse the key from database
	key, err := jwk.ParseKey([]byte(sessionKey.KeyData))
	if err != nil {
		return nil, fmt.Errorf("failed to parse key from database: %w", err)
	}

	// Cache it for future use
	j.sessionKeys[keyID] = key
	j.userKeys[sessionKey.UserID] = append(j.userKeys[sessionKey.UserID], keyID)

	// Export and return
	var rsaPrivateKey rsa.PrivateKey
	if err := jwk.Export(key, &rsaPrivateKey); err != nil {
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

// GetPublicKeys returns all public keys from all sessions (from database)
func (j *jwkManager) GetPublicKeys() ([]*rsa.PublicKey, error) {
	// Get all session keys from database
	allSessions, err := j.userRepo.GetAllSessionKeys()
	if err != nil {
		return nil, fmt.Errorf("failed to get all session keys: %w", err)
	}

	var publicKeys []*rsa.PublicKey
	for _, sessionKey := range allSessions {
		// Parse key
		key, err := jwk.ParseKey([]byte(sessionKey.KeyData))
		if err != nil {
			continue // Skip invalid keys
		}

		// Export to RSA
		var rsaPrivateKey rsa.PrivateKey
		if err := jwk.Export(key, &rsaPrivateKey); err != nil {
			continue // Skip keys that can't be exported
		}

		publicKeys = append(publicKeys, &rsaPrivateKey.PublicKey)
	}

	return publicKeys, nil
}

// GetUserPublicKeys returns all public keys for a specific user (from database)
func (j *jwkManager) GetUserPublicKeys(userID int) ([]*rsa.PublicKey, error) {
	// Get user session keys from database
	sessionKeys, err := j.userRepo.GetUserSessionKeys(userID)
	if err != nil {
		return nil, fmt.Errorf("failed to get user session keys: %w", err)
	}

	var publicKeys []*rsa.PublicKey
	for _, sessionKey := range sessionKeys {
		// Parse key
		key, err := jwk.ParseKey([]byte(sessionKey.KeyData))
		if err != nil {
			continue // Skip invalid keys
		}

		// Export to RSA
		var rsaPrivateKey rsa.PrivateKey
		if err := jwk.Export(key, &rsaPrivateKey); err != nil {
			continue // Skip keys that can't be exported
		}

		publicKeys = append(publicKeys, &rsaPrivateKey.PublicKey)
	}

	return publicKeys, nil
}

// LoadUserKeysFromDB loads all keys for a specific user from database into memory cache
func (j *jwkManager) LoadUserKeysFromDB(userID int) error {
	sessionKeys, err := j.userRepo.GetUserSessionKeys(userID)
	if err != nil {
		return fmt.Errorf("failed to load user keys from database: %w", err)
	}

	// Clear existing cache for this user
	if existingKeys, exists := j.userKeys[userID]; exists {
		for _, keyID := range existingKeys {
			delete(j.sessionKeys, keyID)
		}
	}
	delete(j.userKeys, userID)

	// Load fresh data from database into cache
	for _, sessionKey := range sessionKeys {
		// Parse the individual key
		key, err := jwk.ParseKey([]byte(sessionKey.KeyData))
		if err != nil {
			continue // Skip invalid keys
		}

		// Cache in memory for performance
		j.sessionKeys[sessionKey.KeyID] = key
		j.userKeys[userID] = append(j.userKeys[userID], sessionKey.KeyID)
	}

	return nil
}

// Helper method to remove key from user's key list
func (j *jwkManager) removeKeyFromUser(userID int, keyID string) {
	keys := j.userKeys[userID]
	for i, k := range keys {
		if k == keyID {
			j.userKeys[userID] = append(keys[:i], keys[i+1:]...)
			break
		}
	}
	if len(j.userKeys[userID]) == 0 {
		delete(j.userKeys, userID)
	}
}
