package manager

import (
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/sushan531/jwk-auth/internal/config"
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
}

type jwkManager struct {
	userRepo      repository.UserAuthRepository
	config        *config.Config
	encryptionMgr EncryptionManager
	userKeysets   map[int]*model.UserKeyset
	parsedJWKS    map[int]jwk.Set // JWKS-specific cache for complete JWKS per user
	parsedKeys    map[string]jwk.Key
	keyToUser     map[string]int
}

func NewJwkManager(userRepo repository.UserAuthRepository, cfg *config.Config) JwkManager {
	return &jwkManager{
		userRepo:      userRepo,
		config:        cfg,
		encryptionMgr: NewEncryptionManager(),
		userKeysets:   make(map[int]*model.UserKeyset),
		parsedJWKS:    make(map[int]jwk.Set),
		parsedKeys:    make(map[string]jwk.Key),
		keyToUser:     make(map[string]int),
	}
}

// decryptKeyset decrypts the keyset data and returns a copy with decrypted KeyData
func (j *jwkManager) decryptKeyset(keyset *model.UserKeyset) (*model.UserKeyset, error) {
	if keyset.KeyData == "" {
		// Return a copy with empty KeyData
		decryptedKeyset := *keyset
		decryptedKeyset.KeyData = ""
		return &decryptedKeyset, nil
	}

	// Decrypt the KeyData
	decryptedData, err := j.encryptionMgr.Decrypt(keyset.KeyData, keyset.EncryptionKey)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt keyset data: %w", err)
	}

	// Return a copy with decrypted KeyData
	decryptedKeyset := *keyset
	decryptedKeyset.KeyData = string(decryptedData)
	return &decryptedKeyset, nil
}

// encryptKeyset encrypts the keyset data and returns encrypted KeyData and EncryptionKey
func (j *jwkManager) encryptKeyset(keysetData string, existingKey string) (encryptedData string, encryptionKey string, err error) {
	// Use existing key if provided, otherwise generate new one
	if existingKey != "" {
		encryptionKey = existingKey
	} else {
		encryptionKey, err = j.encryptionMgr.GenerateKey()
		if err != nil {
			return "", "", fmt.Errorf("failed to generate encryption key: %w", err)
		}
	}

	// Encrypt the keyset data
	encryptedData, err = j.encryptionMgr.Encrypt([]byte(keysetData), encryptionKey)
	if err != nil {
		return "", "", fmt.Errorf("failed to encrypt keyset data: %w", err)
	}

	return encryptedData, encryptionKey, nil
}

// findKeysetByKeyID searches through all user keysets to find the one containing the specified key ID
// This method handles decryption internally
func (j *jwkManager) findKeysetByKeyID(keyID string) (*model.UserKeyset, error) {
	// Get all encrypted user keysets
	allEncryptedKeysets, err := j.userRepo.GetAllUserKeysets()
	if err != nil {
		return nil, fmt.Errorf("failed to get all user keysets: %w", err)
	}

	// Search through each keyset for the key ID
	for _, encryptedKeyset := range allEncryptedKeysets {
		// Decrypt the keyset
		keyset, err := j.decryptKeyset(encryptedKeyset)
		if err != nil {
			continue // Skip keysets that can't be decrypted
		}

		// Parse JWKS and search for the key ID
		jwks, err := keyset.GetJWKS()
		if err != nil {
			continue // Skip invalid JWKS
		}

		// Iterate through keys in the JWKS
		for i := 0; i < jwks.Len(); i++ {
			key, _ := jwks.Key(i)

			// Match "kid" claim against target keyID
			var currentKeyID string
			if err := key.Get(jwk.KeyIDKey, &currentKeyID); err == nil && currentKeyID == keyID {
				// Return the decrypted UserKeyset containing the matching key
				return keyset, nil
			}
		}
	}

	return nil, fmt.Errorf("no keyset found containing key ID: %s", keyID)
}

// CreateSessionKey creates a new RSA key for a user session using JWKS format
// Implements single device login - invalidates existing sessions for the same device type
func (j *jwkManager) CreateSessionKey(userID int, deviceType string) (string, error) {
	// Use rsa.GenerateKey() to create RSA private key
	privateKey, err := rsa.GenerateKey(rand.Reader, j.config.JWT.RSAKeySize)
	if err != nil {
		return "", fmt.Errorf("failed to generate private key: %w", err)
	}

	// Use jwk.Import(privateKey) to create JWK from RSA key
	key, err := jwk.Import(privateKey)
	if err != nil {
		return "", fmt.Errorf("failed to import RSA key into JWK: %w", err)
	}

	// Set "kid" claim using key.Set(jwk.KeyIDKey, keyID) with format: deviceType-userID-timestamp
	keyID := fmt.Sprintf("%s-%d-%d", deviceType, userID, time.Now().UnixNano())
	if err := key.Set(jwk.KeyIDKey, keyID); err != nil {
		return "", fmt.Errorf("failed to set key ID: %w", err)
	}

	// Set "use" claim using key.Set("use", deviceType) for device identification
	if err := key.Set("use", deviceType); err != nil {
		return "", fmt.Errorf("failed to set use claim: %w", err)
	}

	// Load user's existing JWKS using GetUserKeyset() and GetJWKS()
	encryptedKeyset, err := j.userRepo.GetUserKeyset(userID)
	var keyset *model.UserKeyset
	if err != nil {
		// If no keyset exists, create a new one
		keyset = &model.UserKeyset{
			UserID:        userID,
			KeyData:       "",
			EncryptionKey: "",
			Created:       time.Now(),
			Updated:       time.Now(),
		}
	} else {
		// Decrypt the existing keyset
		keyset, err = j.decryptKeyset(encryptedKeyset)
		if err != nil {
			return "", fmt.Errorf("failed to decrypt existing keyset: %w", err)
		}
	}

	// Remove old device key using SetDeviceKey() (which handles replacement)
	if keyset.HasDeviceKey(deviceType) {
		// Get the old key to remove it from caches
		if oldKey, err := keyset.GetDeviceKey(deviceType); err == nil {
			if oldKeyID, exists := oldKey.KeyID(); exists {
				// Remove from caches
				delete(j.parsedKeys, oldKeyID)
				delete(j.keyToUser, oldKeyID)
			}
		}
	}

	// Use SetDeviceKey() to add/replace the device key in JWKS
	if err := keyset.SetDeviceKey(deviceType, key); err != nil {
		return "", fmt.Errorf("failed to set device key in JWKS: %w", err)
	}

	// Encrypt and save updated JWKS
	var existingEncryptionKey string
	if encryptedKeyset != nil {
		existingEncryptionKey = encryptedKeyset.EncryptionKey
	}
	encryptedData, encryptionKey, err := j.encryptKeyset(keyset.KeyData, existingEncryptionKey)
	if err != nil {
		return "", fmt.Errorf("failed to encrypt keyset: %w", err)
	}

	if err := j.userRepo.SaveUserKeyset(userID, encryptedData, encryptionKey); err != nil {
		return "", fmt.Errorf("failed to save JWKS to database: %w", err)
	}

	// Update memory caches with new key and JWKS
	j.userKeysets[userID] = keyset
	j.parsedKeys[keyID] = key
	j.keyToUser[keyID] = userID

	// Update JWKS cache
	if jwks, err := keyset.GetJWKS(); err == nil {
		j.parsedJWKS[userID] = jwks
	}

	return keyID, nil
}

// DeleteSessionKey removes a session key for a user using consolidated keyset storage
// Implements requirements: 2.4, 3.2, 3.4
func (j *jwkManager) DeleteSessionKey(userID int, keyID string) error {
	// Load user's keyset from database
	encryptedKeyset, err := j.userRepo.GetUserKeyset(userID)
	if err != nil {
		return fmt.Errorf("failed to load user keyset: %w", err)
	}

	// Decrypt the keyset
	keyset, err := j.decryptKeyset(encryptedKeyset)
	if err != nil {
		return fmt.Errorf("failed to decrypt keyset: %w", err)
	}

	// Find and remove the specified device key from JWKS
	var deviceTypeToRemove string
	found := false

	// Parse the JWKS to search for the key
	jwks, err := keyset.GetJWKS()
	if err != nil {
		return fmt.Errorf("failed to parse JWKS: %w", err)
	}

	// Search through all keys in the JWKS to find the one with matching keyID
	for i := 0; i < jwks.Len(); i++ {
		key, _ := jwks.Key(i)

		// Check if this is the key we're looking for
		if storedKeyID, exists := key.KeyID(); exists && storedKeyID == keyID {
			// Get the device type from the "use" claim
			var use string
			if err := key.Get("use", &use); err == nil {
				deviceTypeToRemove = use
				found = true
				break
			}
		}
	}

	if !found {
		return fmt.Errorf("key ID %s not found in user %d's keyset", keyID, userID)
	}

	// Remove the device key from the JWKS
	if err := keyset.RemoveDeviceKey(deviceTypeToRemove); err != nil {
		return fmt.Errorf("failed to remove device key: %w", err)
	}

	// Save updated keyset or delete if empty
	if keyset.IsEmpty() {
		// If keyset is empty, delete the entire keyset from database
		if err := j.userRepo.DeleteUserKeyset(userID); err != nil {
			return fmt.Errorf("failed to delete empty keyset: %w", err)
		}
		// Remove from cache
		delete(j.userKeysets, userID)
		delete(j.parsedJWKS, userID)
	} else {
		// Encrypt and save the updated keyset to database
		encryptedData, encryptionKey, err := j.encryptKeyset(keyset.KeyData, encryptedKeyset.EncryptionKey)
		if err != nil {
			return fmt.Errorf("failed to encrypt updated keyset: %w", err)
		}

		if err := j.userRepo.SaveUserKeyset(userID, encryptedData, encryptionKey); err != nil {
			return fmt.Errorf("failed to save updated keyset: %w", err)
		}
		// Update cache with decrypted keyset
		j.userKeysets[userID] = keyset
		// Update JWKS cache
		if jwks, err := keyset.GetJWKS(); err == nil {
			j.parsedJWKS[userID] = jwks
		}
	}

	// Update caches - remove the specific key
	delete(j.parsedKeys, keyID)
	delete(j.keyToUser, keyID)

	return nil
}

// GetSessionKeys returns all active key IDs for a user using consolidated keyset storage
// Extracts key IDs from user's keyset using jwk library
func (j *jwkManager) GetSessionKeys(userID int) ([]string, error) {
	// Get user's consolidated keyset from database
	encryptedKeyset, err := j.userRepo.GetUserKeyset(userID)
	if err != nil {
		// If no keyset exists, return empty list (not an error)
		if err.Error() == fmt.Sprintf("no keyset found for user %d", userID) {
			return []string{}, nil
		}
		return nil, fmt.Errorf("failed to get user keyset from database: %w", err)
	}

	// Decrypt the keyset
	keyset, err := j.decryptKeyset(encryptedKeyset)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt keyset: %w", err)
	}

	var keyIDs []string
	// Parse the JWKS and extract key IDs
	jwks, err := keyset.GetJWKS()
	if err != nil {
		return nil, fmt.Errorf("failed to parse JWKS: %w", err)
	}

	// Iterate through JWKS keys using keySet.Len() and keySet.Key(i)
	for i := 0; i < jwks.Len(); i++ {
		key, _ := jwks.Key(i)

		// Extract "kid" claim from each key using key.Get(jwk.KeyIDKey)
		if keyID, exists := key.KeyID(); exists {
			keyIDs = append(keyIDs, keyID)
		}
	}

	return keyIDs, nil
}

// GetPrivateKeyByID retrieves a private key by its ID
// Uses jwk.ParseKey() when loading from database and jwk.Export() to extract RSA key for JWT signing
func (j *jwkManager) GetPrivateKeyByID(keyID string) (*rsa.PrivateKey, error) {
	// Check memory cache first
	if key, exists := j.parsedKeys[keyID]; exists {
		var rsaPrivateKey rsa.PrivateKey
		if err := jwk.Export(key, &rsaPrivateKey); err != nil {
			return nil, fmt.Errorf("failed to export private key from cache: %w", err)
		}
		return &rsaPrivateKey, nil
	}

	// Try reverse lookup to find userID first
	var keyset *model.UserKeyset
	var err error

	if userID, exists := j.keyToUser[keyID]; exists {
		// We know which user owns this key, try to get their keyset from cache
		if cachedKeyset, found := j.userKeysets[userID]; found {
			keyset = cachedKeyset
		} else {
			// Load from database and cache it
			encryptedKeyset, err := j.userRepo.GetUserKeyset(userID)
			if err != nil {
				// Key might have been deleted, fall back to full search
				keyset = nil
			} else {
				// Decrypt the keyset
				keyset, err = j.decryptKeyset(encryptedKeyset)
				if err != nil {
					keyset = nil
				} else {
					j.userKeysets[userID] = keyset
				}
			}
		}
	}

	// If reverse lookup failed or keyset not found, fall back to database search
	if keyset == nil {
		keyset, err = j.findKeysetByKeyID(keyID)
		if err != nil {
			return nil, fmt.Errorf("key not found in consolidated storage: %w", err)
		}
		// Cache the decrypted keyset for future use
		j.userKeysets[keyset.UserID] = keyset
	}

	// Find the specific key within the JWKS
	jwks, err := keyset.GetJWKS()
	if err != nil {
		return nil, fmt.Errorf("failed to parse JWKS: %w", err)
	}

	var foundKey jwk.Key
	// Iterate through JWKS keys using keySet.Len() and keySet.Key(i)
	for i := 0; i < jwks.Len(); i++ {
		key, _ := jwks.Key(i)

		// Find specific key by iterating and matching "kid" claim
		if storedKeyID, exists := key.KeyID(); exists && storedKeyID == keyID {
			foundKey = key
			break
		}
	}

	if foundKey == nil {
		return nil, fmt.Errorf("key ID %s not found in keyset for user %d", keyID, keyset.UserID)
	}

	// Update caches
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
	allEncryptedKeysets, err := j.userRepo.GetAllUserKeysets()
	if err != nil {
		return nil, fmt.Errorf("failed to get all user keysets: %w", err)
	}

	var publicKeys []*rsa.PublicKey
	for _, encryptedKeyset := range allEncryptedKeysets {
		// Decrypt each keyset
		keyset, err := j.decryptKeyset(encryptedKeyset)
		if err != nil {
			continue // Skip keysets that can't be decrypted
		}

		// For GetPublicKeys: iterate through all user JWKS from GetAllUserKeysets()
		jwks, err := keyset.GetJWKS()
		if err != nil {
			continue // Skip invalid JWKS
		}

		// Parse each JWKS using GetJWKS() method
		for i := 0; i < jwks.Len(); i++ {
			key, _ := jwks.Key(i)

			// Extract RSA keys using jwk.Export() for each key in the set
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
	encryptedKeyset, err := j.userRepo.GetUserKeyset(userID)
	if err != nil {
		// If no keyset exists, return empty list (not an error)
		if err.Error() == fmt.Sprintf("no keyset found for user %d", userID) {
			return []*rsa.PublicKey{}, nil
		}
		return nil, fmt.Errorf("failed to get user keyset: %w", err)
	}

	// Decrypt the keyset
	keyset, err := j.decryptKeyset(encryptedKeyset)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt keyset: %w", err)
	}

	var publicKeys []*rsa.PublicKey
	// For GetUserPublicKeys: get specific user's JWKS using GetUserKeyset()
	jwks, err := keyset.GetJWKS()
	if err != nil {
		return nil, fmt.Errorf("failed to parse user JWKS: %w", err)
	}

	// Parse each JWKS using GetJWKS() method
	for i := 0; i < jwks.Len(); i++ {
		key, _ := jwks.Key(i)

		// Extract RSA keys using jwk.Export() for each key in the set
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
	encryptedKeyset, err := j.userRepo.GetUserKeyset(userID)
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

	// Decrypt the keyset
	keyset, err := j.decryptKeyset(encryptedKeyset)
	if err != nil {
		return fmt.Errorf("failed to decrypt keyset: %w", err)
	}

	// Clear existing cache for this user
	for keyID, cachedUserID := range j.keyToUser {
		if cachedUserID == userID {
			delete(j.keyToUser, keyID)
			delete(j.parsedKeys, keyID)
		}
	}
	delete(j.userKeysets, userID)
	delete(j.parsedJWKS, userID)

	// Load user's JWKS using GetUserKeyset() and GetJWKS()
	jwks, err := keyset.GetJWKS()
	if err != nil {
		return fmt.Errorf("failed to parse user JWKS: %w", err)
	}

	// Cache the complete JWKS in parsedJWKS map
	j.parsedJWKS[userID] = jwks

	// Extract individual keys and cache in parsedKeys map
	for i := 0; i < jwks.Len(); i++ {
		key, _ := jwks.Key(i)

		// Update keyToUser reverse lookup cache
		if keyID, exists := key.KeyID(); exists {
			j.parsedKeys[keyID] = key
			j.keyToUser[keyID] = userID
		}
	}

	// Cache the entire keyset
	j.userKeysets[userID] = keyset

	return nil
}
