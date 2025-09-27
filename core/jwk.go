package core

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwk"
)

type JwkManager interface {
	InitializeJwkSet(keyPrefix string) error
	AddOrReplaceKeyToSet(keyPrefix string) error
	GetPrivateKeyWithId(keyPrefix string) (*rsa.PrivateKey, string, error)
	GetJwkSetForStorage() ([]byte, error)
	GetJwkSetFromStorage(jwkSetJSON string) error
	GetPublicKeyBy(keyId string) (*rsa.PublicKey, error)
	// New methods for better performance and management
	GetKeyCount() int
	CleanupExpiredKeys() error
	GetKeyMetadata(keyPrefix string) (*KeyMetadata, error)
}

type KeyMetadata struct {
	KeyID     string    `json:"key_id"`
	CreatedAt time.Time `json:"created_at"`
	Algorithm string    `json:"algorithm"`
	KeySize   int       `json:"key_size"`
}

type jwkManager struct {
	jwkSet    jwk.Set
	mutex     sync.RWMutex
	validator *Validator
	config    *Config
	// Cache for frequently accessed keys
	keyCache map[string]*cachedKey
	// Metadata for key management
	keyMetadata map[string]*KeyMetadata
}

type cachedKey struct {
	privateKey *rsa.PrivateKey
	publicKey  *rsa.PublicKey
	keyID      string
	lastUsed   time.Time
}

func NewJwkManager(config *Config) JwkManager {
	return &jwkManager{
		validator:   NewValidator(),
		config:      config,
		keyCache:    make(map[string]*cachedKey),
		keyMetadata: make(map[string]*KeyMetadata),
	}
}

func (j *jwkManager) InitializeJwkSet(keyPrefix string) error {
	if err := j.validator.ValidateKeyPrefix(keyPrefix); err != nil {
		return NewAuthError("InitializeJwkSet", err)
	}

	j.mutex.Lock()
	defer j.mutex.Unlock()

	// Generate a new key set with a single key
	set := jwk.NewSet()

	privateKey, err := rsa.GenerateKey(rand.Reader, j.config.KeySize)
	if err != nil {
		return NewAuthError("InitializeJwkSet", fmt.Errorf("failed to generate private key: %w", err))
	}

	key, err := jwk.Import(privateKey)
	if err != nil {
		return NewAuthError("InitializeJwkSet", fmt.Errorf("failed to import RSA key into JWK: %w", err))
	}

	keyID := fmt.Sprintf("key-%s", keyPrefix)
	if err := key.Set(jwk.KeyIDKey, keyID); err != nil {
		return NewAuthError("InitializeJwkSet", fmt.Errorf("failed to set key ID: %w", err))
	}

	if err := set.AddKey(key); err != nil {
		return NewAuthError("InitializeJwkSet", fmt.Errorf("failed to add key to set: %w", err))
	}

	j.jwkSet = set

	// Cache the key and metadata
	j.keyCache[keyPrefix] = &cachedKey{
		privateKey: privateKey,
		publicKey:  &privateKey.PublicKey,
		keyID:      keyID,
		lastUsed:   time.Now(),
	}

	j.keyMetadata[keyPrefix] = &KeyMetadata{
		KeyID:     keyID,
		CreatedAt: time.Now(),
		Algorithm: j.config.Algorithm,
		KeySize:   j.config.KeySize,
	}

	return nil
}

func (j *jwkManager) AddOrReplaceKeyToSet(keyPrefix string) error {
	if err := j.validator.ValidateKeyPrefix(keyPrefix); err != nil {
		return NewAuthError("AddOrReplaceKeyToSet", err)
	}

	j.mutex.Lock()
	defer j.mutex.Unlock()

	if j.jwkSet == nil {
		j.mutex.Unlock() // Unlock before calling InitializeJwkSet
		err := j.InitializeJwkSet(keyPrefix)
		j.mutex.Lock() // Re-lock
		return err
	}

	keyID := fmt.Sprintf("key-%s", keyPrefix)

	// Remove old key if exists
	if oldKey, found := j.jwkSet.LookupKeyID(keyID); found {
		_ = j.jwkSet.RemoveKey(oldKey)
	}

	privateKey, err := rsa.GenerateKey(rand.Reader, j.config.KeySize)
	if err != nil {
		return NewAuthError("AddOrReplaceKeyToSet", fmt.Errorf("failed to generate private key: %w", err))
	}

	key, err := jwk.Import(privateKey)
	if err != nil {
		return NewAuthError("AddOrReplaceKeyToSet", fmt.Errorf("failed to import RSA key into JWK: %w", err))
	}

	if err := key.Set(jwk.KeyIDKey, keyID); err != nil {
		return NewAuthError("AddOrReplaceKeyToSet", fmt.Errorf("failed to set key ID: %w", err))
	}

	if err := j.jwkSet.AddKey(key); err != nil {
		return NewAuthError("AddOrReplaceKeyToSet", fmt.Errorf("failed to add key to set: %w", err))
	}

	// Update cache and metadata
	j.keyCache[keyPrefix] = &cachedKey{
		privateKey: privateKey,
		publicKey:  &privateKey.PublicKey,
		keyID:      keyID,
		lastUsed:   time.Now(),
	}

	j.keyMetadata[keyPrefix] = &KeyMetadata{
		KeyID:     keyID,
		CreatedAt: time.Now(),
		Algorithm: j.config.Algorithm,
		KeySize:   j.config.KeySize,
	}

	return nil
}

func (j *jwkManager) GetPrivateKeyWithId(keyPrefix string) (*rsa.PrivateKey, string, error) {
	if err := j.validator.ValidateKeyPrefix(keyPrefix); err != nil {
		return nil, "", NewAuthError("GetPrivateKeyWithId", err)
	}

	j.mutex.RLock()
	defer j.mutex.RUnlock()

	// Check cache first
	if cached, exists := j.keyCache[keyPrefix]; exists {
		cached.lastUsed = time.Now()
		return cached.privateKey, cached.keyID, nil
	}

	// Fallback to JWK set lookup
	keyID := fmt.Sprintf("key-%s", keyPrefix)
	key, foundKey := j.jwkSet.LookupKeyID(keyID)
	if !foundKey {
		return nil, "", NewAuthError("GetPrivateKeyWithId", ErrKeyNotFound)
	}

	var rsaPrivateKey rsa.PrivateKey
	if err := jwk.Export(key, &rsaPrivateKey); err != nil {
		return nil, "", NewAuthError("GetPrivateKeyWithId", fmt.Errorf("failed to export raw key: %w", err))
	}

	// Update cache
	j.keyCache[keyPrefix] = &cachedKey{
		privateKey: &rsaPrivateKey,
		publicKey:  &rsaPrivateKey.PublicKey,
		keyID:      keyID,
		lastUsed:   time.Now(),
	}

	return &rsaPrivateKey, keyID, nil
}

func (j *jwkManager) GetPublicKeyBy(keyId string) (*rsa.PublicKey, error) {
	j.mutex.RLock()
	defer j.mutex.RUnlock()

	if j.jwkSet == nil {
		return nil, NewAuthError("GetPublicKeyBy", ErrJWKSetNotInitialized)
	}

	key, found := j.jwkSet.LookupKeyID(keyId)
	if !found {
		return nil, NewAuthError("GetPublicKeyBy", fmt.Errorf("no key found with kid: %s", keyId))
	}

	var rsaPrivateKey rsa.PrivateKey
	if err := jwk.Export(key, &rsaPrivateKey); err != nil {
		return nil, NewAuthError("GetPublicKeyBy", fmt.Errorf("failed to export raw key: %w", err))
	}

	return &rsaPrivateKey.PublicKey, nil
}

func (j *jwkManager) GetJwkSetForStorage() ([]byte, error) {
	updatedJwkSetJSON, err := json.Marshal(j.jwkSet)
	if err != nil {
		return nil, err
	}
	return updatedJwkSetJSON, nil
}

func (j *jwkManager) GetJwkSetFromStorage(jwkSetJSON string) error {
	set, err := jwk.ParseString(jwkSetJSON)
	if err != nil {
		return err
	}
	j.jwkSet = set
	return nil
}

// New methods for better management
func (j *jwkManager) GetKeyCount() int {
	j.mutex.RLock()
	defer j.mutex.RUnlock()

	if j.jwkSet == nil {
		return 0
	}
	return j.jwkSet.Len()
}

func (j *jwkManager) CleanupExpiredKeys() error {
	j.mutex.Lock()
	defer j.mutex.Unlock()

	// Clean up cache entries that haven't been used in a while
	cutoff := time.Now().Add(-24 * time.Hour)
	for keyPrefix, cached := range j.keyCache {
		if cached.lastUsed.Before(cutoff) {
			delete(j.keyCache, keyPrefix)
		}
	}

	return nil
}

func (j *jwkManager) GetKeyMetadata(keyPrefix string) (*KeyMetadata, error) {
	j.mutex.RLock()
	defer j.mutex.RUnlock()

	metadata, exists := j.keyMetadata[keyPrefix]
	if !exists {
		return nil, NewAuthError("GetKeyMetadata", ErrKeyNotFound)
	}

	// Return a copy to prevent external modification
	return &KeyMetadata{
		KeyID:     metadata.KeyID,
		CreatedAt: metadata.CreatedAt,
		Algorithm: metadata.Algorithm,
		KeySize:   metadata.KeySize,
	}, nil
}
