package manager

import (
	"encoding/base64"
	"fmt"

	"github.com/fernet/fernet-go"
)

// EncryptionManager handles Fernet encryption and decryption for keyset data
type EncryptionManager interface {
	// GenerateKey generates a new Fernet key for a user
	GenerateKey() (string, error)
	
	// Encrypt encrypts data using the provided Fernet key
	Encrypt(data []byte, key string) (string, error)
	
	// Decrypt decrypts data using the provided Fernet key
	Decrypt(encryptedData string, key string) ([]byte, error)
}

type encryptionManager struct{}

// NewEncryptionManager creates a new encryption manager instance
func NewEncryptionManager() EncryptionManager {
	return &encryptionManager{}
}

// GenerateKey generates a new Fernet key and returns it as base64 string
func (e *encryptionManager) GenerateKey() (string, error) {
	// Generate a new Fernet key
	var key fernet.Key
	if err := key.Generate(); err != nil {
		return "", fmt.Errorf("failed to generate Fernet key: %w", err)
	}
	
	// Return the key as string (it's already base64 encoded)
	return key.Encode(), nil
}

// Encrypt encrypts data using Fernet with the provided key
func (e *encryptionManager) Encrypt(data []byte, keyStr string) (string, error) {
	// Decode the Fernet key from string
	key, err := fernet.DecodeKey(keyStr)
	if err != nil {
		return "", fmt.Errorf("failed to decode encryption key: %w", err)
	}
	
	// Encrypt the data
	encrypted, err := fernet.EncryptAndSign(data, key)
	if err != nil {
		return "", fmt.Errorf("failed to encrypt data: %w", err)
	}
	
	// Return as base64 string for storage
	return base64.URLEncoding.EncodeToString(encrypted), nil
}

// Decrypt decrypts data using Fernet with the provided key
func (e *encryptionManager) Decrypt(encryptedDataStr string, keyStr string) ([]byte, error) {
	// Decode the base64 encrypted data
	encryptedData, err := base64.URLEncoding.DecodeString(encryptedDataStr)
	if err != nil {
		return nil, fmt.Errorf("failed to decode encrypted data: %w", err)
	}
	
	// Decode the Fernet key from string
	key, err := fernet.DecodeKey(keyStr)
	if err != nil {
		return nil, fmt.Errorf("failed to decode encryption key: %w", err)
	}
	
	// Decrypt the data (no TTL check, use 0 duration)
	decrypted := fernet.VerifyAndDecrypt(encryptedData, 0, []*fernet.Key{key})
	if decrypted == nil {
		return nil, fmt.Errorf("failed to decrypt data: invalid key or corrupted data")
	}
	
	return decrypted, nil
}