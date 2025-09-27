package service

import (
	"github.com/sushan531/jwk-auth/core"
)

// KeyService handles key management operations
type KeyService interface {
	RotateKey(keyPrefix string) error
	GetKeyMetadata(keyPrefix string) (*core.KeyMetadata, error)
	ListKeys() ([]string, error)
	CleanupUnusedKeys() error
	ExportPublicKeys() ([]byte, error)
	ImportKeys(jwkSetJSON string) error
}

type keyService struct {
	jwkManager core.JwkManager
}

func NewKeyService(jwkManager core.JwkManager) KeyService {
	return &keyService{
		jwkManager: jwkManager,
	}
}

func (ks *keyService) RotateKey(keyPrefix string) error {
	return ks.jwkManager.AddOrReplaceKeyToSet(keyPrefix)
}

func (ks *keyService) GetKeyMetadata(keyPrefix string) (*core.KeyMetadata, error) {
	return ks.jwkManager.GetKeyMetadata(keyPrefix)
}

func (ks *keyService) ListKeys() ([]string, error) {
	// Implementation would depend on adding a ListKeys method to JwkManager
	// This is a placeholder for the interface
	return nil, nil
}

func (ks *keyService) CleanupUnusedKeys() error {
	return ks.jwkManager.CleanupExpiredKeys()
}

func (ks *keyService) ExportPublicKeys() ([]byte, error) {
	return ks.jwkManager.GetJwkSetForStorage()
}

func (ks *keyService) ImportKeys(jwkSetJSON string) error {
	return ks.jwkManager.GetJwkSetFromStorage(jwkSetJSON)
}
