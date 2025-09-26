package internal

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/lestrrat-go/jwx/v3/jwk"
)

type JwkManager interface {
	InitializeJwkSet(keyPrefix string) error
	AddOrReplaceKeyToSet(keyPrefix string) error
	GetPrivateKeyWithId(keyPrefix string) (*rsa.PrivateKey, string, error)
	GetJwkSetForStorage() ([]byte, error)
	GetJwkSetFromStorage(jwkSetJSON string) error
	GetPublicKeyBy(keyId string) (*rsa.PublicKey, error)
}

type jwkManager struct {
	jwkSet jwk.Set
}

func NewJwkManager() JwkManager {
	return &jwkManager{}
}

func (j *jwkManager) InitializeJwkSet(keyPrefix string) error {
	// Generate a new key set with a single key
	set := jwk.NewSet()

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return fmt.Errorf("failed to generate private key: %w", err)
	}

	key, err := jwk.Import(privateKey)
	if err != nil {
		return fmt.Errorf("failed to import RSA key into JWK: %w", err)
	}

	keyID := fmt.Sprintf("key-%s", keyPrefix)
	if err := key.Set(jwk.KeyIDKey, keyID); err != nil {
		return fmt.Errorf("failed to set key ID: %w", err)
	}

	if err := set.AddKey(key); err != nil {
		return fmt.Errorf("failed to add key to set: %w", err)
	}

	j.jwkSet = set
	return nil
}

func (j *jwkManager) AddOrReplaceKeyToSet(keyPrefix string) error {
	if j.jwkSet == nil {
		err := j.InitializeJwkSet(keyPrefix)
		if err != nil {
			return err
		}
		return nil
	}
	keyID := fmt.Sprintf("key-%s", keyPrefix)
	oldKey, found := j.jwkSet.LookupKeyID(keyID)
	if found {
		_ = j.jwkSet.RemoveKey(oldKey)
	}
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return fmt.Errorf("failed to generate private key: %w", err)
	}

	key, err := jwk.Import(privateKey)
	if err != nil {
		return fmt.Errorf("failed to import RSA key into JWK: %w", err)
	}

	if err := key.Set(jwk.KeyIDKey, keyID); err != nil {
		return fmt.Errorf("failed to set key ID: %w", err)
	}

	if err := j.jwkSet.AddKey(key); err != nil {
		return fmt.Errorf("failed to add key to set: %w", err)
	}

	return nil
}

func (j *jwkManager) GetPrivateKeyWithId(keyPrefix string) (*rsa.PrivateKey, string, error) {
	key, foundKey := j.jwkSet.LookupKeyID(fmt.Sprintf("key-%s", keyPrefix))
	if !foundKey {
		return nil, "", fmt.Errorf("key not found in JWK set")
	}

	var rsaPrivateKey rsa.PrivateKey
	if err := jwk.Export(key, &rsaPrivateKey); err != nil {
		return nil, "", fmt.Errorf("failed to export raw key: %w", err)
	}

	var kid string
	if err := key.Get(jwk.KeyIDKey, &kid); err != nil {
		return nil, "", fmt.Errorf("failed to get kid: %w", err)
	}

	return &rsaPrivateKey, kid, nil

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

func (j *jwkManager) GetPublicKeyBy(keyId string) (*rsa.PublicKey, error) {
	if j.jwkSet == nil {
		return nil, errors.New("JWK set not initialized")
	}

	key, found := j.jwkSet.LookupKeyID(keyId)
	if !found {
		return nil, fmt.Errorf("no key found with kid: %s", keyId)
	}

	var rsaPrivateKey rsa.PrivateKey
	if err := jwk.Export(key, &rsaPrivateKey); err != nil {
		return nil, fmt.Errorf("failed to export raw key: %w", err)
	}

	return &rsaPrivateKey.PublicKey, nil
}
