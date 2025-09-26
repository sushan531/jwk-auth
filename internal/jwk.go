package internal

import (
	"crypto/rand"
	"crypto/rsa"
	"fmt"

	"github.com/lestrrat-go/jwx/v3/jwk"
)

type JwkManager interface {
	InitializeJwkSet(keyPrefix string) error
	AddKeyToSet(keyPrefix string) error
	GetPrivateKeyWithId(keyPrefix string) (*rsa.PrivateKey, string, error)
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

func (j *jwkManager) AddKeyToSet(keyPrefix string) error {
	if j.jwkSet == nil {
		err := j.InitializeJwkSet(keyPrefix)
		if err != nil {
			return err
		}
		return nil
	}

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
