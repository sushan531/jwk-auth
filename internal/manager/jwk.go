package manager

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/sushan531/jwk-auth/internal/repository"
)

type JwkManager interface {
	InitializeJwkSet(noOfKeys int) error
	LoadJwkSetFromDB() error
	SaveJwkSetToDB(userID int) error
	GetAnyPrivateKeyWithKeyId() (*rsa.PrivateKey, string, error)
	GetPublicKeyBy(keyId string) (*rsa.PublicKey, error)
	GetPublicKeys() ([]*rsa.PublicKey, error)
}

type jwkManager struct {
	jwkSet   jwk.Set
	userRepo repository.UserAuthRepository
}

func NewJwkManager(userRepo repository.UserAuthRepository) JwkManager {
	return &jwkManager{
		userRepo: userRepo,
	}
}

func (j *jwkManager) InitializeJwkSet(noOfKeys int) error {
	set := jwk.NewSet()

	for i := 0; i < noOfKeys; i++ {
		privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return fmt.Errorf("failed to generate private key: %w", err)
		}

		key, err := jwk.Import(privateKey)
		if err != nil {
			return fmt.Errorf("failed to import RSA key into JWK: %w", err)
		}

		if errSettingKeyId := key.Set(jwk.KeyIDKey, fmt.Sprintf("key-%d", i)); errSettingKeyId != nil {
			return fmt.Errorf("failed to set key ID: %w", errSettingKeyId)
		}

		if errAddingKeyToSet := set.AddKey(key); errAddingKeyToSet != nil {
			return fmt.Errorf("failed to update key set: %w", err)
		}
	}

	j.jwkSet = set

	return nil
}

func (j *jwkManager) GetAnyPrivateKeyWithKeyId() (*rsa.PrivateKey, string, error) {
	if j.jwkSet == nil || j.jwkSet.Len() == 0 {
		return nil, "", fmt.Errorf("JWK set is empty or not initialized")
	}

	// you can place your logic to fetch random key
	// it could be as simple as randomInt from (0 to j.jwkSet.Len() - 1)
	key, foundKey := j.jwkSet.Key(0)
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

func (j *jwkManager) GetPublicKeys() ([]*rsa.PublicKey, error) {
	if j.jwkSet == nil || j.jwkSet.Len() == 0 {
		return nil, errors.New("JWK set is empty or not initialized")
	}

	publicKeys := make([]*rsa.PublicKey, 0)

	for i := 0; i < j.jwkSet.Len(); i++ {
		key, ok := j.jwkSet.Key(i)
		if !ok {
			continue // skip if key not accessible
		}

		var rawKey interface{}
		if err := jwk.Export(key, &rawKey); err != nil {
			continue // skip keys that fail to export
		}

		switch k := rawKey.(type) {
		case *rsa.PrivateKey:
			publicKeys = append(publicKeys, &k.PublicKey)
		case *rsa.PublicKey:
			publicKeys = append(publicKeys, k)
		}
	}

	if len(publicKeys) == 0 {
		return nil, errors.New("no RSA public keys found in JWK set")
	}

	return publicKeys, nil
}

func (j *jwkManager) LoadJwkSetFromDB() error {
	userAuth, err := j.userRepo.GetLatestKeySet()
	if err != nil {
		return fmt.Errorf("failed to load key set from database: %w", err)
	}

	// Parse the JSON key set
	set, err := jwk.ParseString(userAuth.KeySet)
	if err != nil {
		return fmt.Errorf("failed to parse key set from database: %w", err)
	}

	j.jwkSet = set
	return nil
}

func (j *jwkManager) SaveJwkSetToDB(userID int) error {
	if j.jwkSet == nil {
		return errors.New("no JWK set to save")
	}

	// Convert JWK set to JSON
	keySetBytes, err := json.Marshal(j.jwkSet)
	if err != nil {
		return fmt.Errorf("failed to marshal JWK set: %w", err)
	}

	_, err = j.userRepo.SaveKeySet(userID, string(keySetBytes))
	if err != nil {
		return fmt.Errorf("failed to save key set to database: %w", err)
	}

	return nil
}
