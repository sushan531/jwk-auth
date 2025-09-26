package internal

import (
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jws"
	"github.com/lestrrat-go/jwx/v3/jwt"
)

type JwtManager interface {
	GenerateUnsignedToken(claims map[string]interface{}) (jwt.Token, error)
	ParseToken(jwtToken string) (map[string]interface{}, error)
	VerifyTokenSignatureAndGetClaims(jwtToken string, publicKey rsa.PublicKey) (map[string]interface{}, error)
}

type jwtManager struct{}

func NewJwtManager() JwtManager {
	return &jwtManager{}
}

func (j *jwtManager) GenerateUnsignedToken(claims map[string]interface{}) (jwt.Token, error) {
	token := jwt.New()

	var currentTime = time.Now()
	var tokenKeys = map[string]interface{}{
		"claim":           claims,
		jwt.IssuedAtKey:   currentTime.Unix(),
		jwt.ExpirationKey: currentTime.Add(24 * time.Hour).Unix(),
	}

	for key, value := range tokenKeys {
		if err := token.Set(key, value); err != nil {
			return nil, fmt.Errorf("failed to set claim %s: %w", key, err)
		}
	}
	//if err := j.jwkManager.InitializeJwkSet(keyPrefix); err != nil {
	//	return "", fmt.Errorf("Error initializing jwk set: %w", err)
	//}
	//
	//privateKey, keyId, err := j.jwkManager.GetAnyPrivateKeyWithKeyId(keyPrefix)
	//if err != nil {
	//	return "", fmt.Errorf("failed to get signing key: %w", err)
	//}
	//
	//errSettingKeyId := token.Set("kid", keyId)
	//if errSettingKeyId != nil {
	//	return "", fmt.Errorf("failed to set key id in token: %w", errSettingKeyId)
	//}
	//
	//signedToken, err := jwt.Sign(token, jwt.WithKey(jwa.RS256(), privateKey))
	//if err != nil {
	//	return "", fmt.Errorf("failed to sign token: %w", err)
	//}
	return token, nil
}

func (j *jwtManager) ParseToken(jwtToken string) (map[string]interface{}, error) {
	parsedToken, err := jws.Parse([]byte(jwtToken))
	if err != nil {
		return nil, fmt.Errorf("failed to parse JWT: %w", err)
	}
	var payload map[string]interface{}
	payloadInBytes := parsedToken.Payload()

	errUnmarshallingData := json.Unmarshal(payloadInBytes, &payload)
	if errUnmarshallingData != nil {
		return nil, errUnmarshallingData
	}
	return payload, nil
}

func (j *jwtManager) VerifyTokenSignatureAndGetClaims(jwtToken string, publicKey rsa.PublicKey) (map[string]interface{}, error) {
	parsedToken, err := jws.Parse([]byte(jwtToken))
	if err != nil {
		return nil, fmt.Errorf("failed to parse JWT: %w", err)
	}

	var payload map[string]interface{}
	payloadInBytes := parsedToken.Payload()

	errUnmarshallingData := json.Unmarshal(payloadInBytes, &payload)
	if errUnmarshallingData != nil {
		return nil, errUnmarshallingData
	}

	_, errValidatingToken := jwt.Parse([]byte(jwtToken), jwt.WithKey(jwa.RS256(), publicKey))
	if errValidatingToken != nil {
		return nil, fmt.Errorf("failed to verify token signature: %w", errValidatingToken)
	}

	return payload, nil
}
