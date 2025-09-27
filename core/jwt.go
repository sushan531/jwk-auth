package core

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/lestrrat-go/jwx/v3/jws"
	"github.com/lestrrat-go/jwx/v3/jwt"
)

type JwtManager interface {
	GenerateUnsignedToken(claims map[string]any, expiry time.Duration) (jwt.Token, error)
	ParseToken(jwtToken string) (map[string]any, error)
	//VerifyTokenSignatureAndGetClaims(jwtToken string, publicKey rsa.PublicKey) (map[string]any, error)
}

type jwtManager struct {
}

func NewJwtManager() JwtManager {
	return &jwtManager{}
}

func (j *jwtManager) GenerateUnsignedToken(claims map[string]any, expiry time.Duration) (jwt.Token, error) {
	token := jwt.New()

	var currentTime = time.Now()
	var tokenKeys = map[string]any{
		jwt.IssuedAtKey:   currentTime.Unix(),
		jwt.ExpirationKey: currentTime.Add(expiry).Unix(),
	}

	for key, value := range tokenKeys {
		if err := token.Set(key, value); err != nil {
			return nil, fmt.Errorf("failed to set claim %s: %w", key, err)
		}
	}
	for key, value := range claims {
		if err := token.Set(key, value); err != nil {
			return nil, fmt.Errorf("failed to set claim %s: %w", key, err)
		}
	}
	return token, nil
}

func (j *jwtManager) ParseToken(jwtToken string) (map[string]any, error) {
	parsedToken, err := jws.Parse([]byte(jwtToken))
	if err != nil {
		return nil, fmt.Errorf("failed to parse JWT: %w", err)
	}
	var payload map[string]any
	payloadInBytes := parsedToken.Payload()

	errUnmarshallingData := json.Unmarshal(payloadInBytes, &payload)
	if errUnmarshallingData != nil {
		return nil, errUnmarshallingData
	}
	return payload, nil
}

//func (j *jwtManager) VerifyTokenSignatureAndGetClaims(jwtToken string, publicKey rsa.PublicKey) (map[string]any, error) {
//	parsedToken, err := jws.Parse([]byte(jwtToken))
//	if err != nil {
//		return nil, fmt.Errorf("failed to parse JWT: %w", err)
//	}
//
//	var payload map[string]any
//	payloadInBytes := parsedToken.Payload()
//
//	errUnmarshallingData := json.Unmarshal(payloadInBytes, &payload)
//	if errUnmarshallingData != nil {
//		return nil, errUnmarshallingData
//	}
//
//	_, errValidatingToken := jwt.Parse([]byte(jwtToken), jwt.WithKey(jwa.RS256(), publicKey))
//	if errValidatingToken != nil {
//		return nil, fmt.Errorf("failed to verify token signature: %w", errValidatingToken)
//	}
//
//	return payload, nil
//}
