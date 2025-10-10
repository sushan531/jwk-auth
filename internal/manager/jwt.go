package manager

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jws"
	"github.com/lestrrat-go/jwx/v3/jwt"
)

type JwtManager interface {
	GenerateToken(claims map[string]interface{}) (string, error)
	GenerateAccessToken(claims map[string]interface{}) (string, error)
	GenerateRefreshToken(claims map[string]interface{}) (string, error)
	VerifyTokenSignatureAndGetClaims(jwtToken string) (map[string]interface{}, error)
}

type jwtManager struct {
	jwkManager JwkManager
}

func NewJwtManager(jwkManager JwkManager) JwtManager {
	return &jwtManager{
		jwkManager: jwkManager,
	}
}

func (j jwtManager) GenerateToken(claims map[string]interface{}) (string, error) {
	return j.generateTokenWithDuration(claims, 24*time.Hour)
}

func (j jwtManager) GenerateAccessToken(claims map[string]interface{}) (string, error) {
	return j.generateTokenWithDuration(claims, 15*time.Minute)
}

func (j jwtManager) GenerateRefreshToken(claims map[string]interface{}) (string, error) {
	return j.generateTokenWithDuration(claims, 7*24*time.Hour) // 7 days
}

func (j jwtManager) generateTokenWithDuration(claims map[string]interface{}, duration time.Duration) (string, error) {
	token := jwt.New()

	var currentTime = time.Now()

	// Set all claims directly on the token
	for key, value := range claims {
		if err := token.Set(key, value); err != nil {
			return "", fmt.Errorf("failed to set claim %s: %w", key, err)
		}
	}

	// Set standard JWT claims
	if err := token.Set(jwt.IssuedAtKey, currentTime.Unix()); err != nil {
		return "", fmt.Errorf("failed to set iat: %w", err)
	}

	if err := token.Set(jwt.ExpirationKey, currentTime.Add(duration).Unix()); err != nil {
		return "", fmt.Errorf("failed to set exp: %w", err)
	}

	privateKey, keyId, err := j.jwkManager.GetAnyPrivateKeyWithKeyId()
	if err != nil {
		return "", fmt.Errorf("failed to get signing key: %w", err)
	}

	if err := token.Set("kid", keyId); err != nil {
		return "", fmt.Errorf("failed to set key id in token: %w", err)
	}

	signedToken, err := jwt.Sign(token, jwt.WithKey(jwa.RS256(), privateKey))
	if err != nil {
		return "", fmt.Errorf("failed to sign token: %w", err)
	}

	return string(signedToken), nil
}

func (j jwtManager) VerifyTokenSignatureAndGetClaims(jwtToken string) (map[string]interface{}, error) {
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

	var kid = payload["kid"].(string)
	publicKey, errFindingPublicKey := j.jwkManager.GetPublicKeyBy(kid)
	if errFindingPublicKey != nil {
		return nil, errFindingPublicKey
	}

	_, errValidatingToken := jwt.Parse([]byte(jwtToken), jwt.WithKey(jwa.RS256(), publicKey))
	if errValidatingToken != nil {
		return nil, fmt.Errorf("failed to verify token signature: %w", errValidatingToken)
	}

	return payload, nil
}
