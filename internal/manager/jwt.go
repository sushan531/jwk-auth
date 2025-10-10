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
	GenerateTokenWithKeyID(claims map[string]interface{}, keyID string) (string, error)
	GenerateAccessTokenWithKeyID(claims map[string]interface{}, keyID string) (string, error)
	GenerateRefreshTokenWithKeyID(claims map[string]interface{}, keyID string) (string, error)
	VerifyTokenSignatureAndGetClaims(jwtToken string) (map[string]interface{}, error)
	ExtractKeyIDFromToken(jwtToken string) (string, error)
}

type jwtManager struct {
	jwkManager JwkManager
}

func NewJwtManager(jwkManager JwkManager) JwtManager {
	return &jwtManager{
		jwkManager: jwkManager,
	}
}

// Session-based token generation methods
func (j jwtManager) GenerateTokenWithKeyID(claims map[string]interface{}, keyID string) (string, error) {
	return j.generateTokenWithKeyIDAndDuration(claims, keyID, 24*time.Hour)
}

func (j jwtManager) GenerateAccessTokenWithKeyID(claims map[string]interface{}, keyID string) (string, error) {
	return j.generateTokenWithKeyIDAndDuration(claims, keyID, 15*time.Minute)
}

func (j jwtManager) GenerateRefreshTokenWithKeyID(claims map[string]interface{}, keyID string) (string, error) {
	return j.generateTokenWithKeyIDAndDuration(claims, keyID, 7*24*time.Hour) // 7 days
}

func (j jwtManager) generateTokenWithKeyIDAndDuration(claims map[string]interface{}, keyID string, duration time.Duration) (string, error) {
	token := jwt.New()
	currentTime := time.Now()

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

	// Set the key ID
	if err := token.Set("kid", keyID); err != nil {
		return "", fmt.Errorf("failed to set key id in token: %w", err)
	}

	// Get the private key for signing
	privateKey, err := j.jwkManager.GetPrivateKeyByID(keyID)
	if err != nil {
		return "", fmt.Errorf("failed to get signing key: %w", err)
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

// ExtractKeyIDFromToken extracts the key ID from a JWT token without full verification
func (j jwtManager) ExtractKeyIDFromToken(jwtToken string) (string, error) {
	parsedToken, err := jws.Parse([]byte(jwtToken))
	if err != nil {
		return "", fmt.Errorf("failed to parse JWT: %w", err)
	}

	var payload map[string]interface{}
	payloadInBytes := parsedToken.Payload()

	err = json.Unmarshal(payloadInBytes, &payload)
	if err != nil {
		return "", fmt.Errorf("failed to unmarshal payload: %w", err)
	}

	kid, ok := payload["kid"].(string)
	if !ok {
		return "", fmt.Errorf("key ID not found in token")
	}

	return kid, nil
}
