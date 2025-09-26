package service

import (
	"encoding/json"
	"fmt"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jws"
	"github.com/lestrrat-go/jwx/v3/jwt"
	"github.com/sushan531/jwt-auth/internal"
)

type Auth interface {
	GenerateToken(input map[string]interface{}, keyPrefix string) (string, error)
	MarshalJwkSet() ([]byte, error)
	ParseJsonBytes(jwkSetJSON string) error
	VerifyTokenSignatureAndGetClaims(token string) (map[string]interface{}, error)
}

type auth struct {
	jwkManager internal.JwkManager
	jwtManager internal.JwtManager
}

func NewAuth(jwkManager internal.JwkManager, jwtManager internal.JwtManager) Auth {
	return &auth{
		jwkManager: jwkManager,
		jwtManager: jwtManager,
	}
}
func (a *auth) GenerateToken(input map[string]interface{}, keyPrefix string) (string, error) {
	err := a.jwkManager.AddOrReplaceKeyToSet(keyPrefix)
	if err != nil {
		return "", err
	}
	unsignedToken, err := a.jwtManager.GenerateUnsignedToken(input)
	if err != nil {
		return "", err
	}
	privateKey, kid, err := a.jwkManager.GetPrivateKeyWithId(keyPrefix)

	errSettingKeyId := unsignedToken.Set("kid", kid)
	if errSettingKeyId != nil {
		return "", fmt.Errorf("failed to set key id in token: %w", errSettingKeyId)
	}

	signedToken, err := jwt.Sign(unsignedToken, jwt.WithKey(jwa.RS256(), privateKey))
	if err != nil {
		return "", fmt.Errorf("failed to sign token: %w", err)
	}

	return string(signedToken), nil

}

func (a *auth) MarshalJwkSet() ([]byte, error) {
	jwkSet, err := a.jwkManager.GetJwkSetForStorage()
	if err != nil {
		return nil, err
	}
	return jwkSet, nil
}

func (a *auth) ParseJsonBytes(jwkSetJSON string) error {
	err := a.jwkManager.GetJwkSetFromStorage(jwkSetJSON)
	if err != nil {
		return err
	}
	return nil
}

func (a *auth) VerifyTokenSignatureAndGetClaims(jwtToken string) (map[string]interface{}, error) {
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
	publicKey, errFindingPublicKey := a.jwkManager.GetPublicKeyBy(kid)
	if errFindingPublicKey != nil {
		return nil, errFindingPublicKey
	}

	_, errValidatingToken := jwt.Parse([]byte(jwtToken), jwt.WithKey(jwa.RS256(), publicKey))
	if errValidatingToken != nil {
		return nil, fmt.Errorf("failed to verify token signature: %w", errValidatingToken)
	}

	return payload, nil
}
