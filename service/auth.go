package service

import (
	"fmt"
	"jwk-auth/internal"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwt"
)

type Auth interface {
	GenerateToken(input map[string]interface{}, keyPrefix string) (string, error)
	//VerifyTokenSignatureAndGetClaims(token string, publicKey rsa.PublicKey) (map[string]interface{}, error)
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
	err := a.jwkManager.AddKeyToSet(keyPrefix)
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

//func (a *auth) VerifyTokenSignatureAndGetClaims(token string, publicKey rsa.PublicKey) (map[string]interface{}, error) {
//
//}
