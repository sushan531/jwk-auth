package service

import (
	"github.com/sushan531/jwk-auth/core"
)

// ServiceFactory creates and configures services
type ServiceFactory struct {
	config *core.Config
}

// NewServiceFactory creates a new service factory
func NewServiceFactory(config *core.Config) *ServiceFactory {
	return &ServiceFactory{config: config}
}

// CreateAuthService creates a fully configured auth service
func (sf *ServiceFactory) CreateAuthService() Auth {
	jwkManager := core.NewJwkManager(sf.config)
	jwtManager := core.NewJwtManager()
	return NewAuth(jwkManager, jwtManager, sf.config)
}

// CreateTokenService creates a token service
func (sf *ServiceFactory) CreateTokenService() TokenService {
	authService := sf.CreateAuthService()
	return NewTokenService(authService, sf.config)
}

// CreateKeyService creates a key service
func (sf *ServiceFactory) CreateKeyService() KeyService {
	jwkManager := core.NewJwkManager(sf.config)
	return NewKeyService(jwkManager)
}

// CreateAllServices creates all services with shared dependencies
func (sf *ServiceFactory) CreateAllServices() (Auth, TokenService, KeyService) {
	jwkManager := core.NewJwkManager(sf.config)
	jwtManager := core.NewJwtManager()

	authService := NewAuth(jwkManager, jwtManager, sf.config)
	tokenService := NewTokenService(authService, sf.config)
	keyService := NewKeyService(jwkManager)

	return authService, tokenService, keyService
}
