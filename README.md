# JWK Authentication Library

A robust Go library for JWT token generation and verification using JSON Web Keys (JWK) with advanced features including key rotation, device-specific authentication, refresh token functionality, and comprehensive error handling.

## Features

- **JWT Token Management**: Access and refresh token generation with RS256 algorithm
- **Advanced JWK Management**: Automatic key rotation with caching and metadata tracking
- **Device-Specific Authentication**: Separate key management for different device types (Android, iOS, web)
- **Refresh Token Support**: Seamless token renewal without invalidating refresh tokens
- **Comprehensive Validation**: Token verification with expiration and purpose validation
- **Performance Optimized**: Key caching and efficient memory management
- **Robust Error Handling**: Structured error types with detailed context
- **Configurable**: Builder pattern for flexible configuration
- **Event System**: Observer pattern for token lifecycle events
- **Production Ready**: Metrics support and cleanup mechanisms

## Installation

```bash
go get github.com/sushan531/jwk-auth
```

## Quick Start

### Basic Usage with Enhanced Configuration

```go
package main

import (
    "fmt"
    "time"
    
    "github.com/sushan531/jwk-auth/core"
    "github.com/sushan531/jwk-auth/service"
)

func main() {
    // Configure using builder pattern
    config := core.NewConfigBuilder().
        WithTokenExpiry(2 * time.Hour).
        WithRefreshTokenExpiry(7 * 24 * time.Hour).
        WithKeySize(2048).
        WithCacheSettings(100, time.Hour).
        WithMetrics(true).
        Build()

    // Create services using factory pattern
    factory := service.NewServiceFactory(config)
    authService, tokenService, keyService := factory.CreateAllServices()

    // Define token claims
    accessClaims := map[string]any{
        "username": "john_doe",
        "user_id":  "12345",
        "scope":    "read:data write:data",
        "role":     "user",
    }

    refreshClaims := map[string]any{
        "username": "john_doe",
        "user_id":  "12345",
    }

    // Generate token pair
    accessToken, refreshToken, err := authService.GenerateAccessRefreshTokenPair(
        accessClaims, 
        refreshClaims, 
        "android",
    )
    if err != nil {
        fmt.Printf("Error generating tokens: %v\n", err)
        return
    }

    // Validate tokens with structured response
    accessTokenClaims, err := tokenService.ValidateAccessToken(accessToken)
    if err != nil {
        fmt.Printf("Error validating access token: %v\n", err)
        return
    }

    fmt.Printf("Access token valid until: %s\n", accessTokenClaims.ExpiresAt)
    fmt.Printf("Token purpose: %s\n", accessTokenClaims.Purpose)

    // Refresh access token
    newAccessToken, err := tokenService.RefreshAccessToken(
        refreshToken, 
        accessClaims, 
        "android",
    )
    if err != nil {
        fmt.Printf("Error refreshing token: %v\n", err)
        return
    }

    fmt.Printf("New access token: %s\n", newAccessToken)
}
```

### Advanced Configuration Options

```go
// Development configuration
devConfig := core.NewConfigBuilder().
    WithTokenExpiry(24 * time.Hour).
    WithRefreshTokenExpiry(7 * 24 * time.Hour).
    WithKeySize(2048).
    Build()

// Production configuration
prodConfig := core.ProductionConfig() // Pre-configured for production

// Custom configuration
customConfig := core.NewConfigBuilder().
    WithTokenExpiry(30 * time.Minute).
    WithRefreshTokenExpiry(30 * 24 * time.Hour).
    WithKeySize(4096).
    WithCacheSettings(1000, 15*time.Minute).
    WithMetrics(true).
    Build()
```

## Service Architecture

The library follows a clean architecture with separated concerns:

### Core Services

- **AuthService**: Main authentication operations
- **TokenService**: Token-specific operations with validation
- **KeyService**: Key management and rotation

### Usage Examples

```go
// Using individual services
factory := service.NewServiceFactory(config)

// Token operations
tokenService := factory.CreateTokenService()
accessToken, err := tokenService.CreateAccessToken(claims, "android")
refreshToken, err := tokenService.CreateRefreshToken(claims, "android")

// Key management
keyService := factory.CreateKeyService()
err = keyService.RotateKey("android")
metadata, err := keyService.GetKeyMetadata("android")
```

## Integration with Fiber Web Framework

### Complete Fiber Application with Enhanced Error Handling

```go
package main

import (
    "encoding/json"
    "log"
    "strings"
    "time"

    "github.com/gofiber/fiber/v2"
    "github.com/gofiber/fiber/v2/middleware/cors"
    "github.com/gofiber/fiber/v2/middleware/logger"
    "github.com/sushan531/jwk-auth/core"
    "github.com/sushan531/jwk-auth/service"
)

type AuthHandler struct {
    authService  service.Auth
    tokenService service.TokenService
    keyService   service.KeyService
}

func NewAuthHandler() *AuthHandler {
    config := core.ProductionConfig()
    factory := service.NewServiceFactory(config)
    
    authService, tokenService, keyService := factory.CreateAllServices()
    
    return &AuthHandler{
        authService:  authService,
        tokenService: tokenService,
        keyService:   keyService,
    }
}

// Enhanced login endpoint with better validation
func (h *AuthHandler) Login(c *fiber.Ctx) error {
    type LoginRequest struct {
        Username   string `json:"username" validate:"required,min=3,max=50"`
        Password   string `json:"password" validate:"required,min=6"`
        DeviceType string `json:"device_type" validate:"required,oneof=android ios web"`
    }
    
    var req LoginRequest
    if err := c.BodyParser(&req); err != nil {
        return c.Status(400).JSON(fiber.Map{
            "error": "Invalid request body",
            "code":  "INVALID_REQUEST",
        })
    }
    
    // Validate credentials
    user, err := validateAndGetUser(req.Username, req.Password)
    if err != nil {
        return c.Status(401).JSON(fiber.Map{
            "error": "Invalid credentials",
            "code":  "INVALID_CREDENTIALS",
        })
    }
    
    // Create comprehensive claims
    accessClaims := map[string]any{
        "username":    user.Username,
        "user_id":     user.ID,
        "email":       user.Email,
        "role":        user.Role,
        "permissions": user.Permissions,
        "device_type": req.DeviceType,
        "login_time":  time.Now().Unix(),
    }
    
    refreshClaims := map[string]any{
        "username": user.Username,
        "user_id":  user.ID,
        "purpose":  "refresh",
    }
    
    // Generate tokens
    accessToken, refreshToken, err := h.authService.GenerateAccessRefreshTokenPair(
        accessClaims, 
        refreshClaims, 
        req.DeviceType,
    )
    if err != nil {
        log.Printf("Token generation error: %v", err)
        return c.Status(500).JSON(fiber.Map{
            "error": "Failed to generate authentication tokens",
            "code":  "TOKEN_GENERATION_FAILED",
        })
    }
    
    return c.JSON(fiber.Map{
        "access_token":  accessToken,
        "refresh_token": refreshToken,
        "token_type":    "Bearer",
        "expires_in":    7200, // 2 hours
        "user": fiber.Map{
            "id":       user.ID,
            "username": user.Username,
            "email":    user.Email,
            "role":     user.Role,
        },
    })
}

// Enhanced refresh endpoint
func (h *AuthHandler) RefreshToken(c *fiber.Ctx) error {
    type RefreshRequest struct {
        RefreshToken string `json:"refresh_token" validate:"required"`
        DeviceType   string `json:"device_type" validate:"required"`
    }
    
    var req RefreshRequest
    if err := c.BodyParser(&req); err != nil {
        return c.Status(400).JSON(fiber.Map{
            "error": "Invalid request body",
            "code":  "INVALID_REQUEST",
        })
    }
    
    // Validate refresh token
    tokenClaims, err := h.tokenService.ValidateRefreshToken(req.RefreshToken)
    if err != nil {
        return c.Status(401).JSON(fiber.Map{
            "error": "Invalid or expired refresh token",
            "code":  "INVALID_REFRESH_TOKEN",
        })
    }
    
    // Get fresh user data
    userID, ok := tokenClaims.Claims["user_id"].(string)
    if !ok {
        return c.Status(401).JSON(fiber.Map{
            "error": "Invalid token claims",
            "code":  "INVALID_TOKEN_CLAIMS",
        })
    }
    
    user, err := getUserByID(userID)
    if err != nil {
        return c.Status(401).JSON(fiber.Map{
            "error": "User not found",
            "code":  "USER_NOT_FOUND",
        })
    }
    
    // Create new access token with fresh claims
    accessClaims := map[string]any{
        "username":    user.Username,
        "user_id":     user.ID,
        "email":       user.Email,
        "role":        user.Role,
        "permissions": user.Permissions,
        "device_type": req.DeviceType,
        "refresh_time": time.Now().Unix(),
    }
    
    newAccessToken, err := h.tokenService.RefreshAccessToken(
        req.RefreshToken,
        accessClaims,
        req.DeviceType,
    )
    if err != nil {
        log.Printf("Token refresh error: %v", err)
        return c.Status(500).JSON(fiber.Map{
            "error": "Failed to refresh access token",
            "code":  "TOKEN_REFRESH_FAILED",
        })
    }
    
    return c.JSON(fiber.Map{
        "access_token": newAccessToken,
        "token_type":   "Bearer",
        "expires_in":   7200,
    })
}

// Enhanced authentication middleware
func (h *AuthHandler) AuthMiddleware() fiber.Handler {
    return func(c *fiber.Ctx) error {
        authHeader := c.Get("Authorization")
        if authHeader == "" {
            return c.Status(401).JSON(fiber.Map{
                "error": "Authorization header required",
                "code":  "MISSING_AUTH_HEADER",
            })
        }
        
        parts := strings.Split(authHeader, " ")
        if len(parts) != 2 || parts[0] != "Bearer" {
            return c.Status(401).JSON(fiber.Map{
                "error": "Invalid authorization header format",
                "code":  "INVALID_AUTH_FORMAT",
            })
        }
        
        token := parts[1]
        
        // Validate access token
        tokenClaims, err := h.tokenService.ValidateAccessToken(token)
        if err != nil {
            return c.Status(401).JSON(fiber.Map{
                "error": "Invalid or expired token",
                "code":  "INVALID_TOKEN",
            })
        }
        
        // Store claims in context
        c.Locals("token_claims", tokenClaims)
        c.Locals("user_id", tokenClaims.Claims["user_id"])
        c.Locals("username", tokenClaims.Claims["username"])
        c.Locals("role", tokenClaims.Claims["role"])
        
        return c.Next()
    }
}

// Key management endpoints
func (h *AuthHandler) RotateKeys(c *fiber.Ctx) error {
    deviceType := c.Params("device_type")
    
    err := h.keyService.RotateKey(deviceType)
    if err != nil {
        return c.Status(500).JSON(fiber.Map{
            "error": "Failed to rotate keys",
            "code":  "KEY_ROTATION_FAILED",
        })
    }
    
    return c.JSON(fiber.Map{
        "message": "Keys rotated successfully",
        "device_type": deviceType,
    })
}

func (h *AuthHandler) GetKeyMetadata(c *fiber.Ctx) error {
    deviceType := c.Params("device_type")
    
    metadata, err := h.keyService.GetKeyMetadata(deviceType)
    if err != nil {
        return c.Status(404).JSON(fiber.Map{
            "error": "Key metadata not found",
            "code":  "KEY_NOT_FOUND",
        })
    }
    
    return c.JSON(metadata)
}

func (h *AuthHandler) GetJWKS(c *fiber.Ctx) error {
    jwkSet, err := h.keyService.ExportPublicKeys()
    if err != nil {
        return c.Status(500).JSON(fiber.Map{
            "error": "Failed to get JWK set",
            "code":  "JWKS_EXPORT_FAILED",
        })
    }
    
    var jwkSetMap map[string]any
    if err := json.Unmarshal(jwkSet, &jwkSetMap); err != nil {
        return c.Status(500).JSON(fiber.Map{
            "error": "Failed to parse JWK set",
            "code":  "JWKS_PARSE_FAILED",
        })
    }
    
    c.Set("Content-Type", "application/json")
    return c.JSON(jwkSetMap)
}

func main() {
    app := fiber.New(fiber.Config{
        ErrorHandler: func(c *fiber.Ctx, err error) error {
            code := fiber.StatusInternalServerError
            if e, ok := err.(*fiber.Error); ok {
                code = e.Code
            }
            
            return c.Status(code).JSON(fiber.Map{
                "error": err.Error(),
                "code":  "INTERNAL_ERROR",
            })
        },
    })
    
    // Middleware
    app.Use(cors.New())
    app.Use(logger.New())
    
    // Initialize handler
    authHandler := NewAuthHandler()
    
    // Public routes
    app.Post("/auth/login", authHandler.Login)
    app.Post("/auth/refresh", authHandler.RefreshToken)
    app.Get("/.well-known/jwks.json", authHandler.GetJWKS)
    
    // Admin routes (require admin role)
    admin := app.Group("/admin", authHandler.AuthMiddleware(), requireRole("admin"))
    admin.Post("/keys/:device_type/rotate", authHandler.RotateKeys)
    admin.Get("/keys/:device_type/metadata", authHandler.GetKeyMetadata)
    
    // Protected API routes
    api := app.Group("/api", authHandler.AuthMiddleware())
    
    api.Get("/profile", func(c *fiber.Ctx) error {
        claims := c.Locals("token_claims").(*service.TokenClaims)
        return c.JSON(fiber.Map{
            "user": claims.Claims,
            "token_info": fiber.Map{
                "expires_at": claims.ExpiresAt,
                "issued_at":  claims.IssuedAt,
                "purpose":    claims.Purpose,
            },
        })
    })
    
    log.Fatal(app.Listen(":3000"))
}

// Helper functions
type User struct {
    ID          string   `json:"id"`
    Username    string   `json:"username"`
    Email       string   `json:"email"`
    Role        string   `json:"role"`
    Permissions []string `json:"permissions"`
}

func validateAndGetUser(username, password string) (*User, error) {
    // Implement your authentication logic
    if username == "admin" && password == "password" {
        return &User{
            ID:          "1",
            Username:    username,
            Email:       "admin@example.com",
            Role:        "admin",
            Permissions: []string{"read", "write", "admin"},
        }, nil
    }
    return nil, fmt.Errorf("invalid credentials")
}

func getUserByID(userID string) (*User, error) {
    // Implement your user lookup logic
    return &User{
        ID:          userID,
        Username:    "admin",
        Email:       "admin@example.com",
        Role:        "admin",
        Permissions: []string{"read", "write", "admin"},
    }, nil
}

func requireRole(requiredRole string) fiber.Handler {
    return func(c *fiber.Ctx) error {
        role, ok := c.Locals("role").(string)
        if !ok || role != requiredRole {
            return c.Status(403).JSON(fiber.Map{
                "error": "Insufficient permissions",
                "code":  "INSUFFICIENT_PERMISSIONS",
            })
        }
        return c.Next()
    }
}
```

## Error Handling

The library provides comprehensive error handling with structured error types:

```go
// Custom error types
var (
    ErrInvalidKeyPrefix     = errors.New("invalid key prefix format")
    ErrKeyNotFound         = errors.New("key not found in JWK set")
    ErrJWKSetNotInitialized = errors.New("JWK set not initialized")
    ErrInvalidTokenPurpose  = errors.New("invalid token purpose")
    ErrTokenExpired        = errors.New("token has expired")
)

// Structured error handling
if err != nil {
    if errors.Is(err, core.ErrTokenExpired) {
        // Handle expired token
    } else if errors.Is(err, core.ErrInvalidKeyPrefix) {
        // Handle invalid key prefix
    }
}
```

## Performance Features

- **Key Caching**: Frequently used keys are cached in memory
- **Lazy Loading**: Keys are loaded only when needed
- **Cleanup Mechanisms**: Automatic cleanup of unused keys and cache entries
- **Efficient Validation**: Optimized token validation with minimal overhead

## Security Features

1. **Key Rotation**: Automatic key rotation for access tokens
2. **Device Isolation**: Separate keys for different device types
3. **Token Purpose Validation**: Prevents misuse of refresh tokens for API access
4. **Input Validation**: Comprehensive validation of all inputs
5. **Secure Defaults**: Production-ready default configurations
6. **Expiration Handling**: Automatic token expiration validation

## Configuration Options

| Option | Default | Description |
|--------|---------|-------------|
| TokenExpiry | 24h | Access token expiration time |
| RefreshTokenExpiry | 7d | Refresh token expiration time |
| KeySize | 2048 | RSA key size in bits |
| Algorithm | RS256 | Signing algorithm |
| MaxCacheSize | 100 | Maximum number of cached keys |
| CleanupInterval | 1h | Cache cleanup interval |
| EnableMetrics | false | Enable metrics collection |

## Dependencies

```go
require (
    github.com/lestrrat-go/jwx/v3 v3.0.11
    github.com/gofiber/fiber/v2 v2.x.x // For web framework integration
)
```

## Migration Guide

### From v1.x to v2.x

1. **Configuration**: Use the new builder pattern
   ```go
   // Old
   config := core.DefaultConfig()
   
   // New
   config := core.NewConfigBuilder().
       WithTokenExpiry(2 * time.Hour).
       Build()
   ```

2. **Service Creation**: Use the factory pattern
   ```go
   // Old
   authService := service.NewAuth(...)
   
   // New
   factory := service.NewServiceFactory(config)
   authService := factory.CreateAuthService()
   ```

3. **Error Handling**: Use structured errors
   ```go
   // Old
   if err != nil { ... }
   
   // New
   if errors.Is(err, core.ErrTokenExpired) { ... }
   ```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Add tests for new functionality
4. Ensure all tests pass
5. Submit a pull request

## License

This project is licensed under the MIT License - see the LICENSE file for details.