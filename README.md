# JWK Authentication Library

A Go library for JWT token generation and verification using JSON Web Keys (JWK) with support for key rotation and device-specific authentication.

## Features

- JWT token generation with RS256 algorithm
- JWK (JSON Web Key) management with automatic key rotation
- Device-specific key management (e.g., separate keys for Android, iOS, web)
- Token verification and claims extraction
- JWK set serialization/deserialization for storage
- Configurable token expiry and key size

## Installation

```bash
go get github.com/sushan531/jwk-auth
```

## Quick Start

### Basic Usage

```go
package main

import (
    "fmt"
    "github.com/sushan531/jwk-auth/internal"
    "github.com/sushan531/jwk-auth/service"
)

func main() {
    // Create managers
    jwkManager := internal.NewJwkManager()
    jwtManager := internal.NewJwtManager(internal.DefaultConfig())
    
    // Create auth service
    authService := service.NewAuth(jwkManager, jwtManager)
    
    // Define claims for the token
    claims := map[string]interface{}{
        "username": "john_doe",
        "user_id":  "12345",
        "scope":    "read:data write:data",
    }
    
    // Generate a token for Android device
    token, err := authService.GenerateToken(claims, "android")
    if err != nil {
        fmt.Printf("Error generating token: %v\n", err)
        return
    }
    
    fmt.Printf("Generated Token: %s\n", token)
    
    // Get JWK set for public key distribution
    jwkSetJSON, err := authService.MarshalJwkSet()
    if err != nil {
        fmt.Printf("Error marshaling JWK set: %v\n", err)
        return
    }
    
    // Verify token
    claims, err = authService.VerifyTokenSignatureAndGetClaims(token)
    if err != nil {
        fmt.Printf("Error verifying token: %v\n", err)
        return
    }
    
    fmt.Printf("Verified claims: %v\n", claims)
}
```

## Integration with Fiber

Here's how to integrate the JWK authentication library with a Fiber REST API:

### Setup

```go
package main

import (
    "encoding/json"
    "log"
    "strings"
    
    "github.com/gofiber/fiber/v2"
    "github.com/gofiber/fiber/v2/middleware/cors"
    "github.com/sushan531/jwk-auth/internal"
    "github.com/sushan531/jwk-auth/service"
)

type AuthHandler struct {
    authService service.Auth
}

func NewAuthHandler() *AuthHandler {
    jwkManager := internal.NewJwkManager()
    jwtManager := internal.NewJwtManager(internal.DefaultConfig())
    authService := service.NewAuth(jwkManager, jwtManager)
    
    return &AuthHandler{
        authService: authService,
    }
}
```

### Authentication Endpoints

```go
// Login endpoint - generates JWT token
func (h *AuthHandler) Login(c *fiber.Ctx) error {
    type LoginRequest struct {
        Username   string `json:"username"`
        Password   string `json:"password"`
        DeviceType string `json:"device_type"` // "android", "ios", "web"
    }
    
    var req LoginRequest
    if err := c.BodyParser(&req); err != nil {
        return c.Status(400).JSON(fiber.Map{"error": "Invalid request body"})
    }
    
    // Validate credentials (implement your own logic)
    if !validateCredentials(req.Username, req.Password) {
        return c.Status(401).JSON(fiber.Map{"error": "Invalid credentials"})
    }
    
    // Create claims
    claims := map[string]interface{}{
        "username":    req.Username,
        "user_id":     getUserID(req.Username), // implement your own logic
        "scope":       "read:data write:data",
        "device_type": req.DeviceType,
    }
    
    // Generate token
    token, err := h.authService.GenerateToken(claims, req.DeviceType)
    if err != nil {
        return c.Status(500).JSON(fiber.Map{"error": "Failed to generate token"})
    }
    
    return c.JSON(fiber.Map{
        "token":      token,
        "token_type": "Bearer",
        "expires_in": 86400, // 24 hours
    })
}

// JWK endpoint - provides public keys for token verification
func (h *AuthHandler) GetJWKS(c *fiber.Ctx) error {
    jwkSet, err := h.authService.MarshalJwkSet()
    if err != nil {
        return c.Status(500).JSON(fiber.Map{"error": "Failed to get JWK set"})
    }
    
    var jwkSetMap map[string]interface{}
    if err := json.Unmarshal(jwkSet, &jwkSetMap); err != nil {
        return c.Status(500).JSON(fiber.Map{"error": "Failed to parse JWK set"})
    }
    
    c.Set("Content-Type", "application/json")
    return c.JSON(jwkSetMap)
}
```

### Authentication Middleware

```go
func (h *AuthHandler) AuthMiddleware() fiber.Handler {
    return func(c *fiber.Ctx) error {
        authHeader := c.Get("Authorization")
        if authHeader == "" {
            return c.Status(401).JSON(fiber.Map{"error": "Authorization header required"})
        }
        
        // Extract token from "Bearer <token>"
        parts := strings.Split(authHeader, " ")
        if len(parts) != 2 || parts[0] != "Bearer" {
            return c.Status(401).JSON(fiber.Map{"error": "Invalid authorization header format"})
        }
        
        token := parts[1]
        
        // Verify token
        claims, err := h.authService.VerifyTokenSignatureAndGetClaims(token)
        if err != nil {
            return c.Status(401).JSON(fiber.Map{"error": "Invalid or expired token"})
        }
        
        // Store claims in context for use in handlers
        c.Locals("claims", claims)
        c.Locals("username", claims["username"])
        c.Locals("user_id", claims["user_id"])
        
        return c.Next()
    }
}
```

### Complete Fiber Application

```go
func main() {
    app := fiber.New()
    
    // CORS middleware
    app.Use(cors.New())
    
    // Initialize auth handler
    authHandler := NewAuthHandler()
    
    // Public routes
    app.Post("/auth/login", authHandler.Login)
    app.Get("/.well-known/jwks.json", authHandler.GetJWKS)
    
    // Protected routes
    api := app.Group("/api", authHandler.AuthMiddleware())
    
    api.Get("/profile", func(c *fiber.Ctx) error {
        claims := c.Locals("claims").(map[string]interface{})
        return c.JSON(fiber.Map{
            "message": "Protected endpoint",
            "user":    claims,
        })
    })
    
    api.Get("/data", func(c *fiber.Ctx) error {
        username := c.Locals("username").(string)
        return c.JSON(fiber.Map{
            "message": "Hello " + username,
            "data":    []string{"item1", "item2", "item3"},
        })
    })
    
    log.Fatal(app.Listen(":3000"))
}

// Helper functions (implement according to your needs)
func validateCredentials(username, password string) bool {
    // Implement your credential validation logic
    return username == "admin" && password == "password"
}

func getUserID(username string) string {
    // Implement your user ID lookup logic
    return "user_" + username
}
```

## Integration with Echo

Here's how to integrate with Echo framework:

### Setup

```go
package main

import (
    "encoding/json"
    "net/http"
    "strings"
    
    "github.com/labstack/echo/v4"
    "github.com/labstack/echo/v4/middleware"
    "github.com/sushan531/jwk-auth/internal"
    "github.com/sushan531/jwk-auth/service"
)

type AuthHandler struct {
    authService service.Auth
}

func NewAuthHandler() *AuthHandler {
    jwkManager := internal.NewJwkManager()
    jwtManager := internal.NewJwtManager(internal.DefaultConfig())
    authService := service.NewAuth(jwkManager, jwtManager)
    
    return &AuthHandler{
        authService: authService,
    }
}
```

### Authentication Endpoints

```go
func (h *AuthHandler) Login(c echo.Context) error {
    type LoginRequest struct {
        Username   string `json:"username"`
        Password   string `json:"password"`
        DeviceType string `json:"device_type"`
    }
    
    var req LoginRequest
    if err := c.Bind(&req); err != nil {
        return c.JSON(http.StatusBadRequest, map[string]string{"error": "Invalid request body"})
    }
    
    // Validate credentials
    if !validateCredentials(req.Username, req.Password) {
        return c.JSON(http.StatusUnauthorized, map[string]string{"error": "Invalid credentials"})
    }
    
    // Create claims
    claims := map[string]interface{}{
        "username":    req.Username,
        "user_id":     getUserID(req.Username),
        "scope":       "read:data write:data",
        "device_type": req.DeviceType,
    }
    
    // Generate token
    token, err := h.authService.GenerateToken(claims, req.DeviceType)
    if err != nil {
        return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Failed to generate token"})
    }
    
    return c.JSON(http.StatusOK, map[string]interface{}{
        "token":      token,
        "token_type": "Bearer",
        "expires_in": 86400,
    })
}

func (h *AuthHandler) GetJWKS(c echo.Context) error {
    jwkSet, err := h.authService.MarshalJwkSet()
    if err != nil {
        return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Failed to get JWK set"})
    }
    
    var jwkSetMap map[string]interface{}
    if err := json.Unmarshal(jwkSet, &jwkSetMap); err != nil {
        return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Failed to parse JWK set"})
    }
    
    return c.JSON(http.StatusOK, jwkSetMap)
}
```

### Authentication Middleware

```go
func (h *AuthHandler) AuthMiddleware() echo.MiddlewareFunc {
    return func(next echo.HandlerFunc) echo.HandlerFunc {
        return func(c echo.Context) error {
            authHeader := c.Request().Header.Get("Authorization")
            if authHeader == "" {
                return c.JSON(http.StatusUnauthorized, map[string]string{"error": "Authorization header required"})
            }
            
            parts := strings.Split(authHeader, " ")
            if len(parts) != 2 || parts[0] != "Bearer" {
                return c.JSON(http.StatusUnauthorized, map[string]string{"error": "Invalid authorization header format"})
            }
            
            token := parts[1]
            
            claims, err := h.authService.VerifyTokenSignatureAndGetClaims(token)
            if err != nil {
                return c.JSON(http.StatusUnauthorized, map[string]string{"error": "Invalid or expired token"})
            }
            
            c.Set("claims", claims)
            c.Set("username", claims["username"])
            c.Set("user_id", claims["user_id"])
            
            return next(c)
        }
    }
}
```

### Complete Echo Application

```go
func main() {
    e := echo.New()
    
    // Middleware
    e.Use(middleware.Logger())
    e.Use(middleware.Recover())
    e.Use(middleware.CORS())
    
    // Initialize auth handler
    authHandler := NewAuthHandler()
    
    // Public routes
    e.POST("/auth/login", authHandler.Login)
    e.GET("/.well-known/jwks.json", authHandler.GetJWKS)
    
    // Protected routes group
    api := e.Group("/api", authHandler.AuthMiddleware())
    
    api.GET("/profile", func(c echo.Context) error {
        claims := c.Get("claims").(map[string]interface{})
        return c.JSON(http.StatusOK, map[string]interface{}{
            "message": "Protected endpoint",
            "user":    claims,
        })
    })
    
    api.GET("/data", func(c echo.Context) error {
        username := c.Get("username").(string)
        return c.JSON(http.StatusOK, map[string]interface{}{
            "message": "Hello " + username,
            "data":    []string{"item1", "item2", "item3"},
        })
    })
    
    e.Logger.Fatal(e.Start(":3000"))
}
```

## API Usage Examples

### Login Request

```bash
curl -X POST http://localhost:3000/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "username": "admin",
    "password": "password",
    "device_type": "android"
  }'
```

Response:
```json
{
  "token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6ImFuZHJvaWQtMTIzNDU2Nzg5MCJ9...",
  "token_type": "Bearer",
  "expires_in": 86400
}
```

### Access Protected Endpoint

```bash
curl -X GET http://localhost:3000/api/profile \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6ImFuZHJvaWQtMTIzNDU2Nzg5MCJ9..."
```

### Get JWK Set

```bash
curl -X GET http://localhost:3000/.well-known/jwks.json
```

## Configuration

You can customize the JWT configuration:

```go
config := &internal.Config{
    TokenExpiry: 2 * time.Hour,  // 2 hours instead of default 24
    KeySize:     4096,           // 4096 bits instead of default 2048
    Algorithm:   "RS256",        // Currently only RS256 is supported
}

jwtManager := internal.NewJwtManager(config)
```

## Key Management

The library supports device-specific key management:

- Each device type (e.g., "android", "ios", "web") gets its own key pair
- Keys are automatically rotated when generating tokens for a device type
- Old tokens become invalid when keys are rotated
- JWK sets contain all active public keys for verification

## Security Considerations

1. **Key Rotation**: Keys are rotated on each token generation, invalidating previous tokens for that device type
2. **Token Expiry**: Tokens have configurable expiry times (default: 24 hours)
3. **Device Isolation**: Different device types use separate keys
4. **Signature Verification**: All tokens are verified using RS256 algorithm
5. **Input Validation**: Key prefixes are validated to prevent injection attacks

## Dependencies

- `github.com/lestrrat-go/jwx/v3` - JWT/JWK handling
- `github.com/gofiber/fiber/v2` - For Fiber integration
- `github.com/labstack/echo/v4` - For Echo integration

## License

This project is licensed under the MIT License.