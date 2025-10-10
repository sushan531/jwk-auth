# Technology Stack

## Core Technologies

- **Language**: Go 1.25.1
- **Database**: PostgreSQL 15+
- **CLI Framework**: Cobra (spf13/cobra)
- **JWT Library**: lestrrat-go/jwx/v3
- **Database Driver**: lib/pq (PostgreSQL driver)
- **UUID Generation**: google/uuid

## Key Dependencies

- `github.com/lestrrat-go/jwx/v3` - JWT/JWK handling and cryptographic operations
- `github.com/spf13/cobra` - CLI command structure and argument parsing
- `github.com/lib/pq` - PostgreSQL database connectivity
- `github.com/google/uuid` - UUID generation for database records

## Build & Development Commands

### Basic Operations
```bash
# Run the CLI application (legacy mode)
go run main.go menu

# Build the application
go build -o jwk-auth main.go

# Run with custom database settings
export DB_HOST=localhost
export DB_PORT=5432
export DB_USER=myuser
export DB_PASSWORD=mypassword
export DB_NAME=mydb
go run main.go menu

# Use as library in REST API (recommended)
# Import: github.com/sushan531/jwk-auth/service
# Import: github.com/sushan531/jwk-auth/internal/manager
```

### Database Setup
```bash
# Start PostgreSQL with Docker
docker-compose up -d postgres

# Manual PostgreSQL container
docker run -d \
  --name jwk-postgres \
  -e POSTGRES_USER=myuser \
  -e POSTGRES_PASSWORD=mypassword \
  -e POSTGRES_DB=mydb \
  -p 5432:5432 \
  postgres:15
```

### Go Module Management
```bash
# Download dependencies
go mod download

# Update dependencies
go mod tidy

# Vendor dependencies (if needed)
go mod vendor
```

## Environment Configuration

The application uses environment variables for database configuration:
- `DB_HOST` (default: localhost)
- `DB_PORT` (default: 5432)
- `DB_USER` (default: myuser)
- `DB_PASSWORD` (default: mypassword)
- `DB_NAME` (default: mydb)
- `DB_SSLMODE` (default: disable)
## 
Session-Based Key Management

### Key Features
- **Per-Session Keys**: Each login generates a unique RSA key pair
- **Device Tracking**: Keys are tagged with device type (web, android, ios, etc.)
- **Database-First Storage**: PostgreSQL is primary storage, memory is performance cache
- **Persistent Keys**: All keys stored in database for durability across restarts
- **Memory Caching**: Fast access with automatic database fallback
- **Single Device Login**: Only one active session per device type per user
- **Selective Logout**: Individual session invalidation without affecting other devices

### Integration Pattern for REST APIs
```go
// Initialize components
userRepo := repository.NewUserAuthRepository(db)
jwkManager := manager.NewJwkManager(userRepo)
jwtManager := manager.NewJwtManager(jwkManager)
authService := service.NewAuthService(jwtManager, jwkManager)

// On user login (consolidated keyset approach)
keyID, err := jwkManager.CreateSessionKey(userID, "web")
tokenPair, err := authService.GenerateTokenPairWithKeyID(user, keyID)

// On user logout (removes device key from consolidated keyset)
err := jwkManager.DeleteSessionKey(userID, keyID)

// On token verification (searches consolidated keysets)
user, err := authService.VerifyToken(accessToken)

// Key lookup across all users (efficient reverse lookup)
keyset, err := userRepo.FindKeysetByKeyID(keyID)
```

### Database Tables
- `user_keysets`: Consolidated keyset storage with JSONB support
  - `user_id` (PRIMARY KEY): User identifier
  - `key_data` (JSONB): Device keys stored as `{"web": "jwk_json", "android": "jwk_json"}`
  - `created`, `updated`: Timestamps for tracking keyset lifecycle

### JWX Library Integration
- Uses `jwk.Import(privateKey)` to create JWK from RSA keys
- Uses `json.Marshal(jwkKey)` to serialize JWK for database storage
- Uses `jwk.ParseKey([]byte(keyData))` to deserialize JWK from database
- Uses `jwk.Export(jwkKey, &rsaPrivateKey)` to extract RSA key for JWT signing