# JWT Authentication Examples

This directory contains examples demonstrating the consolidated keyset management system for JWT authentication.

## Examples Overview

### 1. `consolidated_keyset_example.go`
**Comprehensive demonstration of consolidated keyset management**

Shows the complete workflow of the new consolidated keyset architecture:
- Creating consolidated keysets for multiple users and devices
- Single device login enforcement (automatic invalidation)
- Cross-device session management
- Efficient key lookup and reverse lookup
- Token generation and verification with consolidated keysets
- Selective logout functionality

```bash
go run examples/consolidated_keyset_example.go
```

### 2. `single_device_test.go`
**Single device login behavior with consolidated storage**

Demonstrates how the single device login feature works with consolidated keysets:
- Creating multiple sessions for the same device type
- Automatic invalidation of previous sessions
- Cross-device session coexistence
- Keyset structure visualization

```bash
go run examples/single_device_test.go
```

### 3. `keyset_storage_demo.go`
**Storage efficiency and database operations**

Focuses on the storage benefits of consolidated keysets:
- Single database row per user (vs multiple rows in old schema)
- Device key management within keysets
- Reverse key lookup functionality
- Multi-user keyset operations
- Automatic cleanup when keysets become empty

```bash
go run examples/keyset_storage_demo.go
```

### 4. `optimized_cache_example.go`
**Performance optimization with consolidated caching**

Demonstrates caching performance improvements:
- Entire user keysets cached in memory
- Cache hit/miss performance comparison
- LRU cache management
- Cache metrics and health monitoring
- Memory usage optimization

```bash
go run examples/optimized_cache_example.go
```

## Key Architecture Benefits

### Consolidated Storage
- **Single Row Per User**: All device keys stored in one database row
- **JSONB Efficiency**: PostgreSQL JSONB provides fast JSON operations
- **Reduced Queries**: One query retrieves all user keys (vs N queries in old schema)

### Performance Improvements
- **Keyset Caching**: Entire user keysets cached, not individual keys
- **Reverse Lookup**: Efficient key-to-user mapping with cache
- **LRU Management**: Automatic memory management with eviction
- **Batch Operations**: Multiple device keys updated in single transaction

### Single Device Login
- **Device Isolation**: Keys organized by device type within keyset
- **Automatic Invalidation**: New login replaces existing key for same device type
- **Cross-Device Support**: Different device types coexist in same keyset
- **Selective Logout**: Remove specific device keys without affecting others

## Database Schema

The examples work with the consolidated `user_keysets` table:

```sql
CREATE TABLE user_keysets (
    user_id INTEGER PRIMARY KEY,
    key_data JSONB NOT NULL,  -- {"web": "jwk_json", "android": "jwk_json"}
    created TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);
```

## Prerequisites

1. **PostgreSQL Database**: Running PostgreSQL instance
2. **Environment Variables**: Database connection configuration
3. **Go Dependencies**: Run `go mod download` to install dependencies

```bash
# Set database environment variables
export DB_HOST=localhost
export DB_PORT=5432
export DB_USER=myuser
export DB_PASSWORD=mypassword
export DB_NAME=mydb

# Run any example
go run examples/consolidated_keyset_example.go
```

## Integration Patterns

### REST API Integration
```go
// Initialize components
userRepo := repository.NewUserAuthRepository(db)
jwkManager := manager.NewJwkManager(userRepo)
authService := service.NewAuthService(jwtManager, jwkManager)

// User login - creates/updates device key in consolidated keyset
keyID, err := jwkManager.CreateSessionKey(userID, "web")
tokenPair, err := authService.GenerateTokenPairWithKeyID(user, keyID)

// Token verification - searches consolidated keysets
user, err := authService.VerifyToken(accessToken)

// User logout - removes device key from keyset
err := jwkManager.DeleteSessionKey(userID, keyID)
```

### Key Management Operations
```go
// Get all device keys for a user (single query)
keyset, err := userRepo.GetUserKeyset(userID)

// Find user by key ID (reverse lookup)
keyset, err := userRepo.FindKeysetByKeyID(keyID)

// Update specific device key in keyset
err := userRepo.UpdateDeviceKeyInKeyset(userID, "web", keyID, keyData)

// Remove device key from keyset
err := userRepo.RemoveDeviceKeyFromKeyset(userID, "android")
```

## Migration from Old Schema

The system automatically handles migration from the old `user_session_keys` table to the new consolidated format. See the migration examples in the codebase for details on how existing data is converted to the new schema.