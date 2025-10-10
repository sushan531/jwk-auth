# Design Document

## Overview

This design refactors the session key management system from a "one row per device session" model to a "one row per user with consolidated key set" model. Each user will have a single database row containing a JSON object with all their device keys, implementing proper single device login semantics.

## Architecture

### Current vs New Data Model

**Current Model (Multiple Rows):**
```sql
user_session_keys:
- user_id: 1, key_id: "web-1-123", device_type: "web", key_data: "{jwk}"
- user_id: 1, key_id: "android-1-456", device_type: "android", key_data: "{jwk}"
```

**New Model (Consolidated):**
```sql
user_keysets:
- user_id: 1 (PRIMARY KEY), key_data: {"web": {"kid": "web-1-123", "jwk": {...}}, "android": {"kid": "android-1-456", "jwk": {...}}}
```

### Key Data Structure

The `key_data` JSON field will store JWK keys using the lestrrat-go/jwx library format:
```json
{
  "web": "serialized_jwk_key_json_from_jwx_library",
  "android": "serialized_jwk_key_json_from_jwx_library"
}
```

**Important**: We will use `json.Marshal(jwk.Key)` and `jwk.ParseKey()` from the lestrrat-go/jwx/v3/jwk library to ensure proper JWK serialization and deserialization, maintaining compatibility with the existing JWT signing and verification processes.

## Components and Interfaces

### Database Schema

```sql
CREATE TABLE user_keysets (
    user_id INTEGER PRIMARY KEY,
    key_data JSONB NOT NULL,
    created TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Indexes for performance
CREATE INDEX idx_user_keysets_updated ON user_keysets(updated);
-- GIN index for JSON queries (PostgreSQL specific)
CREATE INDEX idx_user_keysets_key_data ON user_keysets USING GIN (key_data);
```

### Repository Interface

```go
type UserAuthRepository interface {
    // Keyset management
    SaveUserKeyset(userID int, keyData string) error
    GetUserKeyset(userID int) (*model.UserKeyset, error)
    DeleteUserKeyset(userID int) error
    GetAllUserKeysets() ([]*model.UserKeyset, error)
    
    // Device key operations within keyset
    UpdateDeviceKeyInKeyset(userID int, deviceType string, keyID string, keyData string) error
    RemoveDeviceKeyFromKeyset(userID int, deviceType string) error
    
    // Key lookup operations
    FindKeysetByKeyID(keyID string) (*model.UserKeyset, error)
}
```

### Data Models

```go
// New consolidated model using JWX library types
type UserKeyset struct {
    UserID   int                 `json:"user_id"`
    KeyData  map[string]string   `json:"key_data"` // deviceType -> serialized jwk.Key JSON
    Created  time.Time           `json:"created"`
    Updated  time.Time           `json:"updated"`
}

// Helper methods for JWK operations
func (uk *UserKeyset) GetDeviceKey(deviceType string) (jwk.Key, error) {
    keyData, exists := uk.KeyData[deviceType]
    if !exists {
        return nil, fmt.Errorf("no key found for device type: %s", deviceType)
    }
    return jwk.ParseKey([]byte(keyData))
}

func (uk *UserKeyset) SetDeviceKey(deviceType string, key jwk.Key) error {
    keyBytes, err := json.Marshal(key)
    if err != nil {
        return fmt.Errorf("failed to marshal JWK key: %w", err)
    }
    if uk.KeyData == nil {
        uk.KeyData = make(map[string]string)
    }
    uk.KeyData[deviceType] = string(keyBytes)
    return nil
}
```

### JWK Manager Updates

The JWK manager will be updated to work with consolidated keysets using proper JWX library APIs:

```go
type jwkManager struct {
    userRepo repository.UserAuthRepository
    // Cache: userID -> UserKeyset (contains serialized JWK data)
    userKeysets map[int]*model.UserKeyset
    // Parsed JWK cache: keyID -> jwk.Key (for performance)
    parsedKeys map[string]jwk.Key
    // Reverse lookup cache: keyID -> userID
    keyToUser map[string]int
}

// Key operations will use jwx library methods:
// - jwk.Import(privateKey) to create JWK from RSA key
// - json.Marshal(jwkKey) to serialize for database storage
// - jwk.ParseKey([]byte(keyData)) to deserialize from database
// - jwk.Export(jwkKey, &rsaPrivateKey) to extract RSA key for signing
```

## Data Models

### UserKeyset Model
- **UserID**: Primary key, identifies the user
- **KeyData**: JSON object containing device keys
- **Created/Updated**: Timestamps for tracking

### DeviceKey Structure
- **KeyID**: Unique identifier for the key (kid)
- **JWK**: The actual JSON Web Key data

## Error Handling

### Key Not Found Scenarios
- When a key ID is not found in any user's keyset
- When a user has no keyset (no active sessions)
- When a device type is not found in a user's keyset

### Database Consistency
- Handle concurrent updates to the same user's keyset
- Ensure atomic operations when updating device keys
- Graceful handling of JSON parsing errors

### Migration Errors
- Handle cases where existing data cannot be migrated
- Provide rollback mechanisms for failed migrations

## Testing Strategy

### Unit Tests
- Test keyset JSON serialization/deserialization
- Test device key addition/removal operations
- Test key lookup by ID across all users
- Test single device login logic

### Integration Tests
- Test database operations with real PostgreSQL
- Test concurrent access to user keysets
- Test migration from old schema to new schema

### Performance Tests
- Benchmark key lookup performance
- Test memory usage with large numbers of users
- Test JSON query performance in PostgreSQL

## Implementation Phases

### Phase 1: New Schema and Models
1. Create new `user_keysets` table
2. Implement `UserKeyset` and `DeviceKey` models
3. Create new repository methods

### Phase 2: JWK Manager Refactoring
1. Update JWK manager to use consolidated keysets
2. Implement device key management within keysets
3. Update caching strategy for consolidated data

### Phase 3: Migration and Cleanup
1. Implement data migration from old to new schema
2. Update all dependent code
3. Remove old `user_session_keys` table and related code

### Phase 4: Testing and Optimization
1. Comprehensive testing of new system
2. Performance optimization
3. Documentation updates

## Migration Strategy

### Data Migration
```sql
-- Migrate existing data to new format
INSERT INTO user_keysets (user_id, key_data, created, updated)
SELECT 
    user_id,
    json_object_agg(device_type, json_build_object('kid', key_id, 'jwk', key_data::json)),
    min(created),
    max(updated)
FROM user_session_keys 
GROUP BY user_id;
```

### Rollback Plan
- Keep old table during migration period
- Implement feature flag to switch between old/new systems
- Automated rollback if issues are detected

## Performance Considerations

### Database Performance
- Use JSONB for efficient JSON operations in PostgreSQL
- GIN indexes for fast JSON queries
- Single row per user reduces query complexity

### Memory Usage
- Cache entire user keysets instead of individual keys
- Implement LRU cache eviction for memory management
- Lazy loading of keysets when needed

### Lookup Performance
- Maintain reverse lookup cache (keyID -> userID)
- Batch operations when possible
- Efficient JSON parsing and manipulation