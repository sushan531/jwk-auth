# Design Document

## Overview

This design converts the current individual JWK key storage system to use proper JWKS (JSON Web Key Set) format according to RFC 7517. Each user will have a single JWKS containing all their device keys, maintaining single device login behavior while adopting industry-standard format for better interoperability.

## Architecture

### Current vs New Data Model

**Current Model (Individual JWK Keys):**
```json
{
  "web": "serialized_individual_jwk_key",
  "android": "serialized_individual_jwk_key"
}
```

**New Model (Proper JWKS):**
```json
{
  "keys": [
    {
      "kty": "RSA",
      "kid": "web-123-1234567890",
      "use": "web",
      "n": "...",
      "e": "AQAB",
      "d": "..."
    },
    {
      "kty": "RSA", 
      "kid": "android-123-1234567891",
      "use": "android",
      "n": "...",
      "e": "AQAB",
      "d": "..."
    }
  ]
}
```

### Key Identification Strategy

Each key within the JWKS will be identified using:
- **kid (Key ID)**: Format `{deviceType}-{userID}-{timestamp}` for uniqueness
- **use**: Custom claim indicating device type (web, android, ios, etc.)
- **kty**: Key type (RSA for our implementation)

## Components and Interfaces

### Database Schema (No Changes Required)

The existing `user_keysets` table structure remains the same:
```sql
CREATE TABLE user_keysets (
    user_id INTEGER PRIMARY KEY,
    key_data JSONB NOT NULL,  -- Now stores complete JWKS JSON
    created TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);
```

### Updated Data Models

```go
// UserKeyset now stores complete JWKS
type UserKeyset struct {
    UserID   int       `json:"user_id"`
    KeyData  string    `json:"key_data"`  // Complete JWKS JSON string
    Created  time.Time `json:"created"`
    Updated  time.Time `json:"updated"`
}

// Helper methods for JWKS operations
func (uk *UserKeyset) GetJWKS() (jwk.Set, error) {
    if uk.KeyData == "" {
        return jwk.NewSet(), nil
    }
    return jwk.ParseSet([]byte(uk.KeyData))
}

func (uk *UserKeyset) SetJWKS(keySet jwk.Set) error {
    keyBytes, err := json.Marshal(keySet)
    if err != nil {
        return fmt.Errorf("failed to marshal JWKS: %w", err)
    }
    uk.KeyData = string(keyBytes)
    uk.Updated = time.Now()
    return nil
}

func (uk *UserKeyset) GetDeviceKey(deviceType string) (jwk.Key, error) {
    keySet, err := uk.GetJWKS()
    if err != nil {
        return nil, err
    }
    
    // Find key with matching "use" claim
    for i := 0; i < keySet.Len(); i++ {
        key, _ := keySet.Key(i)
        if use, exists := key.Get("use"); exists && use == deviceType {
            return key, nil
        }
    }
    return nil, fmt.Errorf("no key found for device type: %s", deviceType)
}

func (uk *UserKeyset) SetDeviceKey(deviceType string, key jwk.Key) error {
    keySet, err := uk.GetJWKS()
    if err != nil {
        return err
    }
    
    // Remove existing key for this device type
    uk.RemoveDeviceKey(deviceType)
    
    // Set the "use" claim to identify device type
    if err := key.Set("use", deviceType); err != nil {
        return fmt.Errorf("failed to set use claim: %w", err)
    }
    
    // Add key to the set
    if err := keySet.AddKey(key); err != nil {
        return fmt.Errorf("failed to add key to JWKS: %w", err)
    }
    
    return uk.SetJWKS(keySet)
}

func (uk *UserKeyset) RemoveDeviceKey(deviceType string) error {
    keySet, err := uk.GetJWKS()
    if err != nil {
        return err
    }
    
    // Find and remove key with matching "use" claim
    for i := 0; i < keySet.Len(); i++ {
        key, _ := keySet.Key(i)
        if use, exists := key.Get("use"); exists && use == deviceType {
            if err := keySet.RemoveKey(key); err != nil {
                return fmt.Errorf("failed to remove key from JWKS: %w", err)
            }
            break
        }
    }
    
    return uk.SetJWKS(keySet)
}

func (uk *UserKeyset) HasDeviceKey(deviceType string) bool {
    _, err := uk.GetDeviceKey(deviceType)
    return err == nil
}

func (uk *UserKeyset) IsEmpty() bool {
    keySet, err := uk.GetJWKS()
    if err != nil {
        return true
    }
    return keySet.Len() == 0
}

func (uk *UserKeyset) GetDeviceTypes() []string {
    keySet, err := uk.GetJWKS()
    if err != nil {
        return []string{}
    }
    
    var deviceTypes []string
    for i := 0; i < keySet.Len(); i++ {
        key, _ := keySet.Key(i)
        if use, exists := key.Get("use"); exists {
            if useStr, ok := use.(string); ok {
                deviceTypes = append(deviceTypes, useStr)
            }
        }
    }
    return deviceTypes
}
```

### JWK Manager Updates

```go
type jwkManager struct {
    userRepo    repository.UserAuthRepository
    config      *config.Config
    // Cache: userID -> UserKeyset (contains JWKS JSON)
    userKeysets map[int]*model.UserKeyset
    // Parsed JWKS cache: userID -> jwk.Set
    parsedJWKS  map[int]jwk.Set
    // Individual key cache: keyID -> jwk.Key (for performance)
    parsedKeys  map[string]jwk.Key
    // Reverse lookup cache: keyID -> userID
    keyToUser   map[string]int
}

// Key operations using JWKS:
func (j *jwkManager) CreateSessionKey(userID int, deviceType string) (string, error) {
    // Generate RSA private key
    privateKey, err := rsa.GenerateKey(rand.Reader, j.config.JWT.RSAKeySize)
    if err != nil {
        return "", fmt.Errorf("failed to generate private key: %w", err)
    }

    // Create JWK from RSA key
    key, err := jwk.Import(privateKey)
    if err != nil {
        return "", fmt.Errorf("failed to import RSA key into JWK: %w", err)
    }

    // Generate unique key ID
    keyID := fmt.Sprintf("%s-%d-%d", deviceType, userID, time.Now().UnixNano())
    
    // Set key ID and use claims
    if err := key.Set(jwk.KeyIDKey, keyID); err != nil {
        return "", fmt.Errorf("failed to set key ID: %w", err)
    }
    if err := key.Set("use", deviceType); err != nil {
        return "", fmt.Errorf("failed to set use claim: %w", err)
    }

    // Load or create user's JWKS
    keyset, err := j.userRepo.GetUserKeyset(userID)
    if err != nil {
        keyset = &model.UserKeyset{
            UserID:  userID,
            KeyData: "",
            Created: time.Now(),
            Updated: time.Now(),
        }
    }

    // Add/replace device key in JWKS
    if err := keyset.SetDeviceKey(deviceType, key); err != nil {
        return "", fmt.Errorf("failed to set device key in JWKS: %w", err)
    }

    // Save updated JWKS to database
    if err := j.userRepo.SaveUserKeyset(userID, keyset.KeyData); err != nil {
        return "", fmt.Errorf("failed to save JWKS to database: %w", err)
    }

    // Update caches
    j.userKeysets[userID] = keyset
    j.parsedKeys[keyID] = key
    j.keyToUser[keyID] = userID
    
    // Update JWKS cache
    if jwks, err := keyset.GetJWKS(); err == nil {
        j.parsedJWKS[userID] = jwks
    }

    return keyID, nil
}
```

## Data Models

### JWKS Structure
Following RFC 7517, each user's JWKS will have:
- **keys**: Array of JWK objects
- Each JWK contains:
  - **kty**: Key type (RSA)
  - **kid**: Key identifier (unique per key)
  - **use**: Device type identifier (custom claim)
  - **n, e, d**: RSA key components

### Device Key Management
- Keys are identified by the "use" claim within the JWKS
- Single device login: only one key per device type per user
- Key replacement: remove old key, add new key for same device type

## Error Handling

### JWKS Parsing Errors
- Handle malformed JWKS JSON in database
- Graceful fallback when JWKS cannot be parsed
- Clear error messages for debugging

### Key Not Found Scenarios
- When a device type has no key in the JWKS
- When a key ID is not found in any user's JWKS
- When a user has no JWKS (empty key set)

### Concurrent Access
- Handle concurrent updates to the same user's JWKS
- Atomic operations for JWKS updates
- Proper locking mechanisms for cache updates

## Testing Strategy

### Unit Tests
- Test JWKS creation and manipulation
- Test device key addition/removal within JWKS
- Test key lookup by ID across all user JWKS
- Test single device login logic with JWKS

### Integration Tests
- Test database operations with real JWKS data
- Test JWKS serialization/deserialization
- Test migration from individual JWK to JWKS format

### Standards Compliance Tests
- Validate JWKS format against RFC 7517
- Test interoperability with standard JWT libraries
- Verify JWKS can be used in standard endpoints

## Implementation Phases

### Phase 1: Update Data Models
1. Modify UserKeyset to store complete JWKS
2. Implement JWKS helper methods
3. Update repository to handle JWKS format

### Phase 2: Update JWK Manager
1. Modify CreateSessionKey to work with JWKS
2. Update DeleteSessionKey for JWKS
3. Update key retrieval methods for JWKS format

### Phase 3: Migration and Testing
1. Implement migration from individual JWK to JWKS
2. Update caching strategy for JWKS
3. Comprehensive testing and validation

### Phase 4: Standards Compliance
1. Ensure full RFC 7517 compliance
2. Add support for JWKS endpoints
3. Documentation and examples

## Migration Strategy

### Data Migration
Convert existing individual JWK keys to proper JWKS format:

```go
func migrateToJWKS(userID int, oldKeyData map[string]string) (*model.UserKeyset, error) {
    keySet := jwk.NewSet()
    
    for deviceType, keyDataStr := range oldKeyData {
        // Parse individual JWK
        key, err := jwk.ParseKey([]byte(keyDataStr))
        if err != nil {
            continue // Skip invalid keys
        }
        
        // Set "use" claim for device identification
        if err := key.Set("use", deviceType); err != nil {
            continue
        }
        
        // Add to JWKS
        if err := keySet.AddKey(key); err != nil {
            continue
        }
    }
    
    // Create new UserKeyset with JWKS
    keyset := &model.UserKeyset{
        UserID:  userID,
        Created: time.Now(),
        Updated: time.Now(),
    }
    
    if err := keyset.SetJWKS(keySet); err != nil {
        return nil, err
    }
    
    return keyset, nil
}
```

### Rollback Plan
- Keep backup of old format during migration
- Feature flag to switch between formats
- Automated rollback on migration failure

## Performance Considerations

### JWKS Operations
- Cache parsed JWKS objects to avoid repeated parsing
- Efficient key lookup within JWKS using "use" claim
- Batch operations when updating multiple keys

### Memory Usage
- Cache complete JWKS per user instead of individual keys
- Implement LRU eviction for JWKS cache
- Lazy loading of JWKS when needed

### Database Performance
- Single JSON field per user reduces query complexity
- JSONB indexing for efficient key searches
- Atomic updates for JWKS modifications

## Standards Compliance

### RFC 7517 Compliance
- Proper JWKS structure with "keys" array
- Valid JWK format for each key
- Standard claims (kty, kid, use, etc.)

### Interoperability
- Compatible with standard JWT libraries
- Suitable for `/.well-known/jwks.json` endpoints
- Follows industry best practices for key management