# Implementation Plan

- [x] 1. Create new data models and database schema
  - Create UserKeyset model in model/userkeyset.go with proper JWX library integration
  - Add helper methods: GetDeviceKey() and SetDeviceKey() using jwk.ParseKey() and json.Marshal()
  - Update database schema to include user_keysets table with JSONB support
  - Ensure all JWK operations use lestrrat-go/jwx/v3/jwk library APIs
  - _Requirements: 1.1, 1.2, 4.1, 4.2_

- [ ] 2. Implement new repository methods for consolidated keysets
  - [x] 2.1 Create keyset CRUD operations
    - Implement SaveUserKeyset, GetUserKeyset, DeleteUserKeyset methods
    - Add GetAllUserKeysets for system-wide operations
    - _Requirements: 1.3, 4.3_
  
  - [x] 2.2 Implement device key operations within keysets
    - Create UpdateDeviceKeyInKeyset method for single device updates
    - Implement RemoveDeviceKeyFromKeyset for device-specific logout
    - Add FindKeysetByKeyID for reverse key lookup
    - _Requirements: 3.1, 3.2, 3.3_

- [ ] 3. Refactor JWK manager for consolidated key storage
  - [x] 3.1 Update JWK manager data structures
    - Replace sessionKeys map with userKeysets cache
    - Add keyToUser reverse lookup cache for performance
    - Update NewJwkManager constructor
    - _Requirements: 6.3, 6.4_
  
  - [x] 3.2 Implement consolidated CreateSessionKey method
    - Use rsa.GenerateKey() to create RSA private key
    - Use jwk.Import(privateKey) to create JWK from RSA key
    - Set key ID using key.Set(jwk.KeyIDKey, keyID)
    - Load user's existing keyset from database
    - Remove old device key if exists (single device login)
    - Use UserKeyset.SetDeviceKey() to add new JWK key to keyset
    - Save updated keyset to database using json.Marshal(key)
    - _Requirements: 2.1, 2.2, 3.1_
  
  - [x] 3.3 Implement consolidated DeleteSessionKey method
    - Load user's keyset from database
    - Remove specified device key from keyset
    - Save updated keyset or delete if empty
    - Update memory caches
    - _Requirements: 2.4, 3.2, 3.4_
  
  - [x] 3.4 Update key retrieval methods for consolidated storage
    - Modify GetPrivateKeyByID to use jwk.ParseKey() when loading from database
    - Use jwk.Export(key, &rsaPrivateKey) to extract RSA key for JWT signing
    - Update GetSessionKeys to extract key IDs from user's keyset using jwk library
    - Cache parsed jwk.Key objects for performance, not raw JSON
    - _Requirements: 5.4, 6.1, 6.2_

- [ ] 4. Update database connection and table creation
  - [x] 4.1 Add user_keysets table creation to database setup
    - Update CreateTables function in internal/database/postgres.go
    - Add proper indexes for performance
    - Include JSONB support for PostgreSQL
    - _Requirements: 4.1, 4.2, 6.1_
  
  - [x] 4.2 Implement data migration from old to new schema
    - Create migration function to convert user_session_keys to user_keysets
    - Handle JSON aggregation of device keys per user
    - Preserve created/updated timestamps
    - _Requirements: 4.4_

- [ ] 5. Update service layer for backward compatibility
  - [x] 5.1 Ensure AuthService methods work with new storage
    - Verify GenerateTokenPairWithKeyID works with consolidated keys
    - Test RefreshTokensWithKeyID with new key lookup
    - Validate ExtractKeyIDFromToken functionality
    - _Requirements: 5.1, 5.2, 5.3, 5.4_

- [ ] 6. Update CLI menu for consolidated key management
  - [x] 6.1 Test all menu options with new storage system
    - Verify login creates proper consolidated keysets
    - Test logout removes device keys correctly
    - Validate session viewing shows correct active sessions
    - _Requirements: 5.5_

- [ ] 7. Clean up old schema and code
  - [x] 7.1 Remove old user_session_keys table and related code
    - Drop user_session_keys table from schema
    - Remove old SessionKey model
    - Clean up any remaining references to old system
    - _Requirements: 4.4_

- [ ]* 8. Add comprehensive testing
  - [ ]* 8.1 Create unit tests for new models and repository methods
    - Test UserKeyset JSON serialization/deserialization
    - Test device key addition/removal operations
    - Test key lookup across multiple users
    - _Requirements: All requirements_
  
  - [ ]* 8.2 Create integration tests for consolidated key management
    - Test single device login behavior with consolidated storage
    - Test concurrent access to user keysets
    - Test migration from old to new schema
    - _Requirements: 2.1, 2.2, 2.3, 4.4_

- [ ] 9. Performance optimization and documentation
  - [x] 9.1 Optimize key lookup and caching performance
    - Implement efficient reverse lookup cache
    - Add LRU cache eviction for memory management
    - Benchmark performance improvements
    - _Requirements: 6.1, 6.2, 6.3, 6.4_
  
  - [x] 9.2 Update documentation and examples
    - Update DATABASE.md with new schema
    - Update steering documents with consolidated architecture
    - Create examples showing new keyset management
    - _Requirements: All requirements_