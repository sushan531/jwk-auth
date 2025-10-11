# Implementation Plan

- [x] 1. Update UserKeyset model for JWKS format
  - Modify UserKeyset struct to store complete JWKS as string instead of map
  - Implement GetJWKS() method using jwk.ParseSet() to deserialize JWKS
  - Implement SetJWKS() method using json.Marshal() to serialize JWKS
  - Add GetDeviceKey() method to find keys by "use" claim within JWKS
  - Add SetDeviceKey() method to add/replace keys in JWKS with "use" claim
  - Add RemoveDeviceKey() method to remove keys from JWKS by "use" claim
  - Update HasDeviceKey(), IsEmpty(), and GetDeviceTypes() methods for JWKS
  - _Requirements: 1.1, 1.2, 1.3, 2.3, 2.4, 4.1, 4.2_

- [ ] 2. Update JWK Manager for JWKS operations
  - [x] 2.1 Modify CreateSessionKey for JWKS format
    - Use rsa.GenerateKey() to create RSA private key
    - Use jwk.Import(privateKey) to create JWK from RSA key
    - Set "kid" claim using key.Set(jwk.KeyIDKey, keyID) with format: deviceType-userID-timestamp
    - Set "use" claim using key.Set("use", deviceType) for device identification
    - Load user's existing JWKS using GetUserKeyset() and GetJWKS()
    - Remove old device key using SetDeviceKey() (which handles replacement)
    - Save updated JWKS using SetJWKS() and SaveUserKeyset()
    - Update memory caches with new key and JWKS
    - _Requirements: 1.4, 2.1, 2.2, 3.1, 5.1, 5.2, 5.3_

  - [x] 2.2 Modify DeleteSessionKey for JWKS format
    - Load user's JWKS using GetUserKeyset() and GetJWKS()
    - Find key by iterating through JWKS keys and matching "kid" claim
    - Extract device type from "use" claim of found key
    - Remove device key using RemoveDeviceKey() method
    - Save updated JWKS or delete if empty using IsEmpty() check
    - Update memory caches by removing specific key references
    - _Requirements: 2.5, 3.5, 4.5_

  - [x] 2.3 Update GetSessionKeys for JWKS format
    - Load user's JWKS using GetUserKeyset() and GetJWKS()
    - Iterate through JWKS keys using keySet.Len() and keySet.Key(i)
    - Extract "kid" claim from each key using key.Get(jwk.KeyIDKey)
    - Return array of key IDs from the JWKS
    - _Requirements: 6.3_

  - [x] 2.4 Update GetPrivateKeyByID for JWKS format
    - Check memory cache first for parsed keys
    - If not cached, use FindKeysetByKeyID() to locate user's JWKS
    - Parse JWKS using GetJWKS() method
    - Find specific key by iterating and matching "kid" claim
    - Use jwk.Export(key, &rsaPrivateKey) to extract RSA key for JWT signing
    - Update memory caches with parsed key and user mapping
    - _Requirements: 5.4, 5.5, 6.4_

  - [x] 2.5 Update GetPublicKeys and GetUserPublicKeys for JWKS format
    - For GetPublicKeys: iterate through all user JWKS from GetAllUserKeysets()
    - For GetUserPublicKeys: get specific user's JWKS using GetUserKeyset()
    - Parse each JWKS using GetJWKS() method
    - Extract RSA keys using jwk.Export() for each key in the set
    - Return array of public keys from RSA private keys
    - _Requirements: 6.5_

- [ ] 3. Update repository methods for JWKS storage
  - [x] 3.1 Update FindKeysetByKeyID for JWKS search
    - Get all user keysets using GetAllUserKeysets()
    - For each keyset, parse JWKS using GetJWKS() method
    - Iterate through keys in each JWKS using keySet.Len() and keySet.Key(i)
    - Match "kid" claim using key.Get(jwk.KeyIDKey) against target keyID
    - Return the UserKeyset containing the matching key
    - _Requirements: 5.4, 5.5_

  - [x] 3.2 Update device key operations for JWKS format
    - Modify UpdateDeviceKeyInKeyset to work with JWKS structure
    - Update RemoveDeviceKeyFromKeyset to remove keys from JWKS by "use" claim
    - Ensure atomic operations when updating JWKS in database
    - Handle empty JWKS by deleting the entire keyset
    - _Requirements: 4.3, 4.4_

- [ ] 4. Implement migration from individual JWK to JWKS
  - [x] 4.1 Create migration utility function
    - Read existing UserKeyset with map[string]string format
    - Create new jwk.Set using jwk.NewSet()
    - For each device key, parse using jwk.ParseKey()
    - Set "use" claim on each key using key.Set("use", deviceType)
    - Add keys to JWKS using keySet.AddKey()
    - Serialize JWKS using json.Marshal() and update UserKeyset
    - _Requirements: 8.1, 8.2, 8.3_

  - [x] 4.2 Add migration detection and execution
    - Detect old format by checking if KeyData can be unmarshaled as map[string]string
    - Execute migration automatically when old format is detected
    - Provide rollback mechanism in case of migration failure
    - Log migration progress and results for monitoring
    - _Requirements: 8.4, 8.5_

- [ ] 5. Update caching strategy for JWKS
  - [ ] 5.1 Add JWKS-specific caches
    - Add parsedJWKS map[int]jwk.Set cache for complete JWKS per user
    - Update cache management to handle both individual keys and complete JWKS
    - Implement cache invalidation when JWKS is updated
    - Ensure cache consistency between individual keys and JWKS
    - _Requirements: 6.1, 6.2_

  - [ ] 5.2 Update LoadUserKeysFromDB for JWKS
    - Load user's JWKS using GetUserKeyset() and GetJWKS()
    - Cache the complete JWKS in parsedJWKS map
    - Extract individual keys and cache in parsedKeys map
    - Update keyToUser reverse lookup cache
    - Clear old cache entries before loading fresh data
    - _Requirements: 6.1, 6.2_

- [ ]* 6. Add comprehensive testing for JWKS functionality
  - Write unit tests for UserKeyset JWKS methods (GetJWKS, SetJWKS, device key operations)
  - Write unit tests for JWK Manager JWKS operations (create, delete, retrieve keys)
  - Write integration tests for JWKS database operations and caching
  - Write migration tests to verify conversion from individual JWK to JWKS
  - Write standards compliance tests to validate JWKS format against RFC 7517
  - _Requirements: 7.1, 7.2, 7.3, 7.4, 7.5_

- [ ]* 7. Add JWKS endpoint support for standards compliance
  - Create method to export user JWKS in standard format for public key endpoints
  - Add validation to ensure JWKS compliance with RFC 7517
  - Implement JWKS filtering to return only public key components
  - Add documentation and examples for JWKS endpoint usage
  - _Requirements: 7.4, 7.5_