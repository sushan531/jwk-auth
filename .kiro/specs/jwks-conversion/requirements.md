# Requirements Document

## Introduction

Convert the current individual JWK key management system to use proper JWKS (JSON Web Key Set) format. Each user will have a single JWKS containing all their device keys, following the RFC 7517 standard. This maintains the single device login behavior while adopting industry-standard JWKS format for better interoperability and standards compliance.

## Requirements

### Requirement 1: JWKS Format Adoption

**User Story:** As a system architect, I want to use standard JWKS format for key storage, so that the system follows RFC 7517 specifications and improves interoperability with other JWT systems.

#### Acceptance Criteria

1. WHEN storing user keys THEN the system SHALL use proper JWKS format with a "keys" array
2. WHEN a JWKS is created THEN it SHALL contain the standard JWKS structure: `{"keys": [...]}`
3. WHEN individual keys are stored THEN each key SHALL be a complete JWK object within the keys array
4. WHEN serializing JWKS THEN the system SHALL use `jwk.Set` from the lestrrat-go/jwx library
5. WHEN deserializing JWKS THEN the system SHALL use `jwk.ParseSet()` from the lestrrat-go/jwx library

### Requirement 2: Device-Specific Key Management within JWKS

**User Story:** As a user, I want each device type to have its own key within my JWKS, so that I can maintain separate sessions across different devices while following standards.

#### Acceptance Criteria

1. WHEN a user logs in from a device type THEN the old key for that device type SHALL be removed from the JWKS
2. WHEN a user logs in from a device type THEN a new key for that device type SHALL be added to the JWKS
3. WHEN identifying device keys THEN each key SHALL have a "use" claim indicating the device type
4. WHEN searching for device keys THEN the system SHALL filter keys by the "use" claim
5. WHEN a device key is removed THEN only that specific key SHALL be removed from the JWKS keys array

### Requirement 3: Single Device Login with JWKS

**User Story:** As a security administrator, I want to maintain single device login behavior using JWKS, so that users can only have one active session per device type.

#### Acceptance Criteria

1. WHEN a user logs in from web THEN any existing web key SHALL be removed from their JWKS
2. WHEN a user logs in from android THEN any existing android key SHALL be removed from their JWKS  
3. WHEN a user logs in from ios THEN any existing ios key SHALL be removed from their JWKS
4. WHEN a user has multiple device sessions THEN their JWKS SHALL contain exactly one key per active device type
5. WHEN all device keys are removed THEN the user's JWKS SHALL be deleted from the database

### Requirement 4: JWKS Database Storage

**User Story:** As a database administrator, I want JWKS to be stored efficiently in the database, so that key operations are performant and storage is optimized.

#### Acceptance Criteria

1. WHEN storing a JWKS THEN it SHALL be serialized as a complete JWKS JSON string
2. WHEN retrieving a JWKS THEN it SHALL be deserialized back to a `jwk.Set` object
3. WHEN updating device keys THEN the entire JWKS SHALL be updated atomically
4. WHEN querying by key ID THEN the system SHALL search through all user JWKS efficiently
5. WHEN a JWKS becomes empty THEN the database row SHALL be removed

### Requirement 5: Key Identification and Lookup

**User Story:** As a developer, I want to identify and retrieve keys efficiently from JWKS, so that token verification and signing operations are fast.

#### Acceptance Criteria

1. WHEN generating a key ID THEN it SHALL follow the format: `{deviceType}-{userID}-{timestamp}`
2. WHEN storing keys in JWKS THEN each key SHALL have a unique "kid" (key ID) claim
3. WHEN storing keys in JWKS THEN each key SHALL have a "use" claim indicating device type
4. WHEN searching for a key by ID THEN the system SHALL iterate through all user JWKS to find matches
5. WHEN caching keys THEN the system SHALL maintain reverse lookup from key ID to user ID

### Requirement 6: Backward Compatibility

**User Story:** As a developer, I want the existing API to continue working, so that no changes are required to the service layer or CLI interface.

#### Acceptance Criteria

1. WHEN calling CreateSessionKey THEN the method signature SHALL remain unchanged
2. WHEN calling DeleteSessionKey THEN the method signature SHALL remain unchanged
3. WHEN calling GetSessionKeys THEN it SHALL return key IDs from the JWKS keys array
4. WHEN calling GetPrivateKeyByID THEN it SHALL extract the key from the appropriate JWKS
5. WHEN calling GetPublicKeys THEN it SHALL return all public keys from all user JWKS

### Requirement 7: JWKS Standards Compliance

**User Story:** As a system integrator, I want the JWKS to be fully compliant with RFC 7517, so that it can be used with standard JWT libraries and tools.

#### Acceptance Criteria

1. WHEN creating a JWKS THEN it SHALL have the structure: `{"keys": [jwk1, jwk2, ...]}`
2. WHEN adding keys to JWKS THEN each key SHALL be a valid JWK according to RFC 7515
3. WHEN serializing JWKS THEN it SHALL be valid JSON that can be parsed by standard libraries
4. WHEN exposing JWKS THEN it SHALL be suitable for use in `/.well-known/jwks.json` endpoints
5. WHEN validating JWKS THEN it SHALL pass standard JWKS validation tools

### Requirement 8: Migration from Current Format

**User Story:** As a system administrator, I want to migrate existing individual JWK keys to JWKS format, so that the transition is seamless and no data is lost.

#### Acceptance Criteria

1. WHEN migrating existing data THEN individual JWK keys SHALL be combined into proper JWKS per user
2. WHEN migrating device keys THEN the "use" claim SHALL be set based on the device type
3. WHEN migration is complete THEN all existing functionality SHALL work with the new JWKS format
4. WHEN migration fails THEN the system SHALL provide clear error messages and rollback options
5. WHEN migration is successful THEN the old individual key storage format SHALL be deprecated