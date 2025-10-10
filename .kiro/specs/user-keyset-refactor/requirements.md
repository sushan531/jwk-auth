# Requirements Document

## Introduction

Refactor the current session key management system to store multiple device keys in a single JSON field per user, rather than separate rows per device. This will implement proper single device login where each device type (web, android, ios) has one active key per user, stored together in a consolidated key set.

## Requirements

### Requirement 1: Consolidated Key Storage

**User Story:** As a system administrator, I want user keys to be stored in a consolidated format per user, so that key management is more efficient and follows JWK set standards.

#### Acceptance Criteria

1. WHEN a user has multiple device sessions THEN all keys SHALL be stored in a single database row per user
2. WHEN storing keys THEN the key_data field SHALL contain a JSON object with device types as keys and JWK data as values
3. WHEN querying user keys THEN the system SHALL retrieve all device keys from a single database query
4. WHEN a user has no active sessions THEN their database row SHALL be removed

### Requirement 2: Single Device Login per Device Type

**User Story:** As a user, I want only one active session per device type, so that my account remains secure and previous sessions are automatically invalidated.

#### Acceptance Criteria

1. WHEN a user logs in from a device type THEN any existing key for that device type SHALL be removed
2. WHEN a user logs in from a device type THEN a new key for that device type SHALL be created and stored
3. WHEN a user has sessions on multiple device types THEN each device type SHALL have exactly one active key
4. WHEN a user logs out from a device type THEN only that device type's key SHALL be removed
5. WHEN a user logs out from all devices THEN all keys SHALL be removed and the user row SHALL be deleted

### Requirement 3: Device Type Key Management

**User Story:** As a developer, I want to manage keys by device type within a user's key set, so that I can easily add, update, or remove keys for specific devices.

#### Acceptance Criteria

1. WHEN creating a session key THEN the system SHALL identify the device type and update only that key within the user's key set
2. WHEN deleting a session key THEN the system SHALL remove only the specified device type key from the user's key set
3. WHEN retrieving a key by ID THEN the system SHALL search through all users' key sets to find the matching key
4. WHEN a key set becomes empty THEN the user's database row SHALL be removed

### Requirement 4: Database Schema Migration

**User Story:** As a system administrator, I want the database schema to support consolidated key storage, so that the system can efficiently manage user key sets.

#### Acceptance Criteria

1. WHEN the system starts THEN it SHALL use a user_keysets table with user_id as primary key
2. WHEN storing key data THEN the key_data field SHALL contain JSON with structure: `{"web": {...}, "android": {...}}`
3. WHEN querying keys THEN the system SHALL support efficient lookups by user_id
4. WHEN the schema is updated THEN existing data migration SHALL be handled gracefully

### Requirement 5: Backward Compatibility

**User Story:** As a developer, I want the key management interface to remain consistent, so that existing code continues to work without changes.

#### Acceptance Criteria

1. WHEN calling CreateSessionKey THEN the method signature SHALL remain unchanged
2. WHEN calling DeleteSessionKey THEN the method signature SHALL remain unchanged  
3. WHEN calling GetSessionKeys THEN the method SHALL return the same format as before
4. WHEN calling key retrieval methods THEN they SHALL work with the new storage format
5. WHEN the system is updated THEN no changes SHALL be required to the service or menu layers

### Requirement 6: Performance Optimization

**User Story:** As a system user, I want key operations to be fast and efficient, so that authentication doesn't introduce unnecessary delays.

#### Acceptance Criteria

1. WHEN retrieving user keys THEN the system SHALL require only one database query per user
2. WHEN updating a device key THEN the system SHALL update only the user's row, not create new rows
3. WHEN caching keys THEN the system SHALL cache the entire user key set for optimal performance
4. WHEN searching for a key by ID THEN the system SHALL use efficient lookup mechanisms