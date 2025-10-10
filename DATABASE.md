# Database Setup

## PostgreSQL Configuration

The application uses PostgreSQL to persist JWK sets, ensuring tokens remain valid across application restarts.

### Quick Start with Docker

1. Start PostgreSQL using Docker Compose:
```bash
docker-compose up -d postgres
```

2. Run the application:
```bash
go run main.go menu
```

### Manual PostgreSQL Setup

If you prefer to run PostgreSQL manually:

```bash
docker run -d \
  --name jwk-postgres \
  -e POSTGRES_USER=myuser \
  -e POSTGRES_PASSWORD=mypassword \
  -e POSTGRES_DB=mydb \
  -p 5432:5432 \
  postgres:15
```

### Environment Variables

You can customize the database connection using these environment variables:

- `DB_HOST` (default: localhost)
- `DB_PORT` (default: 5432)
- `DB_USER` (default: myuser)
- `DB_PASSWORD` (default: mypassword)
- `DB_NAME` (default: mydb)
- `DB_SSLMODE` (default: disable)

Example:
```bash
export DB_HOST=localhost
export DB_PORT=5432
export DB_USER=myuser
export DB_PASSWORD=mypassword
export DB_NAME=mydb

go run main.go menu
```

## Database Schema

The application uses two main tables for key management:

### Legacy Table (Backward Compatibility)
```sql
CREATE TABLE user_auth (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id INTEGER NOT NULL UNIQUE,
    key_set TEXT NOT NULL,
    created TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);
```

### Session-Based Key Management (Recommended)
```sql
CREATE TABLE user_session_keys (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id INTEGER NOT NULL,
    key_id VARCHAR(255) NOT NULL UNIQUE,
    key_data TEXT NOT NULL,
    device_type VARCHAR(50) NOT NULL,
    created TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);
```

### Indexes
- `idx_user_auth_user_id` - Fast lookups by user ID (legacy)
- `idx_user_session_keys_user_id` - Fast lookups by user ID
- `idx_user_session_keys_key_id` - Fast lookups by key ID
- `idx_user_session_keys_device_type` - Fast lookups by device type

## Key Features

### Session-Based Key Management (Recommended)
- **Single Device Login**: Only one active session per device type per user
- **Automatic Invalidation**: New login invalidates existing sessions for same device type
- **Device Isolation**: Keys are isolated by device type (web, android, ios, etc.)
- **Cross-Device Support**: Users can be logged in from different device types simultaneously
- **Selective Logout**: Can invalidate specific sessions without affecting other device types
- **Automatic Cleanup**: Keys are removed when users log out or when new sessions are created

### Legacy Features (Backward Compatibility)
- **Persistent JWK Sets**: Key sets are stored in PostgreSQL and loaded on startup
- **Token Continuity**: Tokens issued in previous sessions remain valid
- **Key Rotation**: Generate new key sets while maintaining database persistence
- **Multi-User Support**: Each user can have their own key set (user_id column)

## Usage Flow

### Session-Based Flow (Recommended for REST APIs)
1. **User Login**: 
   - Authenticate user credentials
   - Call `CreateSessionKey(userID, deviceType)` (e.g., "web", "android")
   - **Automatic Invalidation**: Existing sessions for same device type are automatically invalidated
   - Generate access/refresh token pair using the new key
   - Return tokens to client

2. **Token Verification**:
   - Extract key ID from JWT header
   - Use `GetPrivateKeyByID(keyID)` to verify token signature
   - Validate token claims and expiration

3. **User Logout**:
   - Call `DeleteSessionKey(userID, keyID)` to invalidate specific session
   - Or `DeleteAllUserSessionKeys(userID)` to logout from all devices

4. **Token Refresh**:
   - Verify refresh token using existing session key
   - Generate new access token with same key ID

5. **Single Device Enforcement**:
   - Only one active session per device type (web, android, ios, etc.)
   - New login from same device type invalidates previous session
   - Different device types can coexist (user can be logged in on web + android simultaneously)

### Legacy Flow (CLI Applications)
1. **First Run**: Creates new JWK set and saves to database
2. **Subsequent Runs**: Loads existing JWK set from database
3. **Token Verification**: Uses persisted keys to verify tokens from previous sessions
4. **Key Regeneration**: Option to create new key sets (invalidates old tokens)