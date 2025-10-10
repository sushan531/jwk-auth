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

The application uses a consolidated table for efficient key management:

### Consolidated Keyset Management
```sql
CREATE TABLE user_keysets (
    user_id INTEGER PRIMARY KEY,
    key_data JSONB NOT NULL,
    created TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Performance indexes
CREATE INDEX idx_user_keysets_updated ON user_keysets(updated);
CREATE INDEX idx_user_keysets_key_data ON user_keysets USING GIN (key_data);
```

### Key Data Structure
The `key_data` JSONB field stores device keys using JWX library serialization:
```json
{
  "web": "serialized_jwk_key_json_from_jwx_library",
  "android": "serialized_jwk_key_json_from_jwx_library",
  "ios": "serialized_jwk_key_json_from_jwx_library"
}
```

Each device key is serialized using `json.Marshal(jwk.Key)` from the lestrrat-go/jwx/v3/jwk library and deserialized using `jwk.ParseKey()`. This ensures proper JWK format compliance and compatibility with JWT signing operations.

### Schema Migration
The system automatically migrates from the old `user_session_keys` table to the new consolidated format:

**Old Schema (Deprecated):**
```sql
-- This table is automatically migrated and removed
user_session_keys:
- user_id, key_id, device_type, key_data (separate rows per device)
```

**New Schema (Current):**
```sql
-- Consolidated storage with all device keys per user
user_keysets:
- user_id (PRIMARY KEY), key_data (JSONB with all device keys)
```

## Key Features

### Session-Based Key Management (Recommended)
- **Single Device Login**: Only one active session per device type per user
- **Automatic Invalidation**: New login invalidates existing sessions for same device type
- **Device Isolation**: Keys are isolated by device type (web, android, ios, etc.)
- **Cross-Device Support**: Users can be logged in from different device types simultaneously
- **Selective Logout**: Can invalidate specific sessions without affecting other device types
- **Automatic Cleanup**: Keys are removed when users log out or when new sessions are created



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
   - Keys are removed from the consolidated keyset

4. **Token Refresh**:
   - Verify refresh token using existing session key
   - Generate new access token with same key ID

5. **Single Device Enforcement**:
   - Only one active session per device type (web, android, ios, etc.)
   - New login from same device type invalidates previous session
   - Different device types can coexist (user can be logged in on web + android simultaneously)

