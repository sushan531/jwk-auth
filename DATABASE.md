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

The application creates a `user_auth` table with the following structure:

```sql
CREATE TABLE user_auth (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id INTEGER NOT NULL UNIQUE,
    key_set TEXT NOT NULL,
    created TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);
```

## Key Features

- **Persistent JWK Sets**: Key sets are stored in PostgreSQL and loaded on startup
- **Token Continuity**: Tokens issued in previous sessions remain valid
- **Key Rotation**: Generate new key sets while maintaining database persistence
- **Multi-User Support**: Each user can have their own key set (user_id column)

## Usage Flow

1. **First Run**: Creates new JWK set and saves to database
2. **Subsequent Runs**: Loads existing JWK set from database
3. **Token Verification**: Uses persisted keys to verify tokens from previous sessions
4. **Key Regeneration**: Option to create new key sets (invalidates old tokens)