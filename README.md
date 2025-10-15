# jwk-auth

A session-based JWT authentication CLI application that implements JSON Web Key Sets (JWKS) for secure token management.

## Features

- **Session-based Authentication**: Creates unique RSA key pairs per user session/device
- **Multi-device Support**: Manages separate sessions for web, Android, and iOS devices
- **Flexible JWT Claims**: Supports custom claims in tokens with type-safe parsing
- **Token Management**: Access/refresh token pairs with configurable expiration
- **Interactive CLI**: Menu-driven interface for authentication operations
- **Database Persistence**: PostgreSQL storage for encrypted user keysets

## Prerequisites

- Go 1.25.1 or higher
- PostgreSQL database
- Environment variables configured (see Configuration section)

## Installation

```bash
# Clone the repository
git clone https://github.com/sushan531/jwk-auth.git
cd jwk-auth

# Install dependencies
go mod download

# Build the application
go build -o jwk-auth
```

## Configuration

Create a `.env` file in the project root with the following variables:

```bash
# Database Configuration
DB_HOST=localhost
DB_PORT=5432
DB_USER=myuser
DB_PASSWORD=mypassword
DB_NAME=mydb
DB_SSLMODE=disable

# JWT Configuration
JWT_ACCESS_TOKEN_DURATION=15m      # Access token duration (15m, 1h, 30s)
JWT_REFRESH_TOKEN_DURATION=168h    # Refresh token duration (7d, 168h)
JWT_RSA_KEY_SIZE=2048              # RSA key size in bits (2048, 3072, 4096)
```

## Usage

### Run the Interactive Menu

```bash
./jwk-auth menu
```

Or during development:

```bash
go run main.go menu
```

### Available Operations

1. **Login** - Create a session key and generate access/refresh tokens
2. **Logout** - Delete a specific session key
3. **View Active Sessions** - List all active sessions for a user
4. **Verify Access Token** - Validate and decode an access token
5. **Refresh Tokens** - Generate new tokens using a refresh token
6. **Logout from All Devices** - Remove all session keys for a user
7. **Get User Public Keys** - Retrieve public keys for token verification

## Architecture

The project follows a layered architecture:

```
cmd/          → CLI commands and interactive menus
service/      → Application orchestration layer
core/
  ├── manager/     → Business logic (JWK, JWT, encryption)
  ├── repository/  → Data access layer
  ├── config/      → Configuration management
  └── database/    → Database connection and schema
```

## How It Works

1. **Session Creation**: When a user logs in, a unique RSA key pair is generated for that session/device
2. **Token Generation**: Access and refresh tokens are signed with the session's private key
3. **Token Verification**: Tokens are verified using the corresponding public key
4. **Key Storage**: Private keys are encrypted using Fernet and stored in PostgreSQL
5. **Session Management**: Each device maintains its own session key, enabling per-device logout

## Development

### Run Tests

```bash
go test ./...
go test -v ./core/...
```

### Update Dependencies

```bash
go mod tidy
```

## Key Dependencies

- **CLI Framework**: [Cobra](https://github.com/spf13/cobra) - Command-line interface
- **JWT/JWK**: [jwx](https://github.com/lestrrat-go/jwx) - JWT token operations
- **Database**: [pq](https://github.com/lib/pq) - PostgreSQL driver
- **Encryption**: [fernet-go](https://github.com/fernet/fernet-go) - Key encryption

## Security Features

- RSA-2048 (configurable) key pairs for token signing
- Fernet symmetric encryption for private key storage
- Per-session key isolation
- Configurable token expiration
- Token type validation (access vs refresh)

## License

[Add your license here]

## Contributing

[Add contribution guidelines here]
