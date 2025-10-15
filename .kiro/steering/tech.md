---
inclusion: always
---

# Technology Stack

## Language & Runtime
- **Go 1.25.1** - Primary language
- **Module**: `github.com/sushan531/jwk-auth`

## Key Dependencies
- **CLI Framework**: `github.com/spf13/cobra` - Command-line interface and menu system
- **JWT/JWK**: `github.com/lestrrat-go/jwx/v3` - JWT token generation and validation
- **Database**: `github.com/lib/pq` - PostgreSQL driver
- **Encryption**: `github.com/fernet/fernet-go` - Symmetric encryption for key storage

## Database
- **PostgreSQL** - Primary data store for user keysets
- **Schema**: Single `user_keysets` table with encrypted key data
- **Extensions**: Uses `uuid-ossp` for UUID generation

## Configuration
- **Environment-based**: Uses `.env` files for configuration
- **Defaults**: Sensible defaults for all settings
- **Duration parsing**: Supports Go duration format (15m, 7d, etc.)

## Common Commands

### Build & Run
```bash
go build -o jwk-auth
./jwk-auth menu
```

### Development
```bash
go run main.go menu
go mod tidy
go mod download
```

### Testing
```bash
go test ./...
go test -v ./core/...
```

## Architecture Patterns
- **Layered Architecture**: cmd → service → core (manager/repository) → database
- **Dependency Injection**: Services receive dependencies via constructors
- **Interface-based**: Core components use interfaces for testability
- **Configuration Pattern**: Centralized config loading with environment overrides