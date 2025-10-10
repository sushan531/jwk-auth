# Project Structure

## Directory Organization

```
jwk-auth/
├── cmd/                    # CLI commands and entry points
│   ├── root.go            # Root command definition
│   └── menu.go            # Interactive menu command
├── internal/              # Private application code
│   ├── config/            # Configuration management
│   │   └── config.go      # Environment variable loading
│   ├── database/          # Database connection and setup
│   │   └── postgres.go    # PostgreSQL connection logic
│   ├── manager/           # Business logic managers
│   │   ├── jwk.go         # JWK set management
│   │   └── jwt.go         # JWT token operations
│   └── repository/        # Data access layer
│       └── userauth.go    # User authentication repository
├── model/                 # Data models and structures
│   ├── token.go           # Token-related models
│   ├── user.go            # User model
│   └── userkeyset.go      # User keyset model
├── service/               # Service layer
│   └── auth.go            # Authentication service
├── main.go                # Application entry point
├── go.mod                 # Go module definition
├── go.sum                 # Dependency checksums
└── DATABASE.md            # Database setup documentation
```

## Architecture Patterns

### Layered Architecture
- **cmd/**: CLI interface and command handling
- **service/**: Business logic and orchestration
- **internal/manager/**: Core business operations
- **internal/repository/**: Data persistence layer
- **model/**: Data structures and domain objects

### Dependency Injection
- Repositories are injected into managers
- Managers are injected into services
- Services are used by CLI commands

### Interface-Based Design
- All managers and repositories implement interfaces
- Enables testing and modularity
- Clear separation of concerns

## Code Organization Rules

### Package Structure
- `internal/` contains private application code
- `model/` contains shared data structures
- `service/` contains business logic orchestration
- `cmd/` contains CLI-specific code

### Naming Conventions
- Interfaces use descriptive names (e.g., `AuthService`, `JwkManager`)
- Implementations use lowercase with package prefix (e.g., `authService`)
- Models use PascalCase for public fields
- Database fields use snake_case

### Error Handling
- Use wrapped errors with context: `fmt.Errorf("operation failed: %w", err)`
- Repository layer returns domain-specific errors
- Service layer handles and transforms errors appropriately

### Database Integration
- Repository pattern for data access
- Interface-based repository design
- Session-based key storage with device type tracking

- Database schema managed through migration-like table creation
- Environment-based configuration with sensible defaults

### Session Management Architecture
- **Consolidated Key Storage**: All user device keys stored in single database row per user
- **Single Device Login**: Only one active session per device type per user
- **Database-First Storage**: Database is primary storage, memory is cache for performance
- **JWX Library Integration**: Uses lestrrat-go/jwx/v3/jwk for proper JWK serialization
- **Device Isolation**: Keys are categorized by device type within consolidated keyset
- **Automatic Invalidation**: New login invalidates existing sessions for same device type
- **Efficient Lookups**: Single query retrieves all user keys, reverse lookup cache for key-to-user mapping
- **Persistent Storage**: All keys stored in PostgreSQL JSONB format for durability
- **Memory Caching**: Entire user keysets cached for performance, with LRU eviction
- **Cross-Device Support**: Different device types coexist in same keyset simultaneously

### Consolidated Keyset Model
```go
type UserKeyset struct {
    UserID   int                 `json:"user_id"`
    KeyData  map[string]string   `json:"key_data"` // deviceType -> serialized jwk.Key JSON
    Created  time.Time           `json:"created"`
    Updated  time.Time           `json:"updated"`
}

// Helper methods for JWK operations
func (uk *UserKeyset) GetDeviceKey(deviceType string) (jwk.Key, error)
func (uk *UserKeyset) SetDeviceKey(deviceType string, key jwk.Key) error
```