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
│   └── userauth.go        # User authentication model
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
- Database schema managed through migration-like table creation
- Environment-based configuration with sensible defaults