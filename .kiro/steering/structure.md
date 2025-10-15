---
inclusion: always
---

# Project Structure

## Directory Organization

```
jwk-auth/
├── cmd/                    # CLI commands and interactive menus
│   ├── root.go            # Root cobra command setup
│   └── menu.go            # Interactive menu implementation
├── core/                  # Core business logic (no external dependencies)
│   ├── config/            # Configuration management
│   ├── database/          # Database connection and schema
│   ├── manager/           # Business logic managers
│   │   ├── encryption.go  # Key encryption/decryption
│   │   ├── jwk.go         # JWK management and session keys
│   │   └── jwt.go         # JWT token operations
│   └── repository/        # Data access layer
├── service/               # Application services (orchestration layer)
└── examples/              # Usage examples and documentation
```

## Architectural Layers

### 1. CMD Layer (`cmd/`)
- **Purpose**: CLI interface and user interaction
- **Pattern**: Cobra command structure
- **Responsibilities**: Input validation, menu flow, output formatting

### 2. Service Layer (`service/`)
- **Purpose**: Application orchestration and business workflows
- **Pattern**: Interface-based services with dependency injection
- **Responsibilities**: Coordinate between managers, handle complex workflows

### 3. Core Layer (`core/`)
- **Purpose**: Domain logic and data management
- **Managers**: Business logic components (JWK, JWT, encryption)
- **Repository**: Data access abstraction
- **Config**: Environment and configuration management
- **Database**: Connection management and schema

## Naming Conventions

### Files & Packages
- **Lowercase**: All package names and file names
- **Descriptive**: Clear purpose indication (`userauth.go`, `postgres.go`)
- **Single responsibility**: One main concept per file

### Interfaces & Implementations
- **Interfaces**: PascalCase with descriptive names (`JwkManager`, `AuthService`)
- **Implementations**: Lowercase struct with interface suffix (`authService`, `jwkManager`)
- **Constructors**: `New` prefix (`NewAuthService`, `NewJwkManager`)

### Database
- **Tables**: Snake_case (`user_keysets`)
- **Columns**: Snake_case with clear purpose (`encryption_key`, `created`)
- **Indexes**: Descriptive with `idx_` prefix (`idx_user_keysets_updated`)

## Key Design Patterns

- **Dependency Injection**: Services receive dependencies via constructors
- **Repository Pattern**: Data access abstraction in `core/repository`
- **Manager Pattern**: Business logic encapsulation in `core/manager`
- **Configuration Pattern**: Environment-based config with defaults