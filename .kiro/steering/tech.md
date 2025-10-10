# Technology Stack

## Core Technologies

- **Language**: Go 1.25.1
- **Database**: PostgreSQL 15+
- **CLI Framework**: Cobra (spf13/cobra)
- **JWT Library**: lestrrat-go/jwx/v3
- **Database Driver**: lib/pq (PostgreSQL driver)
- **UUID Generation**: google/uuid

## Key Dependencies

- `github.com/lestrrat-go/jwx/v3` - JWT/JWK handling and cryptographic operations
- `github.com/spf13/cobra` - CLI command structure and argument parsing
- `github.com/lib/pq` - PostgreSQL database connectivity
- `github.com/google/uuid` - UUID generation for database records

## Build & Development Commands

### Basic Operations
```bash
# Run the application
go run main.go menu

# Build the application
go build -o jwk-auth main.go

# Run with custom database settings
export DB_HOST=localhost
export DB_PORT=5432
export DB_USER=myuser
export DB_PASSWORD=mypassword
export DB_NAME=mydb
go run main.go menu
```

### Database Setup
```bash
# Start PostgreSQL with Docker
docker-compose up -d postgres

# Manual PostgreSQL container
docker run -d \
  --name jwk-postgres \
  -e POSTGRES_USER=myuser \
  -e POSTGRES_PASSWORD=mypassword \
  -e POSTGRES_DB=mydb \
  -p 5432:5432 \
  postgres:15
```

### Go Module Management
```bash
# Download dependencies
go mod download

# Update dependencies
go mod tidy

# Vendor dependencies (if needed)
go mod vendor
```

## Environment Configuration

The application uses environment variables for database configuration:
- `DB_HOST` (default: localhost)
- `DB_PORT` (default: 5432)
- `DB_USER` (default: myuser)
- `DB_PASSWORD` (default: mypassword)
- `DB_NAME` (default: mydb)
- `DB_SSLMODE` (default: disable)