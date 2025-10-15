---
inclusion: always
---

# Product Overview

**jwk-auth** is a session-based JWT authentication CLI application that implements JSON Web Key Sets (JWKS) for secure token management.

## Core Features

- **Session-based Authentication**: Creates unique RSA key pairs per user session/device
- **Multi-device Support**: Manages separate sessions for web, Android, and iOS devices
- **Flexible JWT Claims**: Supports custom claims in tokens with type-safe parsing
- **Token Management**: Access/refresh token pairs with configurable expiration
- **Interactive CLI**: Menu-driven interface for authentication operations
- **Database Persistence**: PostgreSQL storage for user keysets and session management

## Key Operations

- Login (create session + generate tokens)
- Logout (single session or all devices)
- Token verification and refresh
- Session management and monitoring
- Public key retrieval for token validation

The system is designed for scenarios requiring per-session key isolation and secure token management across multiple devices.