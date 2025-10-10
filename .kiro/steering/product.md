# Product Overview

## JWT Authentication CLI with JWK Support

A command-line application for JWT authentication using JSON Web Key Sets (JWKS) with PostgreSQL persistence.

### Core Features

- **Single Device Login**: Only one active session per device type per user
- **Session-Based Authentication**: Each login creates unique keys tied to device/session
- **JWT Token Generation**: Create access and refresh token pairs with session-specific keys
- **Device Isolation**: Separate keys for web, mobile, and other device types
- **Automatic Invalidation**: New login invalidates existing sessions for same device type
- **Selective Logout**: Invalidate specific sessions without affecting other device types
- **JWK Management**: Generate and manage JSON Web Key Sets with database persistence
- **Token Verification**: Validate JWT tokens using stored public keys
- **Multi-User Support**: Per-user session key management
- **Interactive CLI**: Menu-driven interface for all operations (legacy support)

### Key Benefits

- **Enhanced Security**: Each session has unique keys, limiting blast radius of compromised tokens
- **Device Management**: Users can manage active sessions across different devices
- **Scalability**: Keys created on-demand, not pre-allocated
- **Token Persistence**: Tokens remain valid across application restarts
- **RSA-based Signing**: Industry-standard cryptographic security
- **Flexibility**: Support for both session-based and legacy key management
- **Database Integration**: PostgreSQL storage for session keys and user authentication data

### Primary Use Cases

1. **REST API Authentication**: Session-based JWT authentication for web and mobile apps
2. **Multi-Device Login**: Users can be authenticated on multiple devices simultaneously
3. **Microservices Security**: Distributed key management for service-to-service authentication
4. **Development and Testing**: JWT-based authentication system development and testing
5. **Token Generation**: API testing and integration with proper session management
6. **Educational Tool**: Understanding modern JWT/JWK workflows and session management