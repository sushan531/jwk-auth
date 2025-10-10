# Single Device Login System

## Overview

The JWT authentication system now implements **single device login** - only one active session per device type per user.

## How It Works

### Before Login
```
User 1 Sessions: []
```

### First Web Login
```
User 1 Sessions: [web-1-1760081204]
```

### Second Web Login (Same Device Type)
```
User 1 Sessions: [web-1-1760081251]  // Previous web session invalidated
```

### Android Login (Different Device Type)
```
User 1 Sessions: [web-1-1760081251, android-1-1760081300]  // Both coexist
```

### Third Web Login (Same Device Type Again)
```
User 1 Sessions: [android-1-1760081300, web-1-1760081350]  // Old web invalidated, android remains
```

## Key Behavior

1. **Single Session Per Device Type**: Only one active session per device type (web, android, ios, etc.)
2. **Automatic Invalidation**: New login automatically invalidates existing sessions for the same device type
3. **Cross-Device Support**: Different device types can coexist (user can be logged in on web + android simultaneously)
4. **Token Invalidation**: When a session is invalidated, all tokens signed with that session's key become invalid

## Implementation Details

### Database Level
- `DeleteUserSessionsByDeviceType()` removes existing sessions for device type before creating new one
- Returns deleted sessions for memory cleanup

### Memory Level
- Removed invalidated session keys from in-memory cache
- Updates user-to-keys mapping

### Token Level
- Old tokens become invalid immediately when session is invalidated
- New tokens are signed with the new session key

## Usage Example

```go
// User logs in from web browser
webKeyID, err := jwkManager.CreateSessionKey(userID, "web")
// Any existing "web" sessions are automatically invalidated

// User logs in from Android app  
androidKeyID, err := jwkManager.CreateSessionKey(userID, "android")
// Web session remains active, only one android session exists

// User logs in from web browser again
newWebKeyID, err := jwkManager.CreateSessionKey(userID, "web")
// Previous web session invalidated, android session remains active
```

## Benefits

1. **Security**: Prevents session hijacking across multiple instances of same device type
2. **User Experience**: Users don't get logged out when switching between different device types
3. **Resource Management**: Prevents accumulation of abandoned sessions
4. **Clear Behavior**: Predictable session management for developers and users## Stor
age Architecture

### Database-First Approach
- **Primary Storage**: PostgreSQL database stores all session keys
- **Memory Cache**: In-memory cache for performance optimization
- **Persistence**: Keys survive application restarts
- **Consistency**: Database is always the source of truth

### Storage Flow
```
CreateSessionKey() → Save to Database → Cache in Memory
GetPrivateKeyByID() → Check Cache → Fallback to Database → Update Cache
DeleteSessionKey() → Delete from Database → Remove from Cache
```

### Key Benefits
- **Durability**: Keys persist across application restarts
- **Performance**: Memory cache provides fast access
- **Reliability**: Database fallback ensures keys are never lost
- **Consistency**: Single source of truth prevents data conflicts

## Updated Architecture Summary

✅ **Database-first storage with memory caching**
✅ **Single device login per device type**  
✅ **Cross-device session support**
✅ **Persistent key storage**
✅ **Automatic session invalidation**
✅ **Performance optimization through caching**