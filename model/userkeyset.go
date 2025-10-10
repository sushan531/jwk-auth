package model

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwk"
)

// UserKeyset represents a consolidated key storage for a user
// containing all device keys in a single JSON field
type UserKeyset struct {
	UserID  int               `json:"user_id"`
	KeyData map[string]string `json:"key_data"` // deviceType -> serialized jwk.Key JSON
	Created time.Time         `json:"created"`
	Updated time.Time         `json:"updated"`
}

// GetDeviceKey retrieves and parses a JWK key for a specific device type
// Returns the parsed jwk.Key or an error if the device type doesn't exist
func (uk *UserKeyset) GetDeviceKey(deviceType string) (jwk.Key, error) {
	keyData, exists := uk.KeyData[deviceType]
	if !exists {
		return nil, fmt.Errorf("no key found for device type: %s", deviceType)
	}

	// Parse the serialized JWK key using jwx library
	key, err := jwk.ParseKey([]byte(keyData))
	if err != nil {
		return nil, fmt.Errorf("failed to parse JWK key for device type %s: %w", deviceType, err)
	}

	return key, nil
}

// SetDeviceKey adds or updates a JWK key for a specific device type
// The key is serialized using json.Marshal from the jwx library
func (uk *UserKeyset) SetDeviceKey(deviceType string, key jwk.Key) error {
	// Serialize the JWK key using json.Marshal
	keyBytes, err := json.Marshal(key)
	if err != nil {
		return fmt.Errorf("failed to marshal JWK key for device type %s: %w", deviceType, err)
	}

	// Initialize KeyData map if it doesn't exist
	if uk.KeyData == nil {
		uk.KeyData = make(map[string]string)
	}

	// Store the serialized key data
	uk.KeyData[deviceType] = string(keyBytes)
	uk.Updated = time.Now()

	return nil
}

// RemoveDeviceKey removes a key for a specific device type
func (uk *UserKeyset) RemoveDeviceKey(deviceType string) {
	if uk.KeyData != nil {
		delete(uk.KeyData, deviceType)
		uk.Updated = time.Now()
	}
}

// HasDeviceKey checks if a key exists for a specific device type
func (uk *UserKeyset) HasDeviceKey(deviceType string) bool {
	if uk.KeyData == nil {
		return false
	}
	_, exists := uk.KeyData[deviceType]
	return exists
}

// GetDeviceTypes returns all device types that have keys in this keyset
func (uk *UserKeyset) GetDeviceTypes() []string {
	if uk.KeyData == nil {
		return []string{}
	}

	deviceTypes := make([]string, 0, len(uk.KeyData))
	for deviceType := range uk.KeyData {
		deviceTypes = append(deviceTypes, deviceType)
	}
	return deviceTypes
}

// IsEmpty returns true if the keyset has no device keys
func (uk *UserKeyset) IsEmpty() bool {
	return uk.KeyData == nil || len(uk.KeyData) == 0
}
