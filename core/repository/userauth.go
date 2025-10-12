package repository

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwk"
)

// UserKeyset represents a consolidated key storage for a user
// containing all device keys in a single JWKS JSON field
type UserKeyset struct {
	UserID        int       `json:"user_id"`
	KeyData       string    `json:"key_data"`       // Encrypted JWKS JSON string
	EncryptionKey string    `json:"encryption_key"` // Fernet encryption key for this user
	Created       time.Time `json:"created"`
	Updated       time.Time `json:"updated"`
}

// GetJWKS deserializes the JWKS from the stored encrypted JSON string
// Returns an empty JWKS if KeyData is empty
// Note: This method requires an EncryptionManager to decrypt the data
func (uk *UserKeyset) GetJWKS() (jwk.Set, error) {
	if uk.KeyData == "" {
		return jwk.NewSet(), nil
	}
	// This method now expects decrypted data to be passed in
	// The decryption should be handled by the calling code
	return jwk.Parse([]byte(uk.KeyData))
}

// SetJWKS serializes the JWKS to JSON and stores it in KeyData
// Note: This method now expects the calling code to handle encryption
func (uk *UserKeyset) SetJWKS(keySet jwk.Set) error {
	keyBytes, err := json.Marshal(keySet)
	if err != nil {
		return fmt.Errorf("failed to marshal JWKS: %w", err)
	}
	uk.KeyData = string(keyBytes)
	uk.Updated = time.Now()
	return nil
}

// GetDeviceKey retrieves a JWK key for a specific device type from the JWKS
// Finds the key by matching the "use" claim within the JWKS
func (uk *UserKeyset) GetDeviceKey(deviceType string) (jwk.Key, error) {
	keySet, err := uk.GetJWKS()
	if err != nil {
		return nil, err
	}

	// Find key with matching "use" claim
	for i := 0; i < keySet.Len(); i++ {
		key, _ := keySet.Key(i)
		var use string
		if err := key.Get("use", &use); err == nil && use == deviceType {
			return key, nil
		}
	}
	return nil, fmt.Errorf("no key found for device type: %s", deviceType)
}

// SetDeviceKey adds or replaces a JWK key for a specific device type in the JWKS
// Removes any existing key for the device type and adds the new key with "use" claim
func (uk *UserKeyset) SetDeviceKey(deviceType string, key jwk.Key) error {
	keySet, err := uk.GetJWKS()
	if err != nil {
		return err
	}

	// Remove existing key for this device type first
	uk.removeDeviceKeyFromSet(keySet, deviceType)

	// Set the "use" claim to identify device type
	if err := key.Set("use", deviceType); err != nil {
		return fmt.Errorf("failed to set use claim: %w", err)
	}

	// Add key to the set
	if err := keySet.AddKey(key); err != nil {
		return fmt.Errorf("failed to add key to JWKS: %w", err)
	}

	return uk.SetJWKS(keySet)
}

// RemoveDeviceKey removes a key for a specific device type from the JWKS
func (uk *UserKeyset) RemoveDeviceKey(deviceType string) error {
	keySet, err := uk.GetJWKS()
	if err != nil {
		return err
	}

	// Remove key with matching "use" claim
	uk.removeDeviceKeyFromSet(keySet, deviceType)

	return uk.SetJWKS(keySet)
}

// removeDeviceKeyFromSet is a helper method to remove a key from a JWKS by device type
func (uk *UserKeyset) removeDeviceKeyFromSet(keySet jwk.Set, deviceType string) {
	for i := 0; i < keySet.Len(); i++ {
		key, _ := keySet.Key(i)
		var use string
		if err := key.Get("use", &use); err == nil && use == deviceType {
			keySet.RemoveKey(key)
			break
		}
	}
}

// HasDeviceKey checks if a key exists for a specific device type in the JWKS
func (uk *UserKeyset) HasDeviceKey(deviceType string) bool {
	_, err := uk.GetDeviceKey(deviceType)
	return err == nil
}

// GetDeviceTypes returns all device types that have keys in the JWKS
func (uk *UserKeyset) GetDeviceTypes() []string {
	keySet, err := uk.GetJWKS()
	if err != nil {
		return []string{}
	}

	var deviceTypes []string
	for i := 0; i < keySet.Len(); i++ {
		key, _ := keySet.Key(i)
		var use string
		if err := key.Get("use", &use); err == nil {
			deviceTypes = append(deviceTypes, use)
		}
	}
	return deviceTypes
}

// IsEmpty returns true if the JWKS has no keys
func (uk *UserKeyset) IsEmpty() bool {
	keySet, err := uk.GetJWKS()
	if err != nil {
		return true
	}
	return keySet.Len() == 0
}

type UserAuthRepository interface {
	// Keyset management (consolidated approach)
	SaveUserKeyset(userID int, keyData string, encryptionKey string) error
	GetUserKeyset(userID int) (*UserKeyset, error)
	DeleteUserKeyset(userID int) error
	GetAllUserKeysets() ([]*UserKeyset, error)

	// Device key operations within keysets
	UpdateDeviceKeyInKeyset(userID int, deviceType string, keyID string, keyData string) error
	RemoveDeviceKeyFromKeyset(userID int, deviceType string) error
	FindKeysetByKeyID(keyID string) (*UserKeyset, error)
}

type userAuthRepository struct {
	db *sql.DB
}

func NewUserAuthRepository(db *sql.DB) UserAuthRepository {
	return &userAuthRepository{db: db}
}

// SaveUserKeyset saves or updates a user's consolidated keyset with encryption
func (r *userAuthRepository) SaveUserKeyset(userID int, keyData string, encryptionKey string) error {
	query := `
		INSERT INTO user_keysets (user_id, key_data, encryption_key, created, updated)
		VALUES ($1, $2, $3, $4, $5)
		ON CONFLICT (user_id) 
		DO UPDATE SET 
			key_data = EXCLUDED.key_data,
			encryption_key = EXCLUDED.encryption_key,
			updated = EXCLUDED.updated
	`

	now := time.Now()
	_, err := r.db.Exec(query, userID, keyData, encryptionKey, now, now)
	if err != nil {
		return fmt.Errorf("failed to save user keyset: %w", err)
	}

	return nil
}

// GetUserKeyset retrieves a user's consolidated keyset
func (r *userAuthRepository) GetUserKeyset(userID int) (*UserKeyset, error) {
	query := `
		SELECT user_id, key_data, encryption_key, created, updated
		FROM user_keysets
		WHERE user_id = $1
	`

	var uk UserKeyset

	err := r.db.QueryRow(query, userID).Scan(
		&uk.UserID,
		&uk.KeyData,
		&uk.EncryptionKey,
		&uk.Created,
		&uk.Updated,
	)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("no keyset found for user %d", userID)
		}
		return nil, fmt.Errorf("failed to get user keyset: %w", err)
	}

	return &uk, nil
}

// DeleteUserKeyset removes a user's consolidated keyset
func (r *userAuthRepository) DeleteUserKeyset(userID int) error {
	query := `DELETE FROM user_keysets WHERE user_id = $1`

	result, err := r.db.Exec(query, userID)
	if err != nil {
		return fmt.Errorf("failed to delete user keyset: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rowsAffected == 0 {
		return fmt.Errorf("no keyset found for user %d", userID)
	}

	return nil
}

// GetAllUserKeysets retrieves all user keysets for system-wide operations
func (r *userAuthRepository) GetAllUserKeysets() ([]*UserKeyset, error) {
	query := `
		SELECT user_id, key_data, encryption_key, created, updated
		FROM user_keysets
		ORDER BY updated DESC
	`

	rows, err := r.db.Query(query)
	if err != nil {
		return nil, fmt.Errorf("failed to query all user keysets: %w", err)
	}
	defer rows.Close()

	var keysets []*UserKeyset
	for rows.Next() {
		var uk UserKeyset

		err := rows.Scan(
			&uk.UserID,
			&uk.KeyData,
			&uk.EncryptionKey,
			&uk.Created,
			&uk.Updated,
		)
		if err != nil {
			continue // Skip invalid rows
		}

		keysets = append(keysets, &uk)
	}

	return keysets, nil
}

// UpdateDeviceKeyInKeyset updates a specific device key within a user's JWKS
// Note: This method is deprecated with encryption. Use JWK manager methods instead.
func (r *userAuthRepository) UpdateDeviceKeyInKeyset(userID int, deviceType string, keyID string, keyData string) error {
	return fmt.Errorf("UpdateDeviceKeyInKeyset is deprecated with encryption - use JWK manager methods instead")
}

// RemoveDeviceKeyFromKeyset removes a specific device key from a user's JWKS
// Note: This method is deprecated with encryption. Use JWK manager methods instead.
func (r *userAuthRepository) RemoveDeviceKeyFromKeyset(userID int, deviceType string) error {
	return fmt.Errorf("RemoveDeviceKeyFromKeyset is deprecated with encryption - use JWK manager methods instead")
}

// FindKeysetByKeyID searches through all user keysets to find the one containing the specified key ID
// Note: This method is deprecated with encryption. Use JWK manager methods instead.
func (r *userAuthRepository) FindKeysetByKeyID(keyID string) (*UserKeyset, error) {
	return nil, fmt.Errorf("FindKeysetByKeyID is deprecated with encryption - use JWK manager methods instead")
}
