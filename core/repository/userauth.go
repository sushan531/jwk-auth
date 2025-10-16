package repository

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"

	"github.com/google/uuid"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/sushan531/auth-sqlc/generated"
)

// UserKeyset represents a consolidated key storage for a user
// containing all device keys in a single JWKS JSON field
type UserKeyset struct {
	UserID        uuid.UUID `json:"user_id"`
	KeyData       string    `json:"key_data"`       // Encrypted JWKS JSON string
	EncryptionKey string    `json:"encryption_key"` // Fernet encryption key for this user
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
	SaveUserKeyset(userID uuid.UUID, keyData string, encryptionKey string) error
	GetUserKeyset(userID uuid.UUID) (*UserKeyset, error)
	DeleteUserKeyset(userID uuid.UUID) error
	GetAllUserKeysets() ([]*UserKeyset, error)
}

type userAuthRepository struct {
	db *generated.Queries
}

func NewUserAuthRepository(db *generated.Queries) *userAuthRepository {
	return &userAuthRepository{db: db}
}

// SaveUserKeyset saves or updates a user's consolidated keyset with encryption
func (r *userAuthRepository) SaveUserKeyset(userID uuid.UUID, keyData string, encryptionKey string) error {
	_, err := r.db.ConditionalUpdateAuth(context.Background(), generated.ConditionalUpdateAuthParams{
		Column3:       1,
		KeysetData:    sql.NullString{String: keyData, Valid: true},
		Column5:       1,
		EncryptionKey: sql.NullString{String: encryptionKey, Valid: true},
		UserProfileID: userID,
	})
	if err != nil {
		return fmt.Errorf("failed to save user keyset: %w", err)
	}

	return nil
}

// GetUserKeyset retrieves a user's consolidated keyset
func (r *userAuthRepository) GetUserKeyset(userID uuid.UUID) (*UserKeyset, error) {
	userKeyset, err := r.db.GetUserKeySet(context.Background(), userID)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("no keyset found for user %d", userID)
		}
		return nil, fmt.Errorf("failed to get user keyset: %w", err)
	}

	return &UserKeyset{
		EncryptionKey: userKeyset.EncryptionKey.String,
		KeyData:       userKeyset.KeysetData.String,
	}, nil
}

// DeleteUserKeyset removes a user's consolidated keyset
func (r *userAuthRepository) DeleteUserKeyset(userID uuid.UUID) error {
	_, err := r.db.DeleteUserKeySet(context.Background(), userID)
	if err != nil {
		return fmt.Errorf("failed to delete user keyset: %w", err)
	}

	return nil
}

// GetAllUserKeysets retrieves all user keysets for system-wide operations
func (r *userAuthRepository) GetAllUserKeysets() ([]*UserKeyset, error) {
	rows, err := r.db.GetAllUserKeySet(context.Background())
	if err != nil {
		return nil, fmt.Errorf("failed to query all user keysets: %w", err)
	}
	keysets := make([]*UserKeyset, 0, len(rows))
	for _, row := range rows {
		keyset := &UserKeyset{
			UserID:        row.UserProfileID,
			EncryptionKey: row.EncryptionKey.String,
			KeyData:       row.KeysetData.String,
		}
		keysets = append(keysets, keyset)
	}
	return keysets, nil
}
