package repository

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/sushan531/jwk-auth/model"
)

type UserAuthRepository interface {
	// Keyset management (consolidated approach)
	SaveUserKeyset(userID int, keyData string) error
	GetUserKeyset(userID int) (*model.UserKeyset, error)
	DeleteUserKeyset(userID int) error
	GetAllUserKeysets() ([]*model.UserKeyset, error)

	// Device key operations within keysets
	UpdateDeviceKeyInKeyset(userID int, deviceType string, keyID string, keyData string) error
	RemoveDeviceKeyFromKeyset(userID int, deviceType string) error
	FindKeysetByKeyID(keyID string) (*model.UserKeyset, error)
}

type userAuthRepository struct {
	db *sql.DB
}

func NewUserAuthRepository(db *sql.DB) UserAuthRepository {
	return &userAuthRepository{db: db}
}

// SaveUserKeyset saves or updates a user's consolidated keyset
func (r *userAuthRepository) SaveUserKeyset(userID int, keyData string) error {
	query := `
		INSERT INTO user_keysets (user_id, key_data, created, updated)
		VALUES ($1, $2, $3, $4)
		ON CONFLICT (user_id) 
		DO UPDATE SET 
			key_data = EXCLUDED.key_data,
			updated = EXCLUDED.updated
	`

	now := time.Now()
	_, err := r.db.Exec(query, userID, keyData, now, now)
	if err != nil {
		return fmt.Errorf("failed to save user keyset: %w", err)
	}

	return nil
}

// GetUserKeyset retrieves a user's consolidated keyset
func (r *userAuthRepository) GetUserKeyset(userID int) (*model.UserKeyset, error) {
	query := `
		SELECT user_id, key_data, created, updated
		FROM user_keysets
		WHERE user_id = $1
	`

	var uk model.UserKeyset
	var keyDataJSON string

	err := r.db.QueryRow(query, userID).Scan(
		&uk.UserID,
		&keyDataJSON,
		&uk.Created,
		&uk.Updated,
	)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("no keyset found for user %d", userID)
		}
		return nil, fmt.Errorf("failed to get user keyset: %w", err)
	}

	// Parse the JSON key data
	err = json.Unmarshal([]byte(keyDataJSON), &uk.KeyData)
	if err != nil {
		return nil, fmt.Errorf("failed to parse keyset JSON for user %d: %w", userID, err)
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
func (r *userAuthRepository) GetAllUserKeysets() ([]*model.UserKeyset, error) {
	query := `
		SELECT user_id, key_data, created, updated
		FROM user_keysets
		ORDER BY updated DESC
	`

	rows, err := r.db.Query(query)
	if err != nil {
		return nil, fmt.Errorf("failed to query all user keysets: %w", err)
	}
	defer rows.Close()

	var keysets []*model.UserKeyset
	for rows.Next() {
		var uk model.UserKeyset
		var keyDataJSON string

		err := rows.Scan(
			&uk.UserID,
			&keyDataJSON,
			&uk.Created,
			&uk.Updated,
		)
		if err != nil {
			continue // Skip invalid rows
		}

		// Parse the JSON key data
		err = json.Unmarshal([]byte(keyDataJSON), &uk.KeyData)
		if err != nil {
			continue // Skip rows with invalid JSON
		}

		keysets = append(keysets, &uk)
	}

	return keysets, nil
}

// UpdateDeviceKeyInKeyset updates a specific device key within a user's keyset
// This method loads the keyset, updates the specific device key, and saves it back
func (r *userAuthRepository) UpdateDeviceKeyInKeyset(userID int, deviceType string, keyID string, keyData string) error {
	// Get the current keyset for the user
	keyset, err := r.GetUserKeyset(userID)
	if err != nil {
		// If no keyset exists, create a new one
		if err.Error() == fmt.Sprintf("no keyset found for user %d", userID) {
			keyset = &model.UserKeyset{
				UserID:  userID,
				KeyData: make(map[string]string),
				Created: time.Now(),
				Updated: time.Now(),
			}
		} else {
			return fmt.Errorf("failed to get user keyset: %w", err)
		}
	}

	// Update the device key in the keyset
	keyset.KeyData[deviceType] = keyData
	keyset.Updated = time.Now()

	// Serialize the updated keyset
	keyDataJSON, err := json.Marshal(keyset.KeyData)
	if err != nil {
		return fmt.Errorf("failed to marshal updated keyset: %w", err)
	}

	// Save the updated keyset back to the database
	err = r.SaveUserKeyset(userID, string(keyDataJSON))
	if err != nil {
		return fmt.Errorf("failed to save updated keyset: %w", err)
	}

	return nil
}

// RemoveDeviceKeyFromKeyset removes a specific device key from a user's keyset
// If the keyset becomes empty after removal, the entire keyset is deleted
func (r *userAuthRepository) RemoveDeviceKeyFromKeyset(userID int, deviceType string) error {
	// Get the current keyset for the user
	keyset, err := r.GetUserKeyset(userID)
	if err != nil {
		// If no keyset exists, nothing to remove
		if err.Error() == fmt.Sprintf("no keyset found for user %d", userID) {
			return nil // No error, just nothing to remove
		}
		return fmt.Errorf("failed to get user keyset: %w", err)
	}

	// Remove the device key from the keyset
	delete(keyset.KeyData, deviceType)
	keyset.Updated = time.Now()

	// If the keyset is now empty, delete the entire keyset
	if len(keyset.KeyData) == 0 {
		return r.DeleteUserKeyset(userID)
	}

	// Otherwise, save the updated keyset
	keyDataJSON, err := json.Marshal(keyset.KeyData)
	if err != nil {
		return fmt.Errorf("failed to marshal updated keyset: %w", err)
	}

	err = r.SaveUserKeyset(userID, string(keyDataJSON))
	if err != nil {
		return fmt.Errorf("failed to save updated keyset: %w", err)
	}

	return nil
}

// FindKeysetByKeyID searches through all user keysets to find the one containing the specified key ID
// This method performs a reverse lookup by parsing JWK keys to extract their key IDs
func (r *userAuthRepository) FindKeysetByKeyID(keyID string) (*model.UserKeyset, error) {
	// Get all user keysets
	allKeysets, err := r.GetAllUserKeysets()
	if err != nil {
		return nil, fmt.Errorf("failed to get all user keysets: %w", err)
	}

	// Search through each keyset for the key ID
	for _, keyset := range allKeysets {
		// Check each device key in the keyset
		for _, keyData := range keyset.KeyData {
			// Parse the JWK key to extract its key ID
			key, err := jwk.ParseKey([]byte(keyData))
			if err != nil {
				continue // Skip invalid keys
			}

			// Get the key ID from the JWK (KeyID() returns (string, bool))
			currentKeyID, exists := key.KeyID()
			if exists && currentKeyID == keyID {
				return keyset, nil
			}
		}
	}

	return nil, fmt.Errorf("no keyset found containing key ID: %s", keyID)
}
