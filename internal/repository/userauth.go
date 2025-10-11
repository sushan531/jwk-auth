package repository

import (
	"database/sql"
	"fmt"
	"time"

	"github.com/sushan531/jwk-auth/model"
)

type UserAuthRepository interface {
	// Keyset management (consolidated approach)
	SaveUserKeyset(userID int, keyData string, encryptionKey string) error
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
func (r *userAuthRepository) GetUserKeyset(userID int) (*model.UserKeyset, error) {
	query := `
		SELECT user_id, key_data, encryption_key, created, updated
		FROM user_keysets
		WHERE user_id = $1
	`

	var uk model.UserKeyset

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
func (r *userAuthRepository) GetAllUserKeysets() ([]*model.UserKeyset, error) {
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

	var keysets []*model.UserKeyset
	for rows.Next() {
		var uk model.UserKeyset

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
func (r *userAuthRepository) FindKeysetByKeyID(keyID string) (*model.UserKeyset, error) {
	return nil, fmt.Errorf("FindKeysetByKeyID is deprecated with encryption - use JWK manager methods instead")
}
