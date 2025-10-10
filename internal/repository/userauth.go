package repository

import (
	"database/sql"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/sushan531/jwk-auth/model"
)

type UserAuthRepository interface {
	// Legacy key set methods (deprecated)
	SaveKeySet(userID int, keySet string) (*model.UserAuth, error)
	GetKeySetByUserID(userID int) (*model.UserAuth, error)
	UpdateKeySet(userID int, keySet string) (*model.UserAuth, error)
	GetLatestKeySet() (*model.UserAuth, error)

	// Session-based key management
	SaveSessionKey(userID int, keyID string, keyData string, deviceType string) error
	GetUserSessionKeys(userID int) ([]*model.SessionKey, error)
	GetAllSessionKeys() ([]*model.SessionKey, error)
	GetSessionKey(keyID string) (*model.SessionKey, error)
	DeleteSessionKey(userID int, keyID string) error
	DeleteAllUserSessionKeys(userID int) error
	DeleteUserSessionsByDeviceType(userID int, deviceType string) ([]*model.SessionKey, error)
}

type userAuthRepository struct {
	db *sql.DB
}

func NewUserAuthRepository(db *sql.DB) UserAuthRepository {
	return &userAuthRepository{db: db}
}

func (r *userAuthRepository) SaveKeySet(userID int, keySet string) (*model.UserAuth, error) {
	query := `
		INSERT INTO user_auth (id, user_id, key_set, created, updated)
		VALUES ($1, $2, $3, $4, $5)
		ON CONFLICT (user_id) 
		DO UPDATE SET 
			key_set = EXCLUDED.key_set,
			updated = EXCLUDED.updated
		RETURNING id, user_id, key_set, created, updated
	`

	id := uuid.New()
	now := time.Now()

	var userAuth model.UserAuth
	err := r.db.QueryRow(query, id, userID, keySet, now, now).Scan(
		&userAuth.ID,
		&userAuth.UserID,
		&userAuth.KeySet,
		&userAuth.Created,
		&userAuth.Updated,
	)

	if err != nil {
		return nil, fmt.Errorf("failed to save key set: %w", err)
	}

	return &userAuth, nil
}

func (r *userAuthRepository) GetKeySetByUserID(userID int) (*model.UserAuth, error) {
	query := `
		SELECT id, user_id, key_set, created, updated
		FROM user_auth
		WHERE user_id = $1
	`

	var userAuth model.UserAuth
	err := r.db.QueryRow(query, userID).Scan(
		&userAuth.ID,
		&userAuth.UserID,
		&userAuth.KeySet,
		&userAuth.Created,
		&userAuth.Updated,
	)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("no key set found for user_id %d", userID)
		}
		return nil, fmt.Errorf("failed to get key set: %w", err)
	}

	return &userAuth, nil
}

func (r *userAuthRepository) UpdateKeySet(userID int, keySet string) (*model.UserAuth, error) {
	query := `
		UPDATE user_auth 
		SET key_set = $1, updated = $2
		WHERE user_id = $3
		RETURNING id, user_id, key_set, created, updated
	`

	now := time.Now()
	var userAuth model.UserAuth
	err := r.db.QueryRow(query, keySet, now, userID).Scan(
		&userAuth.ID,
		&userAuth.UserID,
		&userAuth.KeySet,
		&userAuth.Created,
		&userAuth.Updated,
	)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("no key set found for user_id %d", userID)
		}
		return nil, fmt.Errorf("failed to update key set: %w", err)
	}

	return &userAuth, nil
}

func (r *userAuthRepository) GetLatestKeySet() (*model.UserAuth, error) {
	query := `
		SELECT id, user_id, key_set, created, updated
		FROM user_auth
		ORDER BY updated DESC
		LIMIT 1
	`

	var userAuth model.UserAuth
	err := r.db.QueryRow(query).Scan(
		&userAuth.ID,
		&userAuth.UserID,
		&userAuth.KeySet,
		&userAuth.Created,
		&userAuth.Updated,
	)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("no key sets found in database")
		}
		return nil, fmt.Errorf("failed to get latest key set: %w", err)
	}

	return &userAuth, nil
}

// SaveSessionKey saves a session key for a user
func (r *userAuthRepository) SaveSessionKey(userID int, keyID string, keyData string, deviceType string) error {
	query := `
		INSERT INTO user_session_keys (id, user_id, key_id, key_data, device_type, created, updated)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
		ON CONFLICT (key_id) 
		DO UPDATE SET 
			key_data = EXCLUDED.key_data,
			device_type = EXCLUDED.device_type,
			updated = EXCLUDED.updated
	`

	id := uuid.New()
	now := time.Now()

	_, err := r.db.Exec(query, id, userID, keyID, keyData, deviceType, now, now)
	if err != nil {
		return fmt.Errorf("failed to save session key: %w", err)
	}

	return nil
}

// GetUserSessionKeys retrieves all session keys for a user
func (r *userAuthRepository) GetUserSessionKeys(userID int) ([]*model.SessionKey, error) {
	query := `
		SELECT id, user_id, key_id, key_data, device_type, created, updated
		FROM user_session_keys
		WHERE user_id = $1
		ORDER BY created DESC
	`

	rows, err := r.db.Query(query, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to query user session keys: %w", err)
	}
	defer rows.Close()

	var sessionKeys []*model.SessionKey
	for rows.Next() {
		var sk model.SessionKey
		err := rows.Scan(
			&sk.ID,
			&sk.UserID,
			&sk.KeyID,
			&sk.KeyData,
			&sk.DeviceType,
			&sk.Created,
			&sk.Updated,
		)
		if err != nil {
			continue // Skip invalid rows
		}
		sessionKeys = append(sessionKeys, &sk)
	}

	return sessionKeys, nil
}

// GetSessionKey retrieves a specific session key by key ID
func (r *userAuthRepository) GetSessionKey(keyID string) (*model.SessionKey, error) {
	query := `
		SELECT id, user_id, key_id, key_data, device_type, created, updated
		FROM user_session_keys
		WHERE key_id = $1
	`

	var sk model.SessionKey
	err := r.db.QueryRow(query, keyID).Scan(
		&sk.ID,
		&sk.UserID,
		&sk.KeyID,
		&sk.KeyData,
		&sk.DeviceType,
		&sk.Created,
		&sk.Updated,
	)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("no session key found with key_id %s", keyID)
		}
		return nil, fmt.Errorf("failed to get session key: %w", err)
	}

	return &sk, nil
}

// DeleteSessionKey removes a specific session key
func (r *userAuthRepository) DeleteSessionKey(userID int, keyID string) error {
	query := `DELETE FROM user_session_keys WHERE user_id = $1 AND key_id = $2`

	result, err := r.db.Exec(query, userID, keyID)
	if err != nil {
		return fmt.Errorf("failed to delete session key: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rowsAffected == 0 {
		return fmt.Errorf("no session key found with key_id %s for user %d", keyID, userID)
	}

	return nil
}

// DeleteAllUserSessionKeys removes all session keys for a user (logout from all devices)
func (r *userAuthRepository) DeleteAllUserSessionKeys(userID int) error {
	query := `DELETE FROM user_session_keys WHERE user_id = $1`

	_, err := r.db.Exec(query, userID)
	if err != nil {
		return fmt.Errorf("failed to delete all user session keys: %w", err)
	}

	return nil
}

// DeleteUserSessionsByDeviceType removes all sessions for a user's specific device type
// Returns the deleted session keys for cleanup
func (r *userAuthRepository) DeleteUserSessionsByDeviceType(userID int, deviceType string) ([]*model.SessionKey, error) {
	// First, get the sessions that will be deleted
	selectQuery := `
		SELECT id, user_id, key_id, key_data, device_type, created, updated
		FROM user_session_keys
		WHERE user_id = $1 AND device_type = $2
	`

	rows, err := r.db.Query(selectQuery, userID, deviceType)
	if err != nil {
		return nil, fmt.Errorf("failed to query sessions to delete: %w", err)
	}
	defer rows.Close()

	var sessionsToDelete []*model.SessionKey
	for rows.Next() {
		var sk model.SessionKey
		err := rows.Scan(
			&sk.ID,
			&sk.UserID,
			&sk.KeyID,
			&sk.KeyData,
			&sk.DeviceType,
			&sk.Created,
			&sk.Updated,
		)
		if err != nil {
			continue
		}
		sessionsToDelete = append(sessionsToDelete, &sk)
	}

	// Now delete them
	deleteQuery := `DELETE FROM user_session_keys WHERE user_id = $1 AND device_type = $2`
	_, err = r.db.Exec(deleteQuery, userID, deviceType)
	if err != nil {
		return nil, fmt.Errorf("failed to delete sessions by device type: %w", err)
	}

	return sessionsToDelete, nil
}

// GetAllSessionKeys retrieves all session keys from all users
func (r *userAuthRepository) GetAllSessionKeys() ([]*model.SessionKey, error) {
	query := `
		SELECT id, user_id, key_id, key_data, device_type, created, updated
		FROM user_session_keys
		ORDER BY created DESC
	`

	rows, err := r.db.Query(query)
	if err != nil {
		return nil, fmt.Errorf("failed to query all session keys: %w", err)
	}
	defer rows.Close()

	var sessionKeys []*model.SessionKey
	for rows.Next() {
		var sk model.SessionKey
		err := rows.Scan(
			&sk.ID,
			&sk.UserID,
			&sk.KeyID,
			&sk.KeyData,
			&sk.DeviceType,
			&sk.Created,
			&sk.Updated,
		)
		if err != nil {
			continue // Skip invalid rows
		}
		sessionKeys = append(sessionKeys, &sk)
	}

	return sessionKeys, nil
}
