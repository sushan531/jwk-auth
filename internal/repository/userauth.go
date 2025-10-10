package repository

import (
	"database/sql"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/sushan531/jwk-auth/model"
)

type UserAuthRepository interface {
	SaveKeySet(userID int, keySet string) (*model.UserAuth, error)
	GetKeySetByUserID(userID int) (*model.UserAuth, error)
	UpdateKeySet(userID int, keySet string) (*model.UserAuth, error)
	GetLatestKeySet() (*model.UserAuth, error)
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
