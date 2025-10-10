package model

import (
	"time"

	"github.com/google/uuid"
)

type UserAuth struct {
	ID      uuid.UUID `json:"id" db:"id"`
	UserID  int       `json:"user_id" db:"user_id"`
	KeySet  string    `json:"key_set" db:"key_set"` // JSON serialized JWK set
	Created time.Time `json:"created" db:"created"`
	Updated time.Time `json:"updated" db:"updated"`
}
