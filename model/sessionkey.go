package model

import (
	"time"

	"github.com/google/uuid"
)

type SessionKey struct {
	ID         uuid.UUID `json:"id"`
	UserID     int       `json:"user_id"`
	KeyID      string    `json:"key_id"`
	KeyData    string    `json:"key_data"`
	DeviceType string    `json:"device_type"`
	Created    time.Time `json:"created"`
	Updated    time.Time `json:"updated"`
}
