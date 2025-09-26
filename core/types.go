package core

type DeviceClaims struct {
	Username string `json:"username"`
	DeviceID string `json:"device_id,omitempty"`
	Scope    string `json:"scope"`
	UserID   string `json:"user_id,omitempty"`
}

type TokenResponse struct {
	Token     string `json:"token"`
	ExpiresAt int64  `json:"expires_at"`
	TokenType string `json:"token_type"`
}
