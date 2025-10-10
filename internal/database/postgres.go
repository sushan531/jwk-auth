package database

import (
	"database/sql"
	"fmt"

	_ "github.com/lib/pq"
)

type Config struct {
	Host     string
	Port     int
	User     string
	Password string
	DBName   string
	SSLMode  string
}

func NewConnection(config Config) (*sql.DB, error) {
	if config.SSLMode == "" {
		config.SSLMode = "disable"
	}

	dsn := fmt.Sprintf("host=%s port=%d user=%s password=%s dbname=%s sslmode=%s",
		config.Host, config.Port, config.User, config.Password, config.DBName, config.SSLMode)

	db, err := sql.Open("postgres", dsn)
	if err != nil {
		return nil, fmt.Errorf("failed to open database connection: %w", err)
	}

	if err := db.Ping(); err != nil {
		return nil, fmt.Errorf("failed to ping database: %w", err)
	}

	return db, nil
}

func CreateTables(db *sql.DB) error {
	query := `
	CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
	
	-- Legacy table for backward compatibility
	CREATE TABLE IF NOT EXISTS user_auth (
		id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
		user_id INTEGER NOT NULL UNIQUE,
		key_set TEXT NOT NULL,
		created TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
		updated TIMESTAMP WITH TIME ZONE DEFAULT NOW()
	);

	-- New session-based key management table
	CREATE TABLE IF NOT EXISTS user_session_keys (
		id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
		user_id INTEGER NOT NULL,
		key_id VARCHAR(255) NOT NULL UNIQUE,
		key_data TEXT NOT NULL,
		device_type VARCHAR(50) NOT NULL,
		created TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
		updated TIMESTAMP WITH TIME ZONE DEFAULT NOW()
	);

	-- Indexes for performance
	CREATE INDEX IF NOT EXISTS idx_user_auth_user_id ON user_auth(user_id);
	CREATE INDEX IF NOT EXISTS idx_user_session_keys_user_id ON user_session_keys(user_id);
	CREATE INDEX IF NOT EXISTS idx_user_session_keys_key_id ON user_session_keys(key_id);
	CREATE INDEX IF NOT EXISTS idx_user_session_keys_device_type ON user_session_keys(device_type);
	`

	_, err := db.Exec(query)
	if err != nil {
		return fmt.Errorf("failed to create tables: %w", err)
	}

	return nil
}
