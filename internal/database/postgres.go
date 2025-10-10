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
	
	-- Consolidated user keysets table
	CREATE TABLE IF NOT EXISTS user_keysets (
		user_id INTEGER PRIMARY KEY,
		key_data JSONB NOT NULL,
		created TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
		updated TIMESTAMP WITH TIME ZONE DEFAULT NOW()
	);

	-- Indexes for performance
	CREATE INDEX IF NOT EXISTS idx_user_keysets_updated ON user_keysets(updated);
	-- GIN index for JSON queries (PostgreSQL specific)
	CREATE INDEX IF NOT EXISTS idx_user_keysets_key_data ON user_keysets USING GIN (key_data);
	`

	_, err := db.Exec(query)
	if err != nil {
		return fmt.Errorf("failed to create tables: %w", err)
	}

	return nil
}

// DropLegacyTables removes the old user_session_keys table after migration is complete
func DropLegacyTables(db *sql.DB) error {
	query := `DROP TABLE IF EXISTS user_session_keys CASCADE;`

	_, err := db.Exec(query)
	if err != nil {
		return fmt.Errorf("failed to drop legacy tables: %w", err)
	}

	fmt.Println("Successfully dropped legacy user_session_keys table")
	return nil
}
