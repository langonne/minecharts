package database

import (
	"context"
	"errors"
	"os"
	"sync"
	"time"

	"minecharts/cmd/logging"
)

// Supported database types
const (
	SQLite     = "sqlite"
	PostgreSQL = "postgres"
)

var (
	ErrUserExists      = errors.New("user already exists")
	ErrUserNotFound    = errors.New("user not found")
	ErrServerNotFound  = errors.New("server not found")
	ErrInvalidPassword = errors.New("invalid password")
	ErrInvalidAPIKey   = errors.New("invalid API key")
	ErrDuplicate       = errors.New("duplicate value")
)

// DB is the interface that must be implemented by database providers
type DB interface {
	// User operations
	CreateUser(ctx context.Context, user *User) error
	GetUserByID(ctx context.Context, id int64) (*User, error)
	GetUserByUsername(ctx context.Context, username string) (*User, error)
	UpdateUser(ctx context.Context, user *User) error
	DeleteUser(ctx context.Context, id int64) error
	ListUsers(ctx context.Context) ([]*User, error)

	// API Key operations
	CreateAPIKey(ctx context.Context, key *APIKey) error
	GetAPIKey(ctx context.Context, key string) (*APIKey, error)
	DeleteAPIKey(ctx context.Context, id int64) error
	ListAPIKeysByUser(ctx context.Context, userID int64) ([]*APIKey, error)

	// Server methods
	CreateServerRecord(ctx context.Context, server *MinecraftServer) error
	GetServerByID(ctx context.Context, serverID int64) (*MinecraftServer, error)
	GetServerByName(ctx context.Context, serverName string) (*MinecraftServer, error)
	GetServerForOwner(ctx context.Context, ownerID int64, serverName string) (*MinecraftServer, error)
	ListServersByOwner(ctx context.Context, ownerID int64) ([]*MinecraftServer, error)
	UpdateServerStatus(ctx context.Context, serverName string, status string) error
	DeleteServerRecord(ctx context.Context, serverName string) error
	AllowRateLimit(ctx context.Context, key string, capacity float64, refillInterval time.Duration, now time.Time) (bool, time.Duration, error)
	CleanupRateLimits(ctx context.Context, cutoff time.Time) error

	// Database operations
	Init() error
	Close() error
}

// Global database instance
var (
	db     DB
	dbOnce sync.Once
)

// InitDB initializes the database with the provided configuration
func InitDB(dbType string, connectionString string) error {
	logging.DB.WithFields(
		"db_type", dbType,
	).Info("Initializing database")

	var err error
	dbOnce.Do(func() {
		switch dbType {
		case SQLite:
			logging.DB.WithFields(
				"connection", connectionString,
				"db_type", "sqlite",
			).Info("Creating SQLite database connection")
			db, err = NewSQLiteDB(connectionString)
		case PostgreSQL:
			logging.DB.WithFields(
				"connection", connectionString,
				"db_type", "postgres",
			).Info("Creating PostgreSQL database connection")
			db, err = NewPostgresDB(connectionString)
		default:
			// Default to SQLite if not specified
			logging.DB.WithFields(
				"requested_type", dbType,
				"using_type", "sqlite",
			).Warn("Unknown database type, using SQLite as default")
			db, err = NewSQLiteDB(connectionString)
		}

		if err != nil {
			logging.DB.WithFields(
				"error", err.Error(),
			).Error("Failed to initialize database")
			return
		}

		logging.DB.Debug("Database connection established, initializing schema")
		if err = db.Init(); err != nil {
			logging.DB.WithFields(
				"error", err.Error(),
			).Error("Failed to initialize database schema")
		} else {
			logging.DB.Info("Database schema initialized successfully")
		}
	})

	if err != nil {
		logging.DB.WithFields(
			"error", err.Error(),
		).Error("Database initialization failed")
	} else {
		logging.DB.Info("Database initialization completed successfully")
	}
	return err
}

// GetDB returns the global database instance
func GetDB() DB {
	if db == nil {
		logging.DB.Warn("Database instance not initialized, creating default SQLite instance")
		// Default to SQLite with a file in the data directory
		dataDir := os.Getenv("DATA_DIR")
		if dataDir == "" {
			dataDir = "./app/data"
			logging.DB.WithFields(
				"default_dir", dataDir,
			).Warn("DATA_DIR environment variable not set, using default")
		} else {
			logging.DB.WithFields(
				"data_dir", dataDir,
			).Debug("Using DATA_DIR from environment")
		}

		// Create data directory if it doesn't exist
		if err := os.MkdirAll(dataDir, 0755); err != nil {
			logging.DB.WithFields(
				"data_dir", dataDir,
				"error", err.Error(),
			).Error("Failed to create data directory")
		} else {
			logging.DB.WithFields(
				"data_dir", dataDir,
			).Debug("Data directory created or already exists")
		}

		dbPath := dataDir + "/minecharts.db"
		logging.DB.WithFields(
			"db_path", dbPath,
		).Info("Initializing default SQLite database")
		InitDB(SQLite, dbPath)
	} else {
		logging.DB.Debug("Using existing database instance")
	}
	return db
}
