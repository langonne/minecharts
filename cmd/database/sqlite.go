package database

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"math"
	"strings"
	"time"

	"minecharts/cmd/logging"

	_ "modernc.org/sqlite"
)

// SQLiteDB implements the DB interface for SQLite
type SQLiteDB struct {
	db *sql.DB
}

// NewSQLiteDB creates a new SQLite database connection
func NewSQLiteDB(path string) (*SQLiteDB, error) {
	logging.DB.WithFields(
		"db_path", path,
		"db_type", "sqlite",
	).Info("Creating new SQLite database connection")

	db, err := sql.Open("sqlite", path)
	if err != nil {
		logging.DB.WithFields(
			"db_path", path,
			"error", err.Error(),
		).Error("Failed to open SQLite database connection")
		return nil, err
	}

	logging.DB.WithFields(
		"db_path", path,
	).Debug("SQLite database connection established")
	return &SQLiteDB{db: db}, nil
}

// Init initializes the database schema
func (s *SQLiteDB) Init() error {
	logging.DB.Info("Initializing SQLite database schema")

	// Create users table
	logging.DB.Debug("Creating users table if not exists")
	_, err := s.db.Exec(`
		CREATE TABLE IF NOT EXISTS users (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			username TEXT UNIQUE NOT NULL,
			email TEXT UNIQUE NOT NULL,
			password_hash TEXT NOT NULL,
			permissions INTEGER NOT NULL DEFAULT 0,
			active BOOLEAN NOT NULL DEFAULT TRUE,
			last_login TIMESTAMP,
			created_at TIMESTAMP NOT NULL,
			updated_at TIMESTAMP NOT NULL
		)
	`)
	if err != nil {
		logging.DB.WithFields(
			"error", err.Error(),
		).Error("Failed to create users table")
		return err
	}

	logging.DB.Debug("Creating rate_limits table if not exists")
	_, err = s.db.Exec(`
		CREATE TABLE IF NOT EXISTS rate_limits (
			key TEXT PRIMARY KEY,
			tokens REAL NOT NULL,
			last_refill TIMESTAMP NOT NULL
		)
	`)
	if err != nil {
		logging.DB.WithFields(
			"error", err.Error(),
		).Error("Failed to create rate_limits table")
		return err
	}

	// Create API keys table
	logging.DB.Debug("Creating api_keys table if not exists")
	_, err = s.db.Exec(`
		CREATE TABLE IF NOT EXISTS api_keys (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			user_id INTEGER NOT NULL,
			key TEXT UNIQUE NOT NULL,
			description TEXT,
			last_used TIMESTAMP,
			expires_at TIMESTAMP,
			created_at TIMESTAMP NOT NULL,
			FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
		)
	`)
	if err != nil {
		logging.DB.WithFields(
			"error", err.Error(),
		).Error("Failed to create api_keys table")
		return err
	}

	_, err = s.db.Exec(`
    CREATE TABLE IF NOT EXISTS minecraft_servers (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        server_name TEXT UNIQUE NOT NULL,
        deployment_name TEXT NOT NULL,
        pvc_name TEXT NOT NULL,
        owner_id INTEGER NOT NULL,
        status TEXT NOT NULL,
        created_at TIMESTAMP NOT NULL,
        updated_at TIMESTAMP NOT NULL,
        FOREIGN KEY (owner_id) REFERENCES users(id)
    )
`)
	if err != nil {
		logging.DB.WithFields(
			"error", err.Error(),
		).Error("Failed to create minecraft_servers table")
		return fmt.Errorf("failed to create minecraft_servers table: %w", err)
	}

	// Check if we need to create an admin user
	logging.DB.Debug("Checking if admin user needs to be created")
	var count int
	err = s.db.QueryRow("SELECT COUNT(*) FROM users").Scan(&count)
	if err != nil {
		logging.DB.WithFields(
			"error", err.Error(),
		).Error("Failed to count users")
		return err
	}

	// If no users exist, create a default admin user
	if count == 0 {
		logging.DB.Info("Creating default admin user")
		now := time.Now()
		_, err = s.db.Exec(
			"INSERT INTO users (username, email, password_hash, permissions, active, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
			"admin",
			"admin@example.com",
			"$2a$10$lCLlDMorzUH3R9pwSehyau1DISGeEdL21xpSzy7mjFwQ.CYYnydrW", // password: admin
			PermAll,
			true,
			now,
			now,
		)
		if err != nil {
			logging.DB.WithFields(
				"error", err.Error(),
			).Error("Failed to create default admin user")
			return err
		}
		logging.DB.Info("Default admin user created successfully")
	}

	logging.DB.Info("Database schema initialized successfully")
	return nil
}

// Close closes the database connection
func (s *SQLiteDB) Close() error {
	logging.DB.Info("Closing SQLite database connection")
	err := s.db.Close()
	if err != nil {
		logging.DB.WithFields(
			"error", err.Error(),
		).Error("Error closing SQLite database connection")
		return err
	}
	logging.DB.Debug("SQLite database connection closed successfully")
	return nil
}

// User operations

// CreateUser creates a new user
func (s *SQLiteDB) CreateUser(ctx context.Context, user *User) error {
	logging.DB.WithFields(
		"username", user.Username,
		"email", user.Email,
	).Info("Creating new user")

	// Check if user already exists
	var exists bool
	err := s.db.QueryRowContext(ctx,
		"SELECT EXISTS(SELECT 1 FROM users WHERE username = ? OR email = ?)",
		user.Username, user.Email,
	).Scan(&exists)
	if err != nil {
		logging.DB.WithFields(
			"username", user.Username,
			"email", user.Email,
			"error", err.Error(),
		).Error("Database error when checking if user exists")
		return err
	}
	if exists {
		logging.DB.WithFields(
			"username", user.Username,
			"email", user.Email,
			"error", "user_exists",
		).Warn("Cannot create user: username or email already exists")
		return ErrUserExists
	}

	// Set timestamps
	now := time.Now()
	user.CreatedAt = now
	user.UpdatedAt = now

	// Insert user
	result, err := s.db.ExecContext(ctx,
		"INSERT INTO users (username, email, password_hash, permissions, active, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
		user.Username, user.Email, user.PasswordHash, user.Permissions, user.Active, user.CreatedAt, user.UpdatedAt,
	)
	if err != nil {
		logging.DB.WithFields(
			"username", user.Username,
			"email", user.Email,
			"error", err.Error(),
		).Error("Failed to insert new user")
		return err
	}

	id, err := result.LastInsertId()
	if err != nil {
		logging.DB.WithFields(
			"username", user.Username,
			"email", user.Email,
			"error", err.Error(),
		).Error("Failed to get new user ID")
		return err
	}
	user.ID = id

	logging.DB.WithFields(
		"username", user.Username,
		"email", user.Email,
		"user_id", user.ID,
	).Info("User created successfully")
	return nil
}

// GetUserByID retrieves a user by ID
func (s *SQLiteDB) GetUserByID(ctx context.Context, id int64) (*User, error) {
	logging.DB.WithFields(
		"user_id", id,
		"db_type", "sqlite",
	).Debug("Getting user by ID")

	user := &User{}
	err := s.db.QueryRowContext(ctx,
		"SELECT id, username, email, password_hash, permissions, active, last_login, created_at, updated_at FROM users WHERE id = ?",
		id,
	).Scan(
		&user.ID, &user.Username, &user.Email, &user.PasswordHash, &user.Permissions,
		&user.Active, &user.LastLogin, &user.CreatedAt, &user.UpdatedAt,
	)
	if err == sql.ErrNoRows {
		logging.DB.WithFields(
			"user_id", id,
			"error", "user_not_found",
		).Debug("User not found by ID")
		return nil, ErrUserNotFound
	}
	if err != nil {
		logging.DB.WithFields(
			"user_id", id,
			"error", err.Error(),
		).Error("Database error when getting user by ID")
		return nil, err
	}

	logging.DB.WithFields(
		"user_id", id,
		"username", user.Username,
	).Debug("Successfully retrieved user by ID")
	return user, nil
}

// GetUserByUsername retrieves a user by username
func (s *SQLiteDB) GetUserByUsername(ctx context.Context, username string) (*User, error) {
	logging.DB.WithFields(
		"username", username,
		"db_type", "sqlite",
	).Debug("Getting user by username")

	user := &User{}
	query := "SELECT id, username, email, password_hash, permissions, active, last_login, created_at, updated_at FROM users WHERE username = ?"

	logging.DB.WithFields(
		"username", username,
		"query", query,
	).Debug("Executing database query")

	err := s.db.QueryRowContext(ctx, query, username).Scan(
		&user.ID, &user.Username, &user.Email, &user.PasswordHash, &user.Permissions,
		&user.Active, &user.LastLogin, &user.CreatedAt, &user.UpdatedAt,
	)
	if err == sql.ErrNoRows {
		logging.DB.WithFields(
			"username", username,
			"error", "user_not_found",
		).Debug("User not found")
		return nil, ErrUserNotFound
	}
	if err != nil {
		logging.DB.WithFields(
			"username", username,
			"error", err.Error(),
		).Error("Database error when getting user by username")
		return nil, err
	}

	logging.DB.WithFields(
		"username", user.Username,
		"user_id", user.ID,
	).Debug("Successfully retrieved user")
	return user, nil
}

// UpdateUser updates a user's information
func (s *SQLiteDB) UpdateUser(ctx context.Context, user *User) error {
	logging.DB.WithFields(
		"user_id", user.ID,
		"username", user.Username,
	).Info("Updating user information")

	user.UpdatedAt = time.Now()

	_, err := s.db.ExecContext(ctx,
		"UPDATE users SET username = ?, email = ?, password_hash = ?, permissions = ?, active = ?, updated_at = ? WHERE id = ?",
		user.Username, user.Email, user.PasswordHash, user.Permissions, user.Active, user.UpdatedAt, user.ID,
	)
	if err != nil {
		logging.DB.WithFields(
			"user_id", user.ID,
			"username", user.Username,
			"error", err.Error(),
		).Error("Failed to update user")
		return err
	}

	logging.DB.WithFields(
		"user_id", user.ID,
		"username", user.Username,
	).Info("User updated successfully")
	return nil
}

func (s *SQLiteDB) AllowRateLimit(ctx context.Context, key string, capacity float64, refillInterval time.Duration, now time.Time) (bool, time.Duration, error) {
	const maxAttempts = 3
	for attempt := 0; attempt < maxAttempts; attempt++ {
		tx, err := s.db.BeginTx(ctx, nil)
		if err != nil {
			if isSQLiteBusy(err) {
				time.Sleep(50 * time.Millisecond)
				continue
			}
			return false, 0, err
		}

		var tokens float64
		var lastRefill time.Time
		err = tx.QueryRowContext(ctx, "SELECT tokens, last_refill FROM rate_limits WHERE key = ?", key).Scan(&tokens, &lastRefill)
		if errors.Is(err, sql.ErrNoRows) {
			tokens = capacity
			lastRefill = now
		} else if err != nil {
			tx.Rollback()
			if isSQLiteBusy(err) {
				time.Sleep(50 * time.Millisecond)
				continue
			}
			return false, 0, err
		} else {
			elapsed := now.Sub(lastRefill)
			if elapsed > 0 {
				refillTokens := elapsed.Seconds() / refillInterval.Seconds()
				tokens = math.Min(capacity, tokens+refillTokens)
			}
		}

		allowed := tokens >= 1.0
		var retryAfter time.Duration
		if allowed {
			tokens -= 1
		} else {
			missing := 1.0 - tokens
			if missing < 0 {
				missing = 0
			}
			seconds := missing * refillInterval.Seconds()
			retryAfter = time.Duration(math.Ceil(seconds)) * time.Second
		}

		_, err = tx.ExecContext(ctx,
			"INSERT INTO rate_limits(key, tokens, last_refill) VALUES (?, ?, ?) ON CONFLICT(key) DO UPDATE SET tokens=excluded.tokens, last_refill=excluded.last_refill",
			key, tokens, now,
		)
		if err != nil {
			tx.Rollback()
			if isSQLiteBusy(err) {
				time.Sleep(50 * time.Millisecond)
				continue
			}
			return false, 0, err
		}

		if err := tx.Commit(); err != nil {
			if isSQLiteBusy(err) {
				time.Sleep(50 * time.Millisecond)
				continue
			}
			return false, 0, err
		}

		return allowed, retryAfter, nil
	}

	return false, 0, fmt.Errorf("rate limit: database busy after retries")
}

func (s *SQLiteDB) CleanupRateLimits(ctx context.Context, cutoff time.Time) error {
	_, err := s.db.ExecContext(ctx, "DELETE FROM rate_limits WHERE last_refill < ?", cutoff)
	return err
}

func isSQLiteBusy(err error) bool {
	if err == nil {
		return false
	}
	return strings.Contains(err.Error(), "locked")
}

// DeleteUser deletes a user by ID
func (s *SQLiteDB) DeleteUser(ctx context.Context, id int64) error {
	logging.DB.WithFields(
		"user_id", id,
	).Info("Deleting user")

	_, err := s.db.ExecContext(ctx, "DELETE FROM users WHERE id = ?", id)
	if err != nil {
		logging.DB.WithFields(
			"user_id", id,
			"error", err.Error(),
		).Error("Failed to delete user")
		return err
	}

	logging.DB.WithFields(
		"user_id", id,
	).Info("User deleted successfully")
	return nil
}

// ListUsers returns a list of all users
func (s *SQLiteDB) ListUsers(ctx context.Context) ([]*User, error) {
	logging.DB.Debug("Listing all users")

	rows, err := s.db.QueryContext(ctx,
		"SELECT id, username, email, password_hash, permissions, active, last_login, created_at, updated_at FROM users",
	)
	if err != nil {
		logging.DB.WithFields(
			"error", err.Error(),
		).Error("Failed to query users")
		return nil, err
	}
	defer rows.Close()

	users := []*User{}
	for rows.Next() {
		user := &User{}
		if err := rows.Scan(
			&user.ID, &user.Username, &user.Email, &user.PasswordHash, &user.Permissions,
			&user.Active, &user.LastLogin, &user.CreatedAt, &user.UpdatedAt,
		); err != nil {
			logging.DB.WithFields(
				"error", err.Error(),
			).Error("Failed to scan user row")
			return nil, err
		}
		users = append(users, user)
	}

	if err = rows.Err(); err != nil {
		logging.DB.WithFields(
			"error", err.Error(),
		).Error("Error during user rows iteration")
		return nil, err
	}

	logging.DB.WithFields(
		"count", len(users),
	).Debug("Successfully retrieved user list")
	return users, nil
}

// API Key operations

// CreateAPIKey creates a new API key
func (s *SQLiteDB) CreateAPIKey(ctx context.Context, key *APIKey) error {
	logging.DB.WithFields(
		"user_id", key.UserID,
		"description", key.Description,
	).Info("Creating new API key")

	now := time.Now()
	key.CreatedAt = now

	result, err := s.db.ExecContext(ctx,
		"INSERT INTO api_keys (user_id, key, description, expires_at, created_at) VALUES (?, ?, ?, ?, ?)",
		key.UserID, key.Key, key.Description, key.ExpiresAt, key.CreatedAt,
	)
	if err != nil {
		logging.DB.WithFields(
			"user_id", key.UserID,
			"error", err.Error(),
		).Error("Failed to insert API key")
		return err
	}

	id, err := result.LastInsertId()
	if err != nil {
		logging.DB.WithFields(
			"user_id", key.UserID,
			"error", err.Error(),
		).Error("Failed to get API key ID")
		return err
	}
	key.ID = id

	logging.DB.WithFields(
		"user_id", key.UserID,
		"key_id", key.ID,
	).Info("API key created successfully")
	return nil
}

// GetAPIKey retrieves an API key by the key string
func (s *SQLiteDB) GetAPIKey(ctx context.Context, keyStr string) (*APIKey, error) {
	// Mask the full key in logs for security
	maskedKey := keyStr
	if len(keyStr) > 8 {
		maskedKey = keyStr[:4] + "..." + keyStr[len(keyStr)-4:]
	}

	logging.DB.WithFields(
		"key", maskedKey,
	).Debug("Looking up API key")

	key := &APIKey{}
	err := s.db.QueryRowContext(ctx,
		"SELECT id, user_id, key, description, last_used, expires_at, created_at FROM api_keys WHERE key = ?",
		keyStr,
	).Scan(
		&key.ID, &key.UserID, &key.Key, &key.Description, &key.LastUsed, &key.ExpiresAt, &key.CreatedAt,
	)
	if err == sql.ErrNoRows {
		logging.DB.WithFields(
			"key", maskedKey,
			"error", "invalid_api_key",
		).Warn("API key not found")
		return nil, ErrInvalidAPIKey
	}
	if err != nil {
		logging.DB.WithFields(
			"key", maskedKey,
			"error", err.Error(),
		).Error("Database error when retrieving API key")
		return nil, err
	}

	// Update last used time
	now := time.Now()
	key.LastUsed = now
	_, err = s.db.ExecContext(ctx, "UPDATE api_keys SET last_used = ? WHERE id = ?", now, key.ID)
	if err != nil {
		logging.DB.WithFields(
			"key_id", key.ID,
			"error", err.Error(),
		).Error("Failed to update API key last used time")
		return nil, err
	}

	// Check if the key has expired
	if key.ExpiresAt != nil && key.ExpiresAt.Before(now) {
		logging.DB.WithFields(
			"key_id", key.ID,
			"user_id", key.UserID,
			"expired_at", key.ExpiresAt,
		).Warn("Attempted to use expired API key")
		return nil, ErrInvalidAPIKey
	}

	logging.DB.WithFields(
		"key_id", key.ID,
		"user_id", key.UserID,
	).Debug("API key found and last used time updated")
	return key, nil
}

// DeleteAPIKey deletes an API key by ID
func (s *SQLiteDB) DeleteAPIKey(ctx context.Context, id int64) error {
	logging.DB.WithFields(
		"key_id", id,
	).Info("Deleting API key")

	_, err := s.db.ExecContext(ctx, "DELETE FROM api_keys WHERE id = ?", id)
	if err != nil {
		logging.DB.WithFields(
			"key_id", id,
			"error", err.Error(),
		).Error("Failed to delete API key")
		return err
	}

	logging.DB.WithFields(
		"key_id", id,
	).Info("API key deleted successfully")
	return nil
}

// ListAPIKeysByUser lists all API keys for a user
func (s *SQLiteDB) ListAPIKeysByUser(ctx context.Context, userID int64) ([]*APIKey, error) {
	logging.DB.WithFields(
		"user_id", userID,
	).Debug("Listing API keys for user")

	rows, err := s.db.QueryContext(ctx,
		"SELECT id, user_id, key, description, last_used, expires_at, created_at FROM api_keys WHERE user_id = ?",
		userID,
	)
	if err != nil {
		logging.DB.WithFields(
			"user_id", userID,
			"error", err.Error(),
		).Error("Failed to query API keys")
		return nil, err
	}
	defer rows.Close()

	keys := []*APIKey{}
	for rows.Next() {
		key := &APIKey{}
		if err := rows.Scan(
			&key.ID, &key.UserID, &key.Key, &key.Description, &key.LastUsed, &key.ExpiresAt, &key.CreatedAt,
		); err != nil {
			logging.DB.WithFields(
				"user_id", userID,
				"error", err.Error(),
			).Error("Failed to scan API key row")
			return nil, err
		}
		keys = append(keys, key)
	}

	if err = rows.Err(); err != nil {
		logging.DB.WithFields(
			"user_id", userID,
			"error", err.Error(),
		).Error("Error during API key rows iteration")
		return nil, err
	}

	logging.DB.WithFields(
		"user_id", userID,
		"count", len(keys),
	).Debug("Successfully retrieved API keys")
	return keys, nil
}

// CreateServerRecord creates a new server record
func (db *SQLiteDB) CreateServerRecord(ctx context.Context, server *MinecraftServer) error {
	logging.DB.WithFields(
		"server_name", server.ServerName,
		"owner_id", server.OwnerID,
	).Info("Creating new server record")

	query := `INSERT INTO minecraft_servers
              (server_name, deployment_name, pvc_name, owner_id, status, created_at, updated_at)
              VALUES (?, ?, ?, ?, ?, ?, ?)`

	now := time.Now()
	server.CreatedAt = now
	server.UpdatedAt = now

	result, err := db.db.ExecContext(ctx, query,
		server.ServerName,
		server.DeploymentName,
		server.PVCName,
		server.OwnerID,
		server.Status,
		server.CreatedAt,
		server.UpdatedAt,
	)

	if err != nil {
		logging.DB.WithFields(
			"server_name", server.ServerName,
			"error", err.Error(),
		).Error("Failed to create server record")
		return fmt.Errorf("failed to create server record: %w", err)
	}

	id, err := result.LastInsertId()
	if err != nil {
		logging.DB.WithFields(
			"server_name", server.ServerName,
			"error", err.Error(),
		).Error("Failed to get server ID")
		return fmt.Errorf("failed to get server ID: %w", err)
	}
	server.ID = id

	logging.DB.WithFields(
		"server_name", server.ServerName,
		"server_id", server.ID,
	).Info("Server record created successfully")
	return nil
}

// GetServerByName gets a server by its name
func (db *SQLiteDB) GetServerByName(ctx context.Context, serverName string) (*MinecraftServer, error) {
	logging.DB.WithFields(
		"server_name", serverName,
	).Debug("Getting server by name")

	query := `SELECT id, server_name, deployment_name, pvc_name, owner_id,
              status, created_at, updated_at
              FROM minecraft_servers WHERE server_name = ?`

	var server MinecraftServer
	err := db.db.QueryRowContext(ctx, query, serverName).Scan(
		&server.ID,
		&server.ServerName,
		&server.DeploymentName,
		&server.PVCName,
		&server.OwnerID,
		&server.Status,
		&server.CreatedAt,
		&server.UpdatedAt,
	)

	if err == sql.ErrNoRows {
		logging.DB.WithFields(
			"server_name", serverName,
			"error", "server_not_found",
		).Debug("Server not found")
		return nil, fmt.Errorf("server not found: %s", serverName)
	}

	if err != nil {
		logging.DB.WithFields(
			"server_name", serverName,
			"error", err.Error(),
		).Error("Failed to get server")
		return nil, fmt.Errorf("failed to get server: %w", err)
	}

	logging.DB.WithFields(
		"server_name", serverName,
		"server_id", server.ID,
	).Debug("Server found")
	return &server, nil
}

// GetServerByID retrieves a Minecraft server by its numeric ID.
func (db *SQLiteDB) GetServerByID(ctx context.Context, serverID int64) (*MinecraftServer, error) {
	logging.DB.WithFields(
		"server_id", serverID,
	).Debug("Getting server by ID")

	query := `SELECT id, server_name, deployment_name, pvc_name, owner_id,
              status, created_at, updated_at
              FROM minecraft_servers WHERE id = ?`

	var server MinecraftServer
	err := db.db.QueryRowContext(ctx, query, serverID).Scan(
		&server.ID,
		&server.ServerName,
		&server.DeploymentName,
		&server.PVCName,
		&server.OwnerID,
		&server.Status,
		&server.CreatedAt,
		&server.UpdatedAt,
	)

	if err == sql.ErrNoRows {
		logging.DB.WithFields(
			"server_id", serverID,
			"error", "server_not_found",
		).Debug("Server not found by ID")
		return nil, fmt.Errorf("server not found: %d", serverID)
	}

	if err != nil {
		logging.DB.WithFields(
			"server_id", serverID,
			"error", err.Error(),
		).Error("Failed to get server by ID")
		return nil, fmt.Errorf("failed to get server by id: %w", err)
	}

	logging.DB.WithFields(
		"server_id", serverID,
		"server_name", server.ServerName,
	).Debug("Server found by ID")
	return &server, nil
}

// ListServersByOwner list servers by owner ID
func (db *SQLiteDB) ListServersByOwner(ctx context.Context, ownerID int64) ([]*MinecraftServer, error) {
	logging.DB.WithFields(
		"owner_id", ownerID,
	).Debug("Listing servers by owner")

	query := `SELECT id, server_name, deployment_name, pvc_name, owner_id,
              status, created_at, updated_at
              FROM minecraft_servers WHERE owner_id = ?`

	rows, err := db.db.QueryContext(ctx, query, ownerID)
	if err != nil {
		logging.DB.WithFields(
			"owner_id", ownerID,
			"error", err.Error(),
		).Error("Failed to list servers")
		return nil, fmt.Errorf("failed to list servers: %w", err)
	}
	defer rows.Close()

	var servers []*MinecraftServer
	for rows.Next() {
		var server MinecraftServer
		if err := rows.Scan(
			&server.ID,
			&server.ServerName,
			&server.DeploymentName,
			&server.PVCName,
			&server.OwnerID,
			&server.Status,
			&server.CreatedAt,
			&server.UpdatedAt,
		); err != nil {
			logging.DB.WithFields(
				"owner_id", ownerID,
				"error", err.Error(),
			).Error("Failed to scan server row")
			return nil, fmt.Errorf("failed to scan server row: %w", err)
		}
		servers = append(servers, &server)
	}

	if err := rows.Err(); err != nil {
		logging.DB.WithFields(
			"owner_id", ownerID,
			"error", err.Error(),
		).Error("Error iterating server rows")
		return nil, fmt.Errorf("error iterating server rows: %w", err)
	}

	logging.DB.WithFields(
		"owner_id", ownerID,
		"server_count", len(servers),
	).Debug("Servers listed successfully")
	return servers, nil
}

// UpdateServerStatus updates the status of a server
func (db *SQLiteDB) UpdateServerStatus(ctx context.Context, serverName string, status string) error {
	logging.DB.WithFields(
		"server_name", serverName,
		"new_status", status,
	).Info("Updating server status")

	query := `UPDATE minecraft_servers SET status = ?, updated_at = ? WHERE server_name = ?`

	now := time.Now()
	_, err := db.db.ExecContext(ctx, query, status, now, serverName)
	if err != nil {
		logging.DB.WithFields(
			"server_name", serverName,
			"status", status,
			"error", err.Error(),
		).Error("Failed to update server status")
		return fmt.Errorf("failed to update server status: %w", err)
	}

	logging.DB.WithFields(
		"server_name", serverName,
		"status", status,
	).Info("Server status updated successfully")
	return nil
}

// DeleteServerRecord deletes a server record by its name
func (db *SQLiteDB) DeleteServerRecord(ctx context.Context, serverName string) error {
	logging.DB.WithFields(
		"server_name", serverName,
	).Info("Deleting server record")

	query := `DELETE FROM minecraft_servers WHERE server_name = ?`

	_, err := db.db.ExecContext(ctx, query, serverName)
	if err != nil {
		logging.DB.WithFields(
			"server_name", serverName,
			"error", err.Error(),
		).Error("Failed to delete server record")
		return fmt.Errorf("failed to delete server record: %w", err)
	}

	logging.DB.WithFields(
		"server_name", serverName,
	).Info("Server record deleted successfully")
	return nil
}
