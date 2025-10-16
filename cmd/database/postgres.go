package database

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"math"
	"time"

	"minecharts/cmd/auth"
	"minecharts/cmd/logging"

	pq "github.com/lib/pq"
)

// PostgresDB implements the DB interface for PostgreSQL
type PostgresDB struct {
	db *sql.DB
}

// NewPostgresDB creates a new PostgreSQL database connection
func NewPostgresDB(connString string) (*PostgresDB, error) {
	logging.DB.WithFields(
		"db_type", "postgres",
	).Info("Creating new PostgreSQL database connection")

	db, err := sql.Open("postgres", connString)
	if err != nil {
		logging.DB.WithFields(
			"db_type", "postgres",
			"error", err.Error(),
		).Error("Failed to open PostgreSQL database connection")
		return nil, err
	}

	logging.DB.Debug("PostgreSQL database connection established")
	return &PostgresDB{db: db}, nil
}

// Init initializes the database schema
func (p *PostgresDB) Init() error {
	logging.DB.Info("Initializing PostgreSQL database schema")

	// Create users table
	logging.DB.Debug("Creating users table if not exists")
	_, err := p.db.Exec(`
		CREATE TABLE IF NOT EXISTS users (
			id SERIAL PRIMARY KEY,
			username TEXT UNIQUE NOT NULL,
			email TEXT UNIQUE NOT NULL,
			password_hash TEXT NOT NULL,
			permissions BIGINT NOT NULL DEFAULT 0,
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

	// Create API keys table
	logging.DB.Debug("Creating api_keys table if not exists")
	_, err = p.db.Exec(`
		CREATE TABLE IF NOT EXISTS api_keys (
			id SERIAL PRIMARY KEY,
			user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
			key TEXT UNIQUE NOT NULL,
			key_hash TEXT,
			description TEXT,
			last_used TIMESTAMP,
			expires_at TIMESTAMP,
			created_at TIMESTAMP NOT NULL
		)
	`)
	if err != nil {
		logging.DB.WithFields(
			"error", err.Error(),
		).Error("Failed to create api_keys table")
		return err
	}

	_, err = p.db.Exec(`ALTER TABLE api_keys ADD COLUMN IF NOT EXISTS key_hash TEXT`)
	if err != nil {
		logging.DB.WithFields(
			"error", err.Error(),
		).Error("Failed to add key_hash column to api_keys")
		return err
	}

	// Create Minecraft servers table
	_, err = p.db.Exec(`
    CREATE TABLE IF NOT EXISTS minecraft_servers (
        id SERIAL PRIMARY KEY,
        server_name TEXT UNIQUE NOT NULL,
        deployment_name TEXT NOT NULL,
        pvc_name TEXT NOT NULL,
        owner_id INTEGER NOT NULL REFERENCES users(id),
        status TEXT NOT NULL,
        created_at TIMESTAMP NOT NULL,
        updated_at TIMESTAMP NOT NULL
    )
`)
	if err != nil {
		logging.DB.WithFields(
			"error", err.Error(),
		).Error("Failed to create minecraft_servers table")
		return fmt.Errorf("failed to create minecraft_servers table: %w", err)
	}

	_, err = p.db.Exec(`
		CREATE TABLE IF NOT EXISTS rate_limits (
			key TEXT PRIMARY KEY,
			tokens DOUBLE PRECISION NOT NULL,
			last_refill TIMESTAMPTZ NOT NULL
		)
	`)
	if err != nil {
		logging.DB.WithFields(
			"error", err.Error(),
		).Error("Failed to create rate_limits table")
		return fmt.Errorf("failed to create rate_limits table: %w", err)
	}

	// Check if we need to create an admin user
	logging.DB.Debug("Checking if admin user needs to be created")
	var count int
	err = p.db.QueryRow("SELECT COUNT(*) FROM users").Scan(&count)
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
		_, err = p.db.Exec(
			"INSERT INTO users (username, email, password_hash, permissions, active, created_at, updated_at) VALUES ($1, $2, $3, $4, $5, $6, $7)",
			"admin",
			"admin@example.com",
			"$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy", // password: admin
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

	logging.DB.Info("PostgreSQL database schema initialized successfully")
	return nil
}

// Close closes the database connection
func (p *PostgresDB) Close() error {
	logging.DB.Info("Closing PostgreSQL database connection")
	err := p.db.Close()
	if err != nil {
		logging.DB.WithFields(
			"error", err.Error(),
		).Error("Error closing PostgreSQL database connection")
		return err
	}
	logging.DB.Debug("PostgreSQL database connection closed successfully")
	return nil
}

// User operations

// CreateUser creates a new user
func (p *PostgresDB) CreateUser(ctx context.Context, user *User) error {
	logging.DB.WithFields(
		"username", user.Username,
		"email", user.Email,
	).Info("Creating new user in PostgreSQL")

	// Check if user already exists
	var exists bool
	err := p.db.QueryRowContext(ctx,
		"SELECT EXISTS(SELECT 1 FROM users WHERE username = $1 OR email = $2)",
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
	err = p.db.QueryRowContext(ctx,
		"INSERT INTO users (username, email, password_hash, permissions, active, created_at, updated_at) VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING id",
		user.Username, user.Email, user.PasswordHash, user.Permissions, user.Active, user.CreatedAt, user.UpdatedAt,
	).Scan(&user.ID)
	if err != nil {
		logging.DB.WithFields(
			"username", user.Username,
			"email", user.Email,
			"error", err.Error(),
		).Error("Failed to insert new user")
		return err
	}

	logging.DB.WithFields(
		"username", user.Username,
		"email", user.Email,
		"user_id", user.ID,
	).Info("User created successfully in PostgreSQL")
	return nil
}

// GetUserByID retrieves a user by ID
func (p *PostgresDB) GetUserByID(ctx context.Context, id int64) (*User, error) {
	logging.DB.WithFields(
		"user_id", id,
		"db_type", "postgres",
	).Debug("Getting user by ID")

	user := &User{}
	err := p.db.QueryRowContext(ctx,
		"SELECT id, username, email, password_hash, permissions, active, last_login, created_at, updated_at FROM users WHERE id = $1",
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
func (p *PostgresDB) GetUserByUsername(ctx context.Context, username string) (*User, error) {
	logging.DB.WithFields(
		"username", username,
		"db_type", "postgres",
	).Debug("Getting user by username")

	user := &User{}
	query := "SELECT id, username, email, password_hash, permissions, active, last_login, created_at, updated_at FROM users WHERE username = $1"

	logging.DB.WithFields(
		"username", username,
		"query", query,
	).Debug("Executing database query")

	err := p.db.QueryRowContext(ctx, query, username).Scan(
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
func (p *PostgresDB) UpdateUser(ctx context.Context, user *User) error {
	logging.DB.WithFields(
		"user_id", user.ID,
		"username", user.Username,
	).Info("Updating user information in PostgreSQL")

	user.UpdatedAt = time.Now()

	_, err := p.db.ExecContext(ctx,
		"UPDATE users SET username = $1, email = $2, password_hash = $3, permissions = $4, active = $5, updated_at = $6 WHERE id = $7",
		user.Username, user.Email, user.PasswordHash, user.Permissions, user.Active, user.UpdatedAt, user.ID,
	)
	if err != nil {
		if isPostgresUniqueError(err) {
			return ErrDuplicate
		}
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

func isPostgresUniqueError(err error) bool {
	var pqErr *pq.Error
	if errors.As(err, &pqErr) {
		return pqErr.Code == "23505"
	}
	return false
}

func (p *PostgresDB) AllowRateLimit(ctx context.Context, key string, capacity float64, refillInterval time.Duration, now time.Time) (bool, time.Duration, error) {
	tx, err := p.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return false, 0, err
	}

	var tokens float64
	var lastRefill time.Time
	row := tx.QueryRowContext(ctx, "SELECT tokens, last_refill FROM rate_limits WHERE key = $1 FOR UPDATE", key)
	if err := row.Scan(&tokens, &lastRefill); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			tokens = capacity
			lastRefill = now
		} else {
			tx.Rollback()
			return false, 0, err
		}
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
		"INSERT INTO rate_limits(key, tokens, last_refill) VALUES ($1, $2, $3) ON CONFLICT(key) DO UPDATE SET tokens = EXCLUDED.tokens, last_refill = EXCLUDED.last_refill",
		key, tokens, now,
	)
	if err != nil {
		tx.Rollback()
		return false, 0, err
	}

	if err := tx.Commit(); err != nil {
		return false, 0, err
	}

	return allowed, retryAfter, nil
}

func (p *PostgresDB) CleanupRateLimits(ctx context.Context, cutoff time.Time) error {
	_, err := p.db.ExecContext(ctx, "DELETE FROM rate_limits WHERE last_refill < $1", cutoff)
	return err
}

// DeleteUser deletes a user by ID
func (p *PostgresDB) DeleteUser(ctx context.Context, id int64) error {
	logging.DB.WithFields(
		"user_id", id,
	).Info("Deleting user from PostgreSQL")

	_, err := p.db.ExecContext(ctx, "DELETE FROM users WHERE id = $1", id)
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
func (p *PostgresDB) ListUsers(ctx context.Context) ([]*User, error) {
	logging.DB.Debug("Listing all users from PostgreSQL")

	rows, err := p.db.QueryContext(ctx,
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
	).Debug("Successfully retrieved user list from PostgreSQL")
	return users, nil
}

// API Key operations

// CreateAPIKey creates a new API key
func (p *PostgresDB) CreateAPIKey(ctx context.Context, key *APIKey) error {
	logging.DB.WithFields(
		"user_id", key.UserID,
		"description", key.Description,
	).Info("Creating new API key in PostgreSQL")

	now := time.Now()
	key.CreatedAt = now

	err := p.db.QueryRowContext(ctx,
		"INSERT INTO api_keys (user_id, key, key_hash, description, expires_at, created_at) VALUES ($1, $2, $3, $4, $5, $6) RETURNING id",
		key.UserID, key.KeyID, key.KeyHash, key.Description, key.ExpiresAt, key.CreatedAt,
	).Scan(&key.ID)
	if err != nil {
		logging.DB.WithFields(
			"user_id", key.UserID,
			"error", err.Error(),
		).Error("Failed to insert API key")
		return err
	}

	logging.DB.WithFields(
		"user_id", key.UserID,
		"key_id", key.ID,
	).Info("API key created successfully in PostgreSQL")
	return nil
}

// GetAPIKey retrieves an API key by the key string
func (p *PostgresDB) GetAPIKey(ctx context.Context, keyStr string) (*APIKey, error) {
	maskedKey := maskKeyForLog(keyStr)
	logging.DB.WithFields(
		"key", maskedKey,
	).Debug("Looking up API key in PostgreSQL")

	keyID := extractAPIKeyID(keyStr)
	key := &APIKey{}
	err := p.db.QueryRowContext(ctx,
		"SELECT id, user_id, key, key_hash, description, last_used, expires_at, created_at FROM api_keys WHERE key = $1",
		keyID,
	).Scan(
		&key.ID, &key.UserID, &key.KeyID, &key.KeyHash, &key.Description, &key.LastUsed, &key.ExpiresAt, &key.CreatedAt,
	)
	if err == sql.ErrNoRows {
		err = p.db.QueryRowContext(ctx,
			"SELECT id, user_id, key, key_hash, description, last_used, expires_at, created_at FROM api_keys WHERE key = $1",
			keyStr,
		).Scan(
			&key.ID, &key.UserID, &key.KeyID, &key.KeyHash, &key.Description, &key.LastUsed, &key.ExpiresAt, &key.CreatedAt,
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
			).Error("Database error when retrieving legacy API key")
			return nil, err
		}
	}
	if err != nil {
		return nil, err
	}

	if key.KeyHash == "" {
		if key.KeyID != keyStr {
			logging.DB.WithFields(
				"key", maskedKey,
				"error", "plaintext mismatch",
			).Warn("Legacy API key did not match provided value")
			return nil, ErrInvalidAPIKey
		}
		hashed, hashErr := auth.HashAPIKey(keyStr)
		if hashErr == nil {
			_, updErr := p.db.ExecContext(ctx,
				"UPDATE api_keys SET key = $1, key_hash = $2 WHERE id = $3",
				keyID, hashed, key.ID,
			)
			if updErr == nil {
				key.KeyID = keyID
				key.KeyHash = hashed
			}
		}
	} else {
		if err := auth.VerifyAPIKey(key.KeyHash, keyStr); err != nil {
			logging.DB.WithFields(
				"key", maskedKey,
			).Warn("API key hash mismatch")
			return nil, ErrInvalidAPIKey
		}
		key.KeyID = keyID
	}

	now := time.Now()
	key.LastUsed = now
	_, err = p.db.ExecContext(ctx, "UPDATE api_keys SET last_used = $1 WHERE id = $2", now, key.ID)
	if err != nil {
		logging.DB.WithFields(
			"key_id", key.ID,
			"error", err.Error(),
		).Error("Failed to update API key last used time")
		return nil, err
	}

	if !key.ExpiresAt.IsZero() && key.ExpiresAt.Before(now) {
		logging.DB.WithFields(
			"key_id", key.ID,
			"user_id", key.UserID,
			"expired_at", key.ExpiresAt,
		).Warn("Attempted to use expired API key")
		return nil, ErrInvalidAPIKey
	}

	return key, nil
}

// DeleteAPIKey deletes an API key by ID
func (p *PostgresDB) DeleteAPIKey(ctx context.Context, id int64) error {
	logging.DB.WithFields(
		"key_id", id,
	).Info("Deleting API key from PostgreSQL")

	_, err := p.db.ExecContext(ctx, "DELETE FROM api_keys WHERE id = $1", id)
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
func (p *PostgresDB) ListAPIKeysByUser(ctx context.Context, userID int64) ([]*APIKey, error) {
	logging.DB.WithFields(
		"user_id", userID,
	).Debug("Listing API keys for user from PostgreSQL")

	rows, err := p.db.QueryContext(ctx,
		"SELECT id, user_id, key, key_hash, description, last_used, expires_at, created_at FROM api_keys WHERE user_id = $1",
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
			&key.ID, &key.UserID, &key.KeyID, &key.KeyHash, &key.Description, &key.LastUsed, &key.ExpiresAt, &key.CreatedAt,
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
	).Debug("Successfully retrieved API keys from PostgreSQL")
	return keys, nil
}

// CreateServerRecord creates a new Minecraft server record
func (p *PostgresDB) CreateServerRecord(ctx context.Context, server *MinecraftServer) error {
	query := `INSERT INTO minecraft_servers
              (server_name, deployment_name, pvc_name, owner_id, status, created_at, updated_at)
              VALUES ($1, $2, $3, $4, $5, $6, $7)
              RETURNING id`

	now := time.Now()
	server.CreatedAt = now
	server.UpdatedAt = now

	err := p.db.QueryRowContext(ctx, query,
		server.ServerName,
		server.DeploymentName,
		server.PVCName,
		server.OwnerID,
		server.Status,
		server.CreatedAt,
		server.UpdatedAt,
	).Scan(&server.ID)

	if err != nil {
		logging.DB.WithFields(
			"server_name", server.ServerName,
			"error", err.Error(),
		).Error("Failed to create server record")
		return fmt.Errorf("failed to create server record: %w", err)
	}

	logging.DB.WithFields(
		"server_name", server.ServerName,
		"server_id", server.ID,
	).Info("Server record created successfully")
	return nil
}

// GetServerByName gets a Minecraft server by its name
func (p *PostgresDB) GetServerByName(ctx context.Context, serverName string) (*MinecraftServer, error) {
	query := `SELECT id, server_name, deployment_name, pvc_name, owner_id,
              status, created_at, updated_at
              FROM minecraft_servers WHERE server_name = $1`

	var server MinecraftServer
	err := p.db.QueryRowContext(ctx, query, serverName).Scan(
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
		).Warn("Server not found")
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
	).Info("Server retrieved successfully")
	return &server, nil
}

func (p *PostgresDB) GetServerForOwner(ctx context.Context, ownerID int64, serverName string) (*MinecraftServer, error) {
	logging.DB.WithFields(
		"owner_id", ownerID,
		"server_name", serverName,
	).Debug("Getting server by owner and name")

	query := `SELECT id, server_name, deployment_name, pvc_name, owner_id,
              status, created_at, updated_at
              FROM minecraft_servers WHERE owner_id = $1 AND server_name = $2`

	var server MinecraftServer
	err := p.db.QueryRowContext(ctx, query, ownerID, serverName).Scan(
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
			"owner_id", ownerID,
			"server_name", serverName,
		).Debug("Owner does not own requested server")
		return nil, ErrServerNotFound
	}

	if err != nil {
		logging.DB.WithFields(
			"owner_id", ownerID,
			"server_name", serverName,
			"error", err.Error(),
		).Error("Failed to get server for owner")
		return nil, fmt.Errorf("failed to get server: %w", err)
	}

	logging.DB.WithFields(
		"owner_id", ownerID,
		"server_name", serverName,
		"server_id", server.ID,
	).Debug("Server found for owner")
	return &server, nil
}

// GetServerByID retrieves a Minecraft server record by its ID.
func (p *PostgresDB) GetServerByID(ctx context.Context, serverID int64) (*MinecraftServer, error) {
	query := `SELECT id, server_name, deployment_name, pvc_name, owner_id,
              status, created_at, updated_at
              FROM minecraft_servers WHERE id = $1`

	var server MinecraftServer
	err := p.db.QueryRowContext(ctx, query, serverID).Scan(
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
		).Warn("Server not found by ID")
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
	).Info("Server retrieved successfully by ID")
	return &server, nil
}

// ListServersByOwner list all Minecraft servers by owner ID
func (p *PostgresDB) ListServersByOwner(ctx context.Context, ownerID int64) ([]*MinecraftServer, error) {
	query := `SELECT id, server_name, deployment_name, pvc_name, owner_id,
              status, created_at, updated_at
              FROM minecraft_servers WHERE owner_id = $1`

	rows, err := p.db.QueryContext(ctx, query, ownerID)
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
		"count", len(servers),
	).Info("Servers listed successfully")
	return servers, nil
}

// UpdateServerStatus updates the status of a Minecraft server
func (p *PostgresDB) UpdateServerStatus(ctx context.Context, serverName string, status string) error {
	query := `UPDATE minecraft_servers SET status = $1, updated_at = $2 WHERE server_name = $3`

	now := time.Now()
	_, err := p.db.ExecContext(ctx, query, status, now, serverName)
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

// DeleteServerRecord deletes a Minecraft server record
func (p *PostgresDB) DeleteServerRecord(ctx context.Context, serverName string) error {
	query := `DELETE FROM minecraft_servers WHERE server_name = $1`

	_, err := p.db.ExecContext(ctx, query, serverName)
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
