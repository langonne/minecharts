// Package database provides database access and models for the application.
//
// This package defines database interfaces, models, and implementations for
// various database backends like SQLite and PostgreSQL.
package database

import (
	"minecharts/cmd/logging"
	"time"
)

// Permission flags define the bit flags for user permissions.
const (
	PermAdmin         int64 = 1 << iota // Full administrator access
	PermCreateServer                    // Can create new servers
	PermDeleteServer                    // Can delete servers
	PermStartServer                     // Can start servers
	PermStopServer                      // Can stop servers
	PermRestartServer                   // Can restart servers
	PermExecCommand                     // Can execute commands on servers
	PermViewServer                      // Can view server details
)

// Common permissions groups provide pre-defined combinations of permissions.
var (
	// PermAll grants all permissions
	PermAll int64 = PermAdmin | PermCreateServer | PermDeleteServer | PermStartServer |
		PermStopServer | PermRestartServer | PermExecCommand | PermViewServer

	// PermReadOnly grants only view permissions
	PermReadOnly int64 = PermViewServer

	// PermOperator grants everything except admin permissions
	PermOperator int64 = PermCreateServer | PermDeleteServer | PermStartServer |
		PermStopServer | PermRestartServer | PermExecCommand | PermViewServer
)

// APIKey represents an API key for machine authentication.
type APIKey struct {
	ID          int64      `json:"id"`
	UserID      int64      `json:"user_id"`
	KeyID       string     `json:"-"`
	KeyHash     string     `json:"-"`
	Description string     `json:"description"`
	LastUsed    time.Time  `json:"last_used"`
	ExpiresAt   *time.Time `json:"expires_at,omitempty"` // Make this a pointer to allow null values
	CreatedAt   time.Time  `json:"created_at"`
}

// User represents a user in the system with their permissions and account details.
type User struct {
	ID           int64      `json:"id"`
	Username     string     `json:"username"`
	Email        string     `json:"email"`
	PasswordHash string     `json:"-"` // Never expose in JSON
	Permissions  int64      `json:"permissions"`
	Active       bool       `json:"active"`
	LastLogin    *time.Time `json:"last_login"`
	CreatedAt    time.Time  `json:"created_at"`
	UpdatedAt    time.Time  `json:"updated_at"`
}

// MinecraftServer represents a Minecraft server record
type MinecraftServer struct {
	ID             int64     `json:"id"`
	ServerName     string    `json:"server_name"`
	DeploymentName string    `json:"deployment_name"`
	PVCName        string    `json:"pvc_name"`
	OwnerID        int64     `json:"owner_id"`
	CreatedAt      time.Time `json:"created_at"`
	UpdatedAt      time.Time `json:"updated_at"`
	Status         string    `json:"status"`
}

// HasPermission checks if the user has the specified permission.
// It always returns true for administrators.
func (u *User) HasPermission(permission int64) bool {
	// Admin always has all permissions
	if u.Permissions&PermAdmin != 0 {
		logging.Auth.Session.WithFields(
			"user_id", u.ID,
			"username", u.Username,
			"permission", permission,
			"result", true,
		).Debug("Permission check passed: user is admin")
		return true
	}

	result := u.Permissions&permission != 0
	logging.Auth.Session.WithFields(
		"user_id", u.ID,
		"username", u.Username,
		"permission", permission,
		"user_permissions", u.Permissions,
		"result", result,
	).Debug("Permission check completed")
	return result
}

// IsAdmin checks if the user is an administrator.
func (u *User) IsAdmin() bool {
	result := u.HasPermission(PermAdmin)
	logging.Auth.Session.WithFields(
		"user_id", u.ID,
		"username", u.Username,
		"is_admin", result,
	).Debug("Admin check completed")
	return result
}

// HasServerPermission checks if the user has the specified permission for a specific server
// Returns true if any of the following are true:
// 1. User is an administrator
// 2. User is the owner of the server
// 3. User has the specific global permission
func (u *User) HasServerPermission(serverOwnerID int64, permission int64) bool {
	// Admin always has all permissions
	if u.Permissions&PermAdmin != 0 {
		logging.Auth.Session.WithFields(
			"user_id", u.ID,
			"username", u.Username,
			"permission", permission,
			"is_admin", true,
		).Debug("Server permission check passed: user is admin")
		return true
	}

	// Server owner has all permissions for their own server
	if u.ID == serverOwnerID {
		logging.Auth.Session.WithFields(
			"user_id", u.ID,
			"username", u.Username,
			"server_owner_id", serverOwnerID,
		).Debug("Server permission check passed: user is owner")
		return true
	}

	// Otherwise, check specific permission
	result := u.Permissions&permission != 0
	logging.Auth.Session.WithFields(
		"user_id", u.ID,
		"username", u.Username,
		"permission", permission,
		"user_permissions", u.Permissions,
		"result", result,
	).Debug("Server permission check completed")
	return result
}
