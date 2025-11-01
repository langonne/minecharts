package handlers

import (
	"errors"
	"fmt"
	"net/http"
	"net/mail"
	"strconv"
	"strings"
	"unicode"

	"minecharts/cmd/auth"
	"minecharts/cmd/database"
	"minecharts/cmd/logging"

	"github.com/gin-gonic/gin"
)

// PasswordUpdateRequest models a password change payload.
type PasswordUpdateRequest struct {
	Current string `json:"current" example:"oldPassword123!"`
	New     string `json:"new" example:"NewStrongPassword123!"`
	Confirm string `json:"confirm" example:"NewStrongPassword123!"`
}

// UpdateUserRequest represents a request to update user information.
// All fields are optional to allow partial updates.
type UpdateUserRequest struct {
	Username    *string                `json:"username" example:"newusername"`
	Email       *string                `json:"email" example:"new@example.com"`
	Password    *PasswordUpdateRequest `json:"password"`
	Permissions *int64                 `json:"permissions" example:"143"` // Bit flags for permissions
	Active      *bool                  `json:"active" example:"true"`
}

// PermissionAction represents a single permission action.
type PermissionAction struct {
	Permission int64  `json:"permission" binding:"required" example:"128"`
	Name       string `json:"name" example:"PermViewServer"` // Optional, for readability
}

// ModifyPermissionsRequest represents a request to modify user permissions.
type ModifyPermissionsRequest struct {
	Permissions []PermissionAction `json:"permissions" binding:"required"`
}

// ListUsersHandler returns a list of all users (admin only).

func ListUsersHandler(c *gin.Context) {
	// Get current admin user for logging
	adminUser, _ := auth.GetCurrentUser(c)

	logging.Auth.WithFields(
		"admin_user_id", adminUser.ID,
		"username", adminUser.Username,
		"remote_ip", c.ClientIP(),
	).Info("Admin requesting list of all users")

	db := database.GetDB()
	users, err := db.ListUsers(c.Request.Context())
	if err != nil {
		logging.DB.WithFields(
			"admin_user_id", adminUser.ID,
			"error", err.Error(),
		).Error("Failed to list users from database")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to list users"})
		return
	}

	logging.Auth.WithFields(
		"admin_user_id", adminUser.ID,
		"user_count", len(users),
	).Debug("Successfully retrieved user list")

	// Convert to a safer format without password hashes
	response := make([]gin.H, len(users))
	for i, user := range users {
		response[i] = gin.H{
			"id":          user.ID,
			"username":    user.Username,
			"email":       user.Email,
			"permissions": user.Permissions,
			"active":      user.Active,
			"last_login":  user.LastLogin,
			"created_at":  user.CreatedAt,
			"updated_at":  user.UpdatedAt,
		}
	}

	c.JSON(http.StatusOK, response)
}

// GetUserHandler returns details for a specific user.

func GetUserHandler(c *gin.Context) {
	// Get current user
	currentUser, ok := auth.GetCurrentUser(c)
	if !ok {
		logging.API.InvalidRequest.WithFields(
			"path", c.Request.URL.Path,
			"remote_ip", c.ClientIP(),
			"error", "not_authenticated",
		).Warn("Get user details failed: user not authenticated")
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Authentication required"})
		return
	}

	// Get user ID from URL parameter
	idStr := c.Param("id")
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		logging.API.InvalidRequest.WithFields(
			"current_user_id", currentUser.ID,
			"username", currentUser.Username,
			"requested_id", idStr,
			"remote_ip", c.ClientIP(),
			"error", "invalid_id_format",
		).Warn("Get user details failed: invalid user ID format")
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid user ID"})
		return
	}

	logging.Auth.Session.WithFields(
		"current_user_id", currentUser.ID,
		"username", currentUser.Username,
		"requested_user_id", id,
		"remote_ip", c.ClientIP(),
	).Debug("User details requested")

	// Users can only view their own details unless they're an admin
	if !currentUser.IsAdmin() && currentUser.ID != id {
		logging.Auth.Session.WithFields(
			"current_user_id", currentUser.ID,
			"username", currentUser.Username,
			"requested_user_id", id,
			"remote_ip", c.ClientIP(),
			"error", "permission_denied",
		).Warn("Get user details failed: non-admin attempting to access another user's details")
		c.JSON(http.StatusForbidden, gin.H{"error": "Permission denied"})
		return
	}

	// Get user from database
	db := database.GetDB()
	user, err := db.GetUserByID(c.Request.Context(), id)
	if err != nil {
		if err == database.ErrUserNotFound {
			logging.Auth.Session.WithFields(
				"current_user_id", currentUser.ID,
				"username", currentUser.Username,
				"requested_user_id", id,
				"error", "user_not_found",
			).Warn("Get user details failed: user not found")
			c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
			return
		}
		logging.DB.WithFields(
			"current_user_id", currentUser.ID,
			"username", currentUser.Username,
			"requested_user_id", id,
			"error", err.Error(),
		).Error("Get user details failed: database error")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get user"})
		return
	}

	logging.Auth.Session.WithFields(
		"current_user_id", currentUser.ID,
		"username", currentUser.Username,
		"requested_user_id", id,
		"requested_username", user.Username,
	).Debug("User details retrieved successfully")

	c.JSON(http.StatusOK, gin.H{
		"id":          user.ID,
		"username":    user.Username,
		"email":       user.Email,
		"permissions": user.Permissions,
		"active":      user.Active,
		"last_login":  user.LastLogin,
		"created_at":  user.CreatedAt,
		"updated_at":  user.UpdatedAt,
	})
}

// UpdateUserHandler updates a user's information.

func UpdateUserHandler(c *gin.Context) {
	// Get current user
	currentUser, ok := auth.GetCurrentUser(c)
	if !ok {
		logging.API.InvalidRequest.WithFields(
			"path", c.Request.URL.Path,
			"remote_ip", c.ClientIP(),
			"error", "not_authenticated",
		).Warn("Update user failed: user not authenticated")
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Authentication required"})
		return
	}

	// Get user ID from URL parameter
	idStr := c.Param("id")
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		logging.API.InvalidRequest.WithFields(
			"current_user_id", currentUser.ID,
			"username", currentUser.Username,
			"requested_id", idStr,
			"remote_ip", c.ClientIP(),
			"error", "invalid_id_format",
		).Warn("Update user failed: invalid user ID format")
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid user ID"})
		return
	}

	logging.Auth.WithFields(
		"current_user_id", currentUser.ID,
		"username", currentUser.Username,
		"target_user_id", id,
		"remote_ip", c.ClientIP(),
	).Info("User update requested")

	// Users can only update their own details unless they're an admin
	isAdmin := currentUser.IsAdmin()
	isSelf := currentUser.ID == id

	if !isAdmin && !isSelf {
		logging.Auth.WithFields(
			"current_user_id", currentUser.ID,
			"username", currentUser.Username,
			"target_user_id", id,
			"remote_ip", c.ClientIP(),
			"error", "permission_denied",
		).Warn("Update user failed: non-admin attempting to update another user")
		c.JSON(http.StatusForbidden, gin.H{"error": "Permission denied"})
		return
	}

	// Get user from database
	db := database.GetDB()
	user, err := db.GetUserByID(c.Request.Context(), id)
	if err != nil {
		if err == database.ErrUserNotFound {
			logging.Auth.WithFields(
				"current_user_id", currentUser.ID,
				"username", currentUser.Username,
				"target_user_id", id,
				"error", "user_not_found",
			).Warn("Update user failed: target user not found")
			c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
			return
		}
		logging.DB.WithFields(
			"current_user_id", currentUser.ID,
			"username", currentUser.Username,
			"target_user_id", id,
			"error", err.Error(),
		).Error("Update user failed: database error when retrieving user")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get user"})
		return
	}

	// Parse update request
	var req UpdateUserRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		logging.API.InvalidRequest.WithFields(
			"current_user_id", currentUser.ID,
			"username", currentUser.Username,
			"target_user_id", id,
			"error", err.Error(),
		).Warn("Update user failed: invalid request format")
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if req.Username == nil && req.Email == nil && req.Password == nil && req.Permissions == nil && req.Active == nil {
		logging.API.InvalidRequest.WithFields(
			"current_user_id", currentUser.ID,
			"username", currentUser.Username,
			"target_user_id", id,
		).Warn("Update user failed: empty payload")
		c.JSON(http.StatusBadRequest, gin.H{"error": "No fields provided"})
		return
	}

	updateFields := make([]string, 0)

	if req.Username != nil {
		candidate := strings.TrimSpace(*req.Username)
		if candidate == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Username cannot be blank"})
			return
		}
		if err := validateUsername(candidate); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		if candidate != user.Username {
			user.Username = candidate
			updateFields = append(updateFields, "username")
		}
	}

	if req.Email != nil {
		email := strings.TrimSpace(*req.Email)
		if email == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Email cannot be blank"})
			return
		}
		if _, err := mail.ParseAddress(email); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid email address"})
			return
		}
		if email != user.Email {
			user.Email = email
			updateFields = append(updateFields, "email")
		}
	}

	if req.Password != nil {
		// Only admins or the user themselves can change passwords
		if !isAdmin && !isSelf {
			logging.Auth.WithFields(
				"current_user_id", currentUser.ID,
				"username", currentUser.Username,
				"target_user_id", id,
				"error", "permission_denied",
			).Warn("Update user failed: attempt to change password without permission")
			c.JSON(http.StatusForbidden, gin.H{"error": "Permission denied"})
			return
		}

		if req.Password.New == "" || req.Password.Confirm == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "New password and confirmation are required"})
			return
		}
		if req.Password.New != req.Password.Confirm {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Password confirmation does not match"})
			return
		}
		if err := validatePasswordStrength(req.Password.New); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		if isSelf {
			if req.Password.Current == "" {
				c.JSON(http.StatusBadRequest, gin.H{"error": "Current password is required"})
				return
			}
			if err := auth.VerifyPassword(user.PasswordHash, req.Password.Current); err != nil {
				logging.Auth.Password.WithFields(
					"user_id", currentUser.ID,
				).Warn("Password update failed: current password mismatch")
				c.JSON(http.StatusUnauthorized, gin.H{"error": "Current password is incorrect"})
				return
			}
		} else if req.Password.Current != "" {
			if err := auth.VerifyPassword(user.PasswordHash, req.Password.Current); err != nil {
				logging.Auth.Password.WithFields(
					"actor_user_id", currentUser.ID,
					"target_user_id", user.ID,
				).Warn("Password update failed: provided current password mismatch")
				c.JSON(http.StatusUnauthorized, gin.H{"error": "Current password is incorrect"})
				return
			}
		}

		passwordHash, err := auth.HashPassword(req.Password.New)
		if err != nil {
			logging.Auth.WithFields(
				"current_user_id", currentUser.ID,
				"username", currentUser.Username,
				"target_user_id", id,
				"error", err.Error(),
			).Error("Update user failed: password hashing error")
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to hash password"})
			return
		}
		user.PasswordHash = passwordHash
		updateFields = append(updateFields, "password")

		logEntry := logging.Auth.Password.WithFields(
			"actor_user_id", currentUser.ID,
			"actor_username", currentUser.Username,
			"target_user_id", user.ID,
			"target_username", user.Username,
			"remote_ip", c.ClientIP(),
		)
		if isSelf {
			logEntry.Info("User updated own password")
		} else {
			logEntry.Warn("Administrator updated user password")
		}
	}

	if req.Permissions != nil {
		// Only admins can change permissions
		if !isAdmin {
			logging.Auth.WithFields(
				"current_user_id", currentUser.ID,
				"username", currentUser.Username,
				"target_user_id", id,
				"error", "permission_denied",
			).Warn("Update user failed: non-admin attempting to change permissions")
			c.JSON(http.StatusForbidden, gin.H{"error": "Only administrators can modify permissions"})
			return
		}
		if user.Permissions != *req.Permissions {
			updateFields = append(updateFields, "permissions")
			user.Permissions = *req.Permissions
		}
	}

	if req.Active != nil {
		// Only admins can change active status
		if !isAdmin {
			logging.Auth.WithFields(
				"current_user_id", currentUser.ID,
				"username", currentUser.Username,
				"target_user_id", id,
				"error", "permission_denied",
			).Warn("Update user failed: non-admin attempting to change account status")
			c.JSON(http.StatusForbidden, gin.H{"error": "Only administrators can change account status"})
			return
		}
		if user.Active != *req.Active {
			updateFields = append(updateFields, "active")
			user.Active = *req.Active
		}
	}

	if len(updateFields) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "No changes detected"})
		return
	}

	logging.Auth.WithFields(
		"current_user_id", currentUser.ID,
		"username", currentUser.Username,
		"target_user_id", id,
		"target_username", user.Username,
		"updated_fields", updateFields,
	).Debug("Applying user updates")

	// Update user in database
	if err := db.UpdateUser(c.Request.Context(), user); err != nil {
		if errors.Is(err, database.ErrDuplicate) {
			c.JSON(http.StatusConflict, gin.H{"error": "Username or email already in use"})
			return
		}
		logging.DB.WithFields(
			"current_user_id", currentUser.ID,
			"username", currentUser.Username,
			"target_user_id", id,
			"error", err.Error(),
		).Error("Update user failed: database error when saving updates")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update user"})
		return
	}

	logging.Auth.WithFields(
		"current_user_id", currentUser.ID,
		"username", currentUser.Username,
		"target_user_id", id,
		"target_username", user.Username,
		"updated_fields", updateFields,
	).Info("User updated successfully")

	c.JSON(http.StatusOK, gin.H{
		"id":          user.ID,
		"username":    user.Username,
		"email":       user.Email,
		"permissions": user.Permissions,
		"active":      user.Active,
		"last_login":  user.LastLogin,
		"updated_at":  user.UpdatedAt,
	})
}

// DeleteUserHandler removes a user account; only administrators may invoke it.
func DeleteUserHandler(c *gin.Context) {
	// Get current admin user for logging
	adminUser, _ := auth.GetCurrentUser(c)

	// Get user ID from URL parameter
	idStr := c.Param("id")
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		logging.API.InvalidRequest.WithFields(
			"admin_user_id", adminUser.ID,
			"user_id_param", idStr,
			"error", "invalid_id_format",
		).Warn("Invalid user ID format in delete request")
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid user ID"})
		return
	}

	logging.Auth.WithFields(
		"admin_user_id", adminUser.ID,
		"username", adminUser.Username,
		"target_user_id", id,
		"remote_ip", c.ClientIP(),
	).Info("Admin attempting to delete user")

	// Don't allow admins to delete themselves
	if adminUser.ID == id {
		logging.Auth.WithFields(
			"admin_user_id", adminUser.ID,
			"error", "self_deletion_attempt",
		).Warn("Admin attempted to delete their own account")
		c.JSON(http.StatusBadRequest, gin.H{"error": "Cannot delete your own account"})
		return
	}

	// Delete user from database
	db := database.GetDB()
	if err := db.DeleteUser(c.Request.Context(), id); err != nil {
		if err == database.ErrUserNotFound {
			logging.Auth.WithFields(
				"admin_user_id", adminUser.ID,
				"target_user_id", id,
				"error", "user_not_found",
			).Warn("Deletion failed: user not found")
			c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
			return
		}
		logging.DB.WithFields(
			"admin_user_id", adminUser.ID,
			"target_user_id", id,
			"error", err.Error(),
		).Error("Database error when deleting user")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete user"})
		return
	}

	logging.Auth.WithFields(
		"admin_user_id", adminUser.ID,
		"username", adminUser.Username,
		"target_user_id", id,
	).Info("User deleted successfully")

	c.JSON(http.StatusOK, gin.H{"message": "User deleted"})
}

// GrantUserPermissionsHandler grants permissions to a user (admin only).

func GrantUserPermissionsHandler(c *gin.Context) {
	// Get admin user
	adminUser, _ := auth.GetCurrentUser(c)

	// Get user ID
	idStr := c.Param("id")
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		logging.API.InvalidRequest.WithFields(
			"admin_user_id", adminUser.ID,
			"requested_id", idStr,
			"error", "invalid_id_format",
		).Warn("Invalid user ID format in grant permissions request")
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid user ID"})
		return
	}

	// Parse request
	var req ModifyPermissionsRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		logging.API.InvalidRequest.WithFields(
			"admin_user_id", adminUser.ID,
			"target_user_id", id,
			"error", err.Error(),
		).Warn("Invalid permission grant request format")
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Get target user
	db := database.GetDB()
	user, err := db.GetUserByID(c.Request.Context(), id)
	if err != nil {
		if err == database.ErrUserNotFound {
			logging.Auth.WithFields(
				"admin_user_id", adminUser.ID,
				"target_user_id", id,
				"error", "user_not_found",
			).Warn("Permission grant failed: target user not found")
			c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
			return
		}
		logging.DB.WithFields(
			"admin_user_id", adminUser.ID,
			"target_user_id", id,
			"error", err.Error(),
		).Error("Database error when retrieving user for permission grant")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get user"})
		return
	}

	// Apply permissions
	oldPermissions := user.Permissions
	for _, perm := range req.Permissions {
		user.Permissions |= perm.Permission
	}

	// Save updated permissions
	if err := db.UpdateUser(c.Request.Context(), user); err != nil {
		logging.DB.WithFields(
			"admin_user_id", adminUser.ID,
			"target_user_id", id,
			"error", err.Error(),
		).Error("Database error when updating user permissions")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update user"})
		return
	}

	logging.Auth.WithFields(
		"admin_user_id", adminUser.ID,
		"admin_username", adminUser.Username,
		"target_user_id", id,
		"old_permissions", oldPermissions,
		"new_permissions", user.Permissions,
	).Info("User permissions updated successfully")

	c.JSON(http.StatusOK, gin.H{
		"user_id":         user.ID,
		"username":        user.Username,
		"old_permissions": oldPermissions,
		"new_permissions": user.Permissions,
	})
}

// RevokeUserPermissionsHandler revokes permissions from a user (admin only).

func RevokeUserPermissionsHandler(c *gin.Context) {
	// Get admin user
	adminUser, _ := auth.GetCurrentUser(c)

	// Get user ID
	idStr := c.Param("id")
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		logging.API.InvalidRequest.WithFields(
			"admin_user_id", adminUser.ID,
			"requested_id", idStr,
			"error", "invalid_id_format",
		).Warn("Invalid user ID format in revoke permissions request")
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid user ID"})
		return
	}

	// Parse request
	var req ModifyPermissionsRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		logging.API.InvalidRequest.WithFields(
			"admin_user_id", adminUser.ID,
			"target_user_id", id,
			"error", err.Error(),
		).Warn("Invalid permission revoke request format")
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Get target user
	db := database.GetDB()
	user, err := db.GetUserByID(c.Request.Context(), id)
	if err != nil {
		if err == database.ErrUserNotFound {
			logging.Auth.WithFields(
				"admin_user_id", adminUser.ID,
				"target_user_id", id,
				"error", "user_not_found",
			).Warn("Permission revoke failed: target user not found")
			c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
			return
		}
		logging.DB.WithFields(
			"admin_user_id", adminUser.ID,
			"target_user_id", id,
			"error", err.Error(),
		).Error("Database error when retrieving user for permission revoke")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get user"})
		return
	}

	// Revoke permissions
	oldPermissions := user.Permissions
	for _, perm := range req.Permissions {
		user.Permissions &= ^perm.Permission
	}

	// Save updated permissions
	if err := db.UpdateUser(c.Request.Context(), user); err != nil {
		logging.DB.WithFields(
			"admin_user_id", adminUser.ID,
			"target_user_id", id,
			"error", err.Error(),
		).Error("Database error when updating user permissions")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update user"})
		return
	}

	logging.Auth.WithFields(
		"admin_user_id", adminUser.ID,
		"admin_username", adminUser.Username,
		"target_user_id", id,
		"old_permissions", oldPermissions,
		"new_permissions", user.Permissions,
	).Info("User permissions revoked successfully")

	c.JSON(http.StatusOK, gin.H{
		"user_id":         user.ID,
		"username":        user.Username,
		"old_permissions": oldPermissions,
		"new_permissions": user.Permissions,
	})
}

// GetPermissionsMapHandler returns a mapping of permission values to their names.

func GetPermissionsMapHandler(c *gin.Context) {
	// Return a map of permission names to their values
	permissionsMap := map[string]int64{
		"PermAdmin":         database.PermAdmin,
		"PermCreateServer":  database.PermCreateServer,
		"PermDeleteServer":  database.PermDeleteServer,
		"PermStartServer":   database.PermStartServer,
		"PermStopServer":    database.PermStopServer,
		"PermRestartServer": database.PermRestartServer,
		"PermExecCommand":   database.PermExecCommand,
		"PermViewServer":    database.PermViewServer,
	}

	// Add permissions for database access
	permissionsMap["PermOperator"] = database.PermOperator
	permissionsMap["PermAll"] = database.PermAll
	permissionsMap["PermReadOnly"] = database.PermReadOnly

	c.JSON(http.StatusOK, permissionsMap)
}

func validateUsername(username string) error {
	if len(username) < 3 || len(username) > 32 {
		return fmt.Errorf("username must be between 3 and 32 characters")
	}
	for _, r := range username {
		switch {
		case unicode.IsLetter(r), unicode.IsDigit(r), r == '-', r == '_', r == '.':
			continue
		default:
			return fmt.Errorf("username contains invalid character: %q", r)
		}
	}
	return nil
}

func validatePasswordStrength(password string) error {
	if len(password) < 12 {
		return fmt.Errorf("password must be at least 12 characters long")
	}
	var hasUpper, hasLower, hasDigit, hasSymbol bool
	for _, r := range password {
		switch {
		case unicode.IsUpper(r):
			hasUpper = true
		case unicode.IsLower(r):
			hasLower = true
		case unicode.IsDigit(r):
			hasDigit = true
		case unicode.IsPunct(r), unicode.IsSymbol(r):
			hasSymbol = true
		}
	}
	if !(hasUpper && hasLower && hasDigit && hasSymbol) {
		return fmt.Errorf("password must include upper, lower, digit, and symbol characters")
	}
	return nil
}
