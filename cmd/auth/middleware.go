// Package auth provides authentication and authorization capabilities.
//
// This package handles JWT token generation and validation, API key authentication,
// password hashing and verification, and OAuth provider integration.
package auth

import (
	"context"
	"net/http"
	"time"

	"minecharts/cmd/database"
	"minecharts/cmd/logging"

	"github.com/gin-gonic/gin"
)

// AuthUserKey is the key used to store authenticated user in the Gin context.
const (
	AuthUserKey = "auth_user"
)

// JWTMiddleware validates JWT tokens in the Authorization header.
// It extracts the token from the Authorization header, validates it,
// and sets the authenticated user in the Gin context for downstream handlers.
func JWTMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Get Cookie
		cookie, err := c.Cookie("auth_token")
		if err != nil {
			logging.Auth.JWT.WithFields(
				"path", c.Request.URL.Path,
				"remote_ip", c.ClientIP(),
				"error", "missing_cookie",
			).Warn("Authentication failed: missing cookie")
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Authentication cookie is required"})
			return
		}

		// Validate token
		claims, err := ValidateJWT(cookie)
		if err != nil {
			if err == ErrExpiredToken {
				logging.Auth.JWT.WithFields(
					"path", c.Request.URL.Path,
					"remote_ip", c.ClientIP(),
					"error", "token_expired",
				).Warn("Authentication failed: token expired")
				c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Token has expired"})
				return
			}
			logging.Auth.JWT.WithFields(
				"path", c.Request.URL.Path,
				"remote_ip", c.ClientIP(),
				"error", "invalid_token",
				"error_details", err.Error(),
			).Warn("Authentication failed: invalid token")
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Invalid token"})
			return
		}

		logging.Auth.JWT.WithFields(
			"path", c.Request.URL.Path,
			"user_id", claims.UserID,
			"username", claims.Username,
		).Debug("JWT token validated successfully")

		// Get user from database to ensure they still exist and have the right permissions
		db := database.GetDB()
		user, err := db.GetUserByID(c.Request.Context(), claims.UserID)
		if err != nil {
			logging.Auth.JWT.WithFields(
				"path", c.Request.URL.Path,
				"user_id", claims.UserID,
				"error", "user_not_found",
				"error_details", err.Error(),
			).Warn("Authentication failed: user not found")
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "User not found"})
			return
		}

		// Check if user is active
		if !user.Active {
			logging.Auth.Session.WithFields(
				"path", c.Request.URL.Path,
				"user_id", user.ID,
				"username", user.Username,
				"error", "account_inactive",
			).Warn("Authentication failed: account inactive")
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "User account is inactive"})
			return
		}

		// Set user in context for handlers to use
		c.Set(AuthUserKey, user)

		logging.Auth.Session.WithFields(
			"path", c.Request.URL.Path,
			"user_id", user.ID,
			"username", user.Username,
			"remote_ip", c.ClientIP(),
		).Debug("User authenticated successfully via JWT")

		c.Next()
	}
}

// APIKeyMiddleware validates API key in the X-API-Key header.
// It attempts API key authentication if JWT authentication hasn't already succeeded.
func APIKeyMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Skip if JWT already authenticated
		if _, exists := c.Get(AuthUserKey); exists {
			c.Next()
			return
		}

		// Get API key from header
		apiKey := c.GetHeader("X-API-Key")
		if apiKey == "" {
			logging.API.InvalidRequest.WithFields(
				"path", c.Request.URL.Path,
				"remote_ip", c.ClientIP(),
				"error", "missing_api_key",
			).Warn("API key authentication failed: missing API key")
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "API key is required"})
			return
		}

		// Validate API key
		db := database.GetDB()
		key, err := db.GetAPIKey(c.Request.Context(), apiKey)
		if err != nil {
			logging.API.Keys.WithFields(
				"path", c.Request.URL.Path,
				"remote_ip", c.ClientIP(),
				"error", "invalid_api_key",
				"error_details", err.Error(),
			).Warn("API key authentication failed: invalid API key")
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Invalid API key"})
			return
		}

		logging.API.Keys.WithFields(
			"path", c.Request.URL.Path,
			"api_key_id", key.ID,
			"user_id", key.UserID,
		).Debug("API key validated")

		// Check if API key is expired
		if !key.ExpiresAt.IsZero() && key.ExpiresAt.Before(c.Request.Context().Value("now").(time.Time)) {
			logging.API.Keys.WithFields(
				"path", c.Request.URL.Path,
				"api_key_id", key.ID,
				"user_id", key.UserID,
				"error", "expired_api_key",
			).Warn("API key authentication failed: expired API key")
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "API key has expired"})
			return
		}

		// Get user associated with API key
		user, err := db.GetUserByID(c.Request.Context(), key.UserID)
		if err != nil {
			logging.DB.WithFields(
				"path", c.Request.URL.Path,
				"api_key_id", key.ID,
				"user_id", key.UserID,
				"error", "user_not_found",
				"error_details", err.Error(),
			).Warn("API key authentication failed: user not found")
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "User not found"})
			return
		}

		// Check if user is active
		if !user.Active {
			logging.Auth.Session.WithFields(
				"path", c.Request.URL.Path,
				"api_key_id", key.ID,
				"user_id", user.ID,
				"username", user.Username,
				"error", "account_inactive",
			).Warn("API key authentication failed: account inactive")
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "User account is inactive"})
			return
		}

		// Set user in context for handlers to use
		c.Set(AuthUserKey, user)

		logging.Auth.Session.WithFields(
			"path", c.Request.URL.Path,
			"api_key_id", key.ID,
			"user_id", user.ID,
			"username", user.Username,
			"remote_ip", c.ClientIP(),
		).Debug("User authenticated successfully via API key")

		c.Next()
	}
}

// RequestTimeMiddleware injects the current time into the request context.
// This is required for handlers that rely on the "now" context value.
func RequestTimeMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		ctx := context.WithValue(c.Request.Context(), "now", time.Now())
		c.Request = c.Request.WithContext(ctx)
		c.Next()
	}
}

// extractAuthenticatedUser extracts the user from the context and verifies authentication.
// Returns the user and a boolean indicating if the extraction was successful.
func extractAuthenticatedUser(c *gin.Context, permission int64) (*database.User, bool) {
	// Get user from context
	value, exists := c.Get(AuthUserKey)
	if !exists {
		logging.API.InvalidRequest.WithFields(
			"path", c.Request.URL.Path,
			"remote_ip", c.ClientIP(),
			"required_permission", permission,
			"error", "not_authenticated",
		).Warn("Permission check failed: user not authenticated")
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Authentication required"})
		return nil, false
	}

	user, ok := value.(*database.User)
	if !ok {
		logging.API.InvalidRequest.WithFields(
			"path", c.Request.URL.Path,
			"remote_ip", c.ClientIP(),
			"required_permission", permission,
			"error", "invalid_user_object",
		).Error("Permission check failed: invalid user object in context")
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "Invalid user object in context"})
		return nil, false
	}

	return user, true
}

// RequirePermission checks if the authenticated user has the required permission.
// It returns a 403 Forbidden response if the user doesn't have the required permission.
func RequirePermission(permission int64) gin.HandlerFunc {
	return func(c *gin.Context) {
		user, ok := extractAuthenticatedUser(c, permission)
		if !ok {
			return // extractAuthenticatedUser already handled error response
		}

		// Check permission
		if !user.HasPermission(permission) {
			logging.Auth.Session.WithFields(
				"path", c.Request.URL.Path,
				"user_id", user.ID,
				"username", user.Username,
				"remote_ip", c.ClientIP(),
				"required_permission", permission,
				"user_permissions", user.Permissions,
				"error", "permission_denied",
			).Warn("Permission check failed: insufficient permissions")
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "Permission denied"})
			return
		}

		logging.Auth.Session.WithFields(
			"path", c.Request.URL.Path,
			"user_id", user.ID,
			"username", user.Username,
			"required_permission", permission,
		).Debug("Permission check passed")

		c.Next()
	}
}

// RequireServerPermission checks if the user has permission for the specific server
func RequireServerPermission(permission int64) gin.HandlerFunc {
	return func(c *gin.Context) {
		user, ok := extractAuthenticatedUser(c, permission)
		if !ok {
			return // extractAuthenticatedUser already handled error response
		}

		// Get server name from URL parameter
		serverName := c.Param("serverName")
		if serverName == "" {
			// If no serverName, use standard permission check
			if !user.HasPermission(permission) {
				logging.Auth.Session.WithFields(
					"path", c.Request.URL.Path,
					"user_id", user.ID,
					"username", user.Username,
					"remote_ip", c.ClientIP(),
					"permission", permission,
					"error", "permission_denied",
				).Warn("Permission check failed: insufficient permissions")
				c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "Permission denied"})
				return
			}
			c.Next()
			return
		}

		// Get server info
		db := database.GetDB()
		server, err := db.GetServerByName(c.Request.Context(), serverName)
		if err != nil {
			// If server not found in DB but exists in K8s, default to standard permission check
			if !user.HasPermission(permission) {
				logging.Auth.Session.WithFields(
					"path", c.Request.URL.Path,
					"user_id", user.ID,
					"username", user.Username,
					"remote_ip", c.ClientIP(),
					"server_name", serverName,
					"error", "server_not_found_and_insufficient_permissions",
				).Warn("Permission check failed: server not found and insufficient permissions")
				c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "Permission denied"})
				return
			}
			c.Next()
			return
		}

		// Check permission with ownership logic
		if !user.HasServerPermission(server.OwnerID, permission) {
			logging.Auth.Session.WithFields(
				"path", c.Request.URL.Path,
				"user_id", user.ID,
				"username", user.Username,
				"remote_ip", c.ClientIP(),
				"server_name", serverName,
				"server_owner_id", server.OwnerID,
				"error", "insufficient_server_permissions",
			).Warn("Server permission check failed")
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "Permission denied"})
			return
		}

		c.Next()
	}
}

// GetCurrentUser retrieves the authenticated user from the Gin context.
// It returns the user object and a boolean indicating if the user was found.
func GetCurrentUser(c *gin.Context) (*database.User, bool) {
	value, exists := c.Get(AuthUserKey)
	if !exists {
		return nil, false
	}

	user, ok := value.(*database.User)
	return user, ok
}
