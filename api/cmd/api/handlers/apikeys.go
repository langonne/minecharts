package handlers

import (
	"net/http"
	"strconv"
	"strings"
	"time"

	"minecharts/cmd/auth"
	"minecharts/cmd/config"
	"minecharts/cmd/database"
	"minecharts/cmd/logging"

	"github.com/gin-gonic/gin"
)

// CreateAPIKeyRequest represents a request to create a new API key.
type CreateAPIKeyRequest struct {
	Description string    `json:"description" example:"Key for CI/CD pipeline"`
	ExpiresAt   time.Time `json:"expires_at" example:"2023-12-31T23:59:59Z"`
}

// CreateAPIKeyHandler creates a new API key for the authenticated user.

func CreateAPIKeyHandler(c *gin.Context) {
	user, ok := auth.GetCurrentUser(c)
	if !ok {
		logging.API.InvalidRequest.WithFields(
			"path", c.Request.URL.Path,
			"remote_ip", c.ClientIP(),
			"error", "not_authenticated",
		).Warn("API key creation failed: user not authenticated")
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Authentication required"})
		return
	}

	logging.API.Keys.WithFields(
		"user_id", user.ID,
		"username", user.Username,
		"remote_ip", c.ClientIP(),
	).Info("API key creation requested")

	var req CreateAPIKeyRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		logging.API.InvalidRequest.WithFields(
			"user_id", user.ID,
			"username", user.Username,
			"remote_ip", c.ClientIP(),
			"error", err.Error(),
		).Warn("API key creation failed: invalid request format")
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	db := database.GetDB()
	existingKeys, err := db.ListAPIKeysByUser(c.Request.Context(), user.ID)
	if err != nil {
		logging.DB.WithFields(
			"user_id", user.ID,
			"username", user.Username,
			"error", err.Error(),
		).Error("Failed to list API keys before creation")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create API key"})
		return
	}
	if len(existingKeys) >= config.MaxAPIKeysPerUser {
		logging.API.Keys.WithFields(
			"user_id", user.ID,
			"username", user.Username,
			"max_keys", config.MaxAPIKeysPerUser,
		).Warn("API key creation blocked: user reached limit")
		c.JSON(http.StatusBadRequest, gin.H{"error": "API key limit reached"})
		return
	}

	// Generate a new API key
	keyValue, err := auth.GenerateAPIKey(config.APIKeyPrefix)
	if err != nil {
		logging.API.Keys.WithFields(
			"user_id", user.ID,
			"username", user.Username,
			"error", err.Error(),
		).Error("Failed to generate API key")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate API key"})
		return
	}

	logging.API.Keys.Debug("API key generated successfully")

	keyID := extractAPIKeyID(keyValue)
	keyHash, err := auth.HashAPIKey(keyValue)
	if err != nil {
		logging.API.Keys.WithFields(
			"user_id", user.ID,
			"username", user.Username,
			"error", err.Error(),
		).Error("Failed to hash API key")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create API key"})
		return
	}

	// Create API key record
	apiKey := &database.APIKey{
		UserID:      user.ID,
		KeyID:       keyID,
		KeyHash:     keyHash,
		Description: req.Description,
	}
	if !req.ExpiresAt.IsZero() {
		apiKey.ExpiresAt = &req.ExpiresAt
	}

	if err := db.CreateAPIKey(c.Request.Context(), apiKey); err != nil {
		logging.DB.WithFields(
			"user_id", user.ID,
			"username", user.Username,
			"error", err.Error(),
		).Error("Failed to save API key to database")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create API key"})
		return
	}

	logging.API.Keys.WithFields(
		"user_id", user.ID,
		"username", user.Username,
		"api_key_id", apiKey.ID,
		"expires_at", apiKey.ExpiresAt,
	).Info("API key created successfully")

	c.JSON(http.StatusCreated, gin.H{
		"id":          apiKey.ID,
		"key":         keyValue, // This is the only time the full key will be shown
		"description": apiKey.Description,
		"expires_at":  apiKey.ExpiresAt,
		"created_at":  apiKey.CreatedAt,
	})
}

// ListAPIKeysHandler returns all API keys for the authenticated user.

func ListAPIKeysHandler(c *gin.Context) {
	user, ok := auth.GetCurrentUser(c)
	if !ok {
		logging.API.InvalidRequest.WithFields(
			"path", c.Request.URL.Path,
			"remote_ip", c.ClientIP(),
			"error", "not_authenticated",
		).Warn("API key listing failed: user not authenticated")
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Authentication required"})
		return
	}

	logging.API.Keys.WithFields(
		"user_id", user.ID,
		"username", user.Username,
		"remote_ip", c.ClientIP(),
	).Info("API key listing requested")

	db := database.GetDB()
	apiKeys, err := db.ListAPIKeysByUser(c.Request.Context(), user.ID)
	if err != nil {
		logging.DB.WithFields(
			"user_id", user.ID,
			"username", user.Username,
			"error", err.Error(),
		).Error("Failed to list API keys from database")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to list API keys"})
		return
	}

	// For security, only return partial key values
	response := make([]gin.H, len(apiKeys))
	for i, key := range apiKeys {
		// Create a masked version of the key (e.g., "mcapi.XXXX")
		maskedKey := maskAPIKeyForDisplay(key.KeyID)
		response[i] = gin.H{
			"id":          key.ID,
			"key":         maskedKey,
			"description": key.Description,
			"last_used":   key.LastUsed,
			"expires_at":  key.ExpiresAt,
			"created_at":  key.CreatedAt,
		}
	}

	logging.API.Keys.WithFields(
		"user_id", user.ID,
		"username", user.Username,
		"key_count", len(apiKeys),
	).Debug("API keys listed successfully")

	c.JSON(http.StatusOK, response)
}

// DeleteAPIKeyHandler deletes an API key.

func DeleteAPIKeyHandler(c *gin.Context) {
	user, ok := auth.GetCurrentUser(c)
	if !ok {
		logging.API.InvalidRequest.WithFields(
			"path", c.Request.URL.Path,
			"remote_ip", c.ClientIP(),
			"error", "not_authenticated",
		).Warn("API key deletion failed: user not authenticated")
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Authentication required"})
		return
	}

	// Get API key ID from URL parameter
	idStr := c.Param("id")
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		logging.API.InvalidRequest.WithFields(
			"user_id", user.ID,
			"username", user.Username,
			"key_id_param", idStr,
			"remote_ip", c.ClientIP(),
			"error", "invalid_id_format",
		).Warn("API key deletion failed: invalid ID format")
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid API key ID"})
		return
	}

	logging.API.Keys.WithFields(
		"user_id", user.ID,
		"username", user.Username,
		"api_key_id", id,
		"remote_ip", c.ClientIP(),
	).Info("API key deletion requested")

	// Verify the API key belongs to the user (unless admin)
	if !user.IsAdmin() {
		db := database.GetDB()
		keys, err := db.ListAPIKeysByUser(c.Request.Context(), user.ID)
		if err != nil {
			logging.DB.WithFields(
				"user_id", user.ID,
				"username", user.Username,
				"api_key_id", id,
				"error", err.Error(),
			).Error("Failed to verify API key ownership")
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to verify API key ownership"})
			return
		}

		found := false
		for _, key := range keys {
			if key.ID == id {
				found = true
				break
			}
		}

		if !found {
			logging.API.Keys.WithFields(
				"user_id", user.ID,
				"username", user.Username,
				"api_key_id", id,
				"remote_ip", c.ClientIP(),
				"error", "permission_denied",
			).Warn("API key deletion failed: user doesn't own this API key")
			c.JSON(http.StatusForbidden, gin.H{"error": "You do not own this API key"})
			return
		}
	}

	// Delete the API key
	db := database.GetDB()
	if err := db.DeleteAPIKey(c.Request.Context(), id); err != nil {
		logging.DB.WithFields(
			"user_id", user.ID,
			"username", user.Username,
			"api_key_id", id,
			"error", err.Error(),
		).Error("Failed to delete API key from database")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete API key"})
		return
	}

	logging.API.Keys.WithFields(
		"user_id", user.ID,
		"username", user.Username,
		"api_key_id", id,
		"remote_ip", c.ClientIP(),
	).Info("API key deleted successfully")

	c.JSON(http.StatusOK, gin.H{"message": "API key deleted"})
}

func extractAPIKeyID(fullKey string) string {
	if idx := strings.Index(fullKey, "."); idx >= 0 && idx < len(fullKey)-1 {
		return fullKey[idx+1:]
	}
	return fullKey
}

func maskAPIKeyForDisplay(stored string) string {
	if stored == "" {
		return "***"
	}
	if strings.Contains(stored, ".") {
		parts := strings.SplitN(stored, ".", 2)
		return parts[0] + "." + maskSegment(parts[1])
	}
	return config.APIKeyPrefix + "." + maskSegment(stored)
}

func maskSegment(token string) string {
	if len(token) <= 4 {
		return token
	}
	if len(token) <= 8 {
		return token[:2] + "..." + token[len(token)-2:]
	}
	return token[:4] + "..." + token[len(token)-4:]
}
