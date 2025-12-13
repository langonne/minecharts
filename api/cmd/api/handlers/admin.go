package handlers

import (
	"net/http"

	"minecharts/cmd/config"

	"github.com/gin-gonic/gin"
)

// ListAdminWarningsHandler exposes configuration warnings to administrators.
func ListAdminWarningsHandler(c *gin.Context) {
	if !config.WebAdminWarningsEnabled {
		c.JSON(http.StatusNotFound, gin.H{"error": "warnings feature disabled"})
		return
	}

	warnings := config.AdminWarnings()
	c.JSON(http.StatusOK, gin.H{
		"warnings": warnings,
	})
}
