// Package api provides routing and API endpoints for the application.
package api

import (
	"time"

	"minecharts/cmd/api/handlers"
	"minecharts/cmd/api/middleware"
	"minecharts/cmd/auth"
	"minecharts/cmd/database"

	"github.com/gin-gonic/gin"
)

// SetupRoutes registers all the API routes with their respective handlers.
// It defines the authentication middleware, permissions, and path grouping.
func SetupRoutes(router *gin.Engine) {
	loginLimiter := middleware.NewDBRateLimiter(5, time.Minute, 100, 30*time.Minute)
	registerLimiter := middleware.NewDBRateLimiter(2, 5*time.Minute, 100, 30*time.Minute)
	userPatchLimiter := middleware.NewDBRateLimiter(5, time.Minute, 100, 30*time.Minute)
	loginRateLimitMiddleware := loginLimiter.Middleware(middleware.IPKeyExtractor)
	registerRateLimitMiddleware := registerLimiter.Middleware(middleware.IPKeyExtractor)
	userPatchRateLimitMiddleware := userPatchLimiter.Middleware(middleware.IPKeyExtractor)
	// Ping endpoint for health checks
	router.GET("/ping", handlers.PingHandler)

	// Websocket endpoint for streaming Minecraft logs
	router.GET("/ws",
		auth.RequestTimeMiddleware(),
		auth.JWTMiddleware(),
		auth.APIKeyMiddleware(),
		handlers.LogsWebsocketHandler,
	)

	// Authentication group
	authGroup := router.Group("/auth")
	{
		authGroup.POST("/login", loginRateLimitMiddleware, handlers.LoginHandler)
		authGroup.POST("/register", registerRateLimitMiddleware, handlers.RegisterHandler)
		authGroup.POST("/logout", auth.JWTMiddleware(), handlers.LogoutJWTHandler)

		// OAuth endpoints
		authGroup.GET("/oauth/:provider", handlers.OAuthLoginHandler)
		authGroup.GET("/callback/:provider", handlers.OAuthCallbackHandler)

		// Protected auth endpoints (require JWT)
		authProtected := authGroup.Group("")
		authProtected.Use(auth.JWTMiddleware())
		{
			authProtected.GET("/me", handlers.GetUserInfoHandler)
		}
	}

	// API keys management
	apiKeyGroup := router.Group("/apikeys")
	apiKeyGroup.Use(auth.JWTMiddleware())
	{
		apiKeyGroup.POST("", handlers.CreateAPIKeyHandler)
		apiKeyGroup.GET("", handlers.ListAPIKeysHandler)
		apiKeyGroup.DELETE("/:id", handlers.DeleteAPIKeyHandler)
	}

	// User management (admin only)
	userGroup := router.Group("/users")
	userGroup.Use(auth.JWTMiddleware(), auth.RequirePermission(database.PermAdmin))
	{
		userGroup.GET("", handlers.ListUsersHandler)
		userGroup.GET("/:id", handlers.GetUserHandler)
		userGroup.DELETE("/:id", handlers.DeleteUserHandler)

		userGroup.POST("/:id/permissions/grant", auth.RequirePermission(database.PermAdmin), handlers.GrantUserPermissionsHandler)
		userGroup.POST("/:id/permissions/revoke", auth.RequirePermission(database.PermAdmin), handlers.RevokeUserPermissionsHandler)
	}

	router.GET("/permissions", auth.JWTMiddleware(), handlers.GetPermissionsMapHandler)

	router.PATCH("/users/:id",
		auth.RequestTimeMiddleware(),
		userPatchRateLimitMiddleware,
		auth.JWTMiddleware(),
		handlers.UpdateUserHandler,
	)

	// Server management endpoints - protected with authentication
	// First try JWT, then fall back to API key
	serverGroup := router.Group("/servers")
	serverGroup.Use(auth.RequestTimeMiddleware(), auth.JWTMiddleware(), auth.APIKeyMiddleware())
	{
		// Create server (requires PermCreateServer)
		serverGroup.POST("", auth.RequirePermission(database.PermCreateServer), handlers.StartMinecraftServerHandler)

		// Server operations
		serverGroup.GET("", auth.RequirePermission(database.PermViewServer), handlers.ListMinecraftServersHandler)
		serverGroup.GET("/:serverName", auth.RequireServerPermission(database.PermViewServer), handlers.GetMinecraftServerHandler)
		serverGroup.POST("/:serverName/restart", auth.RequireServerPermission(database.PermRestartServer), handlers.RestartMinecraftServerHandler)
		serverGroup.POST("/:serverName/stop", auth.RequireServerPermission(database.PermStopServer), handlers.StopMinecraftServerHandler)
		serverGroup.POST("/:serverName/start", auth.RequireServerPermission(database.PermStartServer), handlers.StartStoppedServerHandler)
		serverGroup.POST("/:serverName/delete", auth.RequireServerPermission(database.PermDeleteServer), handlers.DeleteMinecraftServerHandler)
		serverGroup.POST("/:serverName/exec", auth.RequireServerPermission(database.PermExecCommand), handlers.ExecCommandHandler)

		// Network exposure endpoint
		serverGroup.POST("/:serverName/expose", auth.RequireServerPermission(database.PermCreateServer), handlers.ExposeMinecraftServerHandler)
	}
}
