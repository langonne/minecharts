package main

import (
	"log"
	"minecharts/cmd/api"
	"minecharts/cmd/config"
	"minecharts/cmd/database"
	_ "minecharts/cmd/docs" // Import swagger docs
	"minecharts/cmd/kubernetes"
	"minecharts/cmd/logging"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	swaggerFiles "github.com/swaggo/files"
	ginSwagger "github.com/swaggo/gin-swagger"
)

// @title           Minecharts API
// @version         0.1
// @description     API for managing Minecraft servers in Kubernetes
// @termsOfService  http://swagger.io/terms/

// @contact.name   API Support
// @contact.url    http://www.minecharts.io/support
// @contact.email  support@minecharts.io

// @license.name  MIT
// @license.url   https://opensource.org/licenses/MIT

// @securityDefinitions.apikey BearerAuth
// @in header
// @name Authorization
// @description Type "Bearer" followed by a space and JWT token.

// @securityDefinitions.apikey APIKeyAuth
// @in header
// @name X-API-Key
// @description API Key for authentication.

func main() {

	// Initialize logger
	logging.Init()
	logger := logging.Logger

	// Initialize timezone
	location, err := time.LoadLocation(config.TimeZone)
	if err != nil {
		logging.WithFields(
			logging.F("timezone", config.TimeZone),
			logging.F("error", err.Error()),
		).Warn("Failed to load timezone, falling back to UTC")
		location = time.UTC
	}

	time.Local = location

	logging.WithFields(
		logging.F("timezone", config.TimeZone),
	).Info("Application timezone configured")

	logger.Info("Starting Minecharts API server")

	// Set Gin mode
	if config.LogLevel == "debug" || config.LogLevel == "trace" {
		gin.SetMode(gin.DebugMode)
	} else {
		gin.SetMode(gin.ReleaseMode)
	}

	// Initialize Kubernetes client
	if err := kubernetes.Init(); err != nil {
		logger.Fatalf("Failed to initialize Kubernetes client: %v", err)
	}
	logger.Info("Kubernetes client initialized")

	// Initialize database
	if err := database.InitDB(config.DatabaseType, config.DatabaseConnectionString); err != nil {
		logger.Fatalf("Failed to initialize database: %v", err)
	}
	defer database.GetDB().Close()
	logger.Info("Database initialized")

	// Create a new Gin router
	router := gin.Default()
	proxies := strings.Split(config.TrustedProxies, ",")
	if err := router.SetTrustedProxies(proxies); err != nil {
		log.Fatalf("invalid trusted proxies: %v", err)
	}

	// Setup API routes
	api.SetupRoutes(router)
	logger.Info("API routes configured")

	// Setup Swagger endpoint
	router.GET("/swagger/*any", ginSwagger.WrapHandler(swaggerFiles.Handler))
	logger.Info("Swagger documentation endpoint enabled at /swagger/index.html")

	// Start the server
	logger.Info("Starting HTTP server on port 8080")
	if err := router.Run(":8080"); err != nil {
		logger.Fatalf("Failed to start server: %v", err)
	}
}
