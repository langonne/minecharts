package main

import (
	"log"
	"minecharts/cmd/api"
	"minecharts/cmd/config"
	"minecharts/cmd/database"
	"minecharts/cmd/kubernetes"
	"minecharts/cmd/logging"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
)

func main() {

	// Initialize logger
	logging.Init()
	logger := logging.Logger

	if strings.TrimSpace(config.JWTSecret) == "" {
		logger.Fatal("MINECHARTS_JWT_SECRET is required; set it before starting the API")
	}
	if strings.TrimSpace(config.MCRouterDomainSuffix) == "" {
		logger.Fatal("MINECHARTS_MCROUTER_DOMAIN_SUFFIX is required; set it before starting the API")
	}
	if strings.TrimSpace(config.StorageClass) == "" {
		logger.Fatal("MINECHARTS_STORAGE_CLASS is required; set it before starting the API")
	}
	if config.FeedbackEnabled {
		var missing []string
		if strings.TrimSpace(config.FeedbackGitHubToken) == "" {
			missing = append(missing, "MINECHARTS_FEEDBACK_GITHUB_TOKEN")
		}
		if strings.TrimSpace(config.FeedbackGitHubRepoOwner) == "" {
			missing = append(missing, "MINECHARTS_FEEDBACK_GITHUB_REPO_OWNER")
		}
		if strings.TrimSpace(config.FeedbackGitHubRepoName) == "" {
			missing = append(missing, "MINECHARTS_FEEDBACK_GITHUB_REPO_NAME")
		}
		if len(missing) > 0 {
			logger.Fatalf("Feedback endpoint enabled but missing configuration: %s", strings.Join(missing, ", "))
		}
	}

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
	logger.Info("Trusted proxies configured", "proxies", proxies)

	// Setup API routes
	api.SetupRoutes(router)
	logger.Info("API routes configured")

	// Start the server
	logger.Info("Starting HTTP server on port 8080")
	if err := router.Run(":8080"); err != nil {
		logger.Fatalf("Failed to start server: %v", err)
	}
}
