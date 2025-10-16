package config

import (
	"os"
	"strconv"
	"time"
)

// Global configuration variables, configurable via environment variables.
var (
	// Server configuration
	DefaultNamespace     = getEnv("MINECHARTS_NAMESPACE", "minecharts")
	DeploymentPrefix     = getEnv("MINECHARTS_DEPLOYMENT_PREFIX", "minecraft-server-")
	PVCSuffix            = getEnv("MINECHARTS_PVC_SUFFIX", "-pvc")
	StorageSize          = getEnv("MINECHARTS_STORAGE_SIZE", "10Gi")
	StorageClass         = getEnv("MINECHARTS_STORAGE_CLASS", "rook-ceph-block")
	MCRouterDomainSuffix = getEnv("MINECHARTS_MCROUTER_DOMAIN_SUFFIX", "test.nasdak.fr")
	DefaultReplicas      = 1

	//  Reverse proxy configuration
	TrustedProxies = getEnv("MINECHARTS_TRUSTED_PROXIES", "127.0.0.1")

	// Database configuration
	DatabaseType             = getEnv("MINECHARTS_DB_TYPE", "sqlite")                         // "sqlite" or "postgres"
	DatabaseConnectionString = getEnv("MINECHARTS_DB_CONNECTION", "./app/data/minecharts.db") // File path for SQLite or connection string for Postgres

	// Authentication configuration
	JWTSecret      = getEnv("MINECHARTS_JWT_SECRET", "your-secret-key-change-me-in-production")
	JWTExpiryHours = getEnvInt("MINECHARTS_JWT_EXPIRY_HOURS", 24)
	APIKeyPrefix   = getEnv("MINECHARTS_API_KEY_PREFIX", "mcapi")

	// OAuth configuration
	OAuthEnabled = getEnvBool("MINECHARTS_OAUTH_ENABLED", false)

	// Authentik OAuth configuration
	AuthentikEnabled      = getEnvBool("MINECHARTS_AUTHENTIK_ENABLED", false)
	AuthentikIssuer       = getEnv("MINECHARTS_AUTHENTIK_ISSUER", "") // e.g., https://auth.example.com/application/o/
	AuthentikClientID     = getEnv("MINECHARTS_AUTHENTIK_CLIENT_ID", "")
	AuthentikClientSecret = getEnv("MINECHARTS_AUTHENTIK_CLIENT_SECRET", "")
	AuthentikRedirectURL  = getEnv("MINECHARTS_AUTHENTIK_REDIRECT_URL", "") // e.g., http://localhost:8080/api/auth/callback/authentik

	// URL Frontend configuration
	FrontendURL = "http://localhost:3000"

	// Timezone configuration
	TimeZone = getEnv("MINECHARTS_TIMEZONE", "UTC") // Default value: UTC

	// Logging configuration
	LogLevel  = getEnv("MINECHARTS_LOG_LEVEL", "info")  // Possible values: trace, debug, info, warn, error, fatal, panic
	LogFormat = getEnv("MINECHARTS_LOG_FORMAT", "json") // Possible values: json, text

	// Rate limiting configuration
	RateLimitCleanupEvery      = getEnvInt("MINECHARTS_RATE_LIMIT_CLEANUP_EVERY", 100)
	RateLimitRetention         = getEnvDuration("MINECHARTS_RATE_LIMIT_RETENTION", 30*time.Minute)
	LoginRateLimitCapacity     = getEnvFloat("MINECHARTS_RATE_LIMIT_LOGIN_CAPACITY", 5)
	LoginRateLimitInterval     = getEnvDuration("MINECHARTS_RATE_LIMIT_LOGIN_INTERVAL", time.Minute)
	RegisterRateLimitCapacity  = getEnvFloat("MINECHARTS_RATE_LIMIT_REGISTER_CAPACITY", 2)
	RegisterRateLimitInterval  = getEnvDuration("MINECHARTS_RATE_LIMIT_REGISTER_INTERVAL", 5*time.Minute)
	UserPatchRateLimitCapacity = getEnvFloat("MINECHARTS_RATE_LIMIT_USER_PATCH_CAPACITY", 5)
	UserPatchRateLimitInterval = getEnvDuration("MINECHARTS_RATE_LIMIT_USER_PATCH_INTERVAL", time.Minute)
	MaxAPIKeysPerUser          = getEnvInt("MINECHARTS_API_KEYS_PER_USER", 5)
)

func getEnv(key, fallback string) string {
	if value, exists := os.LookupEnv(key); exists {
		return value
	}
	return fallback
}

func getEnvBool(key string, fallback bool) bool {
	if value, exists := os.LookupEnv(key); exists {
		return value == "true" || value == "1" || value == "yes"
	}
	return fallback
}

func getEnvInt(key string, fallback int) int {
	if value, exists := os.LookupEnv(key); exists {
		if intVal, err := strconv.Atoi(value); err == nil {
			return intVal
		}
	}
	return fallback
}

func getEnvFloat(key string, fallback float64) float64 {
	if value, exists := os.LookupEnv(key); exists {
		if floatVal, err := strconv.ParseFloat(value, 64); err == nil {
			return floatVal
		}
	}
	return fallback
}

func getEnvDuration(key string, fallback time.Duration) time.Duration {
	if value, exists := os.LookupEnv(key); exists {
		if duration, err := time.ParseDuration(value); err == nil {
			return duration
		}
	}
	return fallback
}
