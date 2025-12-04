package config

import (
	"os"
	"strconv"
	"time"
)

// Global configuration variables, configurable via environment variables.
var (
	// Server configuration
	DefaultNamespace      = getEnv("MINECHARTS_NAMESPACE", "minecharts")
	StatefulSetPrefix     = getEnv("MINECHARTS_STATEFULSET_PREFIX", "minecraft-server-")
	PVCSuffix             = getEnv("MINECHARTS_PVC_SUFFIX", "-pvc")
	StorageSize           = getEnv("MINECHARTS_STORAGE_SIZE", "10Gi")
	StorageClass          = getEnv("MINECHARTS_STORAGE_CLASS", "")          // local-path
	MCRouterDomainSuffix  = getEnv("MINECHARTS_MCROUTER_DOMAIN_SUFFIX", "") // change-me.local
	DefaultReplicas       = 1
	MemoryQuotaEnabled    = getEnvBool("MINECHARTS_MEMORY_QUOTA_ENABLED", false)
	MemoryQuotaLimit      = getEnvInt("MINECHARTS_MEMORY_QUOTA_LIMIT", 0)
	MemoryLimitOverheadMi = getEnvInt("MINECHARTS_MEMORY_LIMIT_OVERHEAD_MI", 256)
	DataDir               = getEnv("DATA_DIR", "./app/data")

	//  Reverse proxy configuration
	TrustedProxies = getEnv("MINECHARTS_TRUSTED_PROXIES", "127.0.0.1")

	// Database configuration
	DatabaseType             = getEnv("MINECHARTS_DB_TYPE", "sqlite")                         // "sqlite" or "postgres"
	DatabaseConnectionString = getEnv("MINECHARTS_DB_CONNECTION", "./app/data/minecharts.db") // File path for SQLite or connection string for Postgres

	// Authentication configuration
	JWTSecret              string
	JWTExpiryHours         = getEnvInt("MINECHARTS_JWT_EXPIRY_HOURS", 24)
	APIKeyPrefix           = getEnv("MINECHARTS_API_KEY_PREFIX", "mcapi")
	AllowSelfRegistration  = getEnvBool("MINECHARTS_ALLOW_SELF_REGISTRATION", false)
	DefaultUserPermissions = getEnv("MINECHARTS_DEFAULT_USER_PERMISSIONS", "operator")

	// OAuth configuration
	OAuthEnabled = getEnvBool("MINECHARTS_OAUTH_ENABLED", false)

	// Generic OIDC provider configuration
	OAuthProviderName        = getEnv("MINECHARTS_OAUTH_PROVIDER_NAME", "")
	OAuthProviderDisplayName = getEnv("MINECHARTS_OAUTH_PROVIDER_DISPLAY_NAME", "")
	OIDCIssuer               = getEnv("MINECHARTS_OIDC_ISSUER", "")
	OIDCClientID             = getEnv("MINECHARTS_OIDC_CLIENT_ID", "")
	OIDCClientSecret         = getEnv("MINECHARTS_OIDC_CLIENT_SECRET", "")
	OIDCRedirectURL          = getEnv("MINECHARTS_OIDC_REDIRECT_URL", "")

	// Authentik-specific group sync (optional)
	AuthentikGroupSyncEnabled = getEnvBool("MINECHARTS_AUTHENTIK_GROUP_SYNC_ENABLED", false)
	AuthentikAdminGroup       = getEnv("MINECHARTS_AUTHENTIK_ADMIN_GROUP", "")
	AuthentikUserGroup        = getEnv("MINECHARTS_AUTHENTIK_USER_GROUP", "")
	AuthentikUserPermissions  = getEnv("MINECHARTS_AUTHENTIK_USER_PERMISSIONS", "")

	// URL Frontend configuration
	FrontendURL = getEnv("MINECHARTS_FRONTEND_URL", "http://localhost:3000")

	// Timezone configuration
	TimeZone = getEnv("MINECHARTS_TIMEZONE", "UTC")

	// Logging configuration
	LogLevel  = getEnv("MINECHARTS_LOG_LEVEL", "info")  // Possible values: trace, debug, info, warn, error, fatal, panic
	LogFormat = getEnv("MINECHARTS_LOG_FORMAT", "json") // Possible values: json, text

	// Security configuration
	BCryptCost = clampBcryptCost(getEnvInt("MINECHARTS_BCRYPT_COST", 14))

	// Rate limiting configuration
	RateLimitCleanupEvery      = getEnvInt("MINECHARTS_RATE_LIMIT_CLEANUP_EVERY", 100)
	RateLimitRetention         = getEnvDuration("MINECHARTS_RATE_LIMIT_RETENTION", 30*time.Minute)
	LoginRateLimitCapacity     = getEnvFloat("MINECHARTS_RATE_LIMIT_LOGIN_CAPACITY", 10)
	LoginRateLimitInterval     = getEnvDuration("MINECHARTS_RATE_LIMIT_LOGIN_INTERVAL", time.Minute)
	RegisterRateLimitCapacity  = getEnvFloat("MINECHARTS_RATE_LIMIT_REGISTER_CAPACITY", 4)
	RegisterRateLimitInterval  = getEnvDuration("MINECHARTS_RATE_LIMIT_REGISTER_INTERVAL", 5*time.Minute)
	UserPatchRateLimitCapacity = getEnvFloat("MINECHARTS_RATE_LIMIT_USER_PATCH_CAPACITY", 10)
	UserPatchRateLimitInterval = getEnvDuration("MINECHARTS_RATE_LIMIT_USER_PATCH_INTERVAL", time.Minute)
	MaxAPIKeysPerUser          = getEnvInt("MINECHARTS_API_KEYS_PER_USER", 5)

	// Feedback integration configuration
	FeedbackEnabled         = getEnvBool("MINECHARTS_FEEDBACK_ENABLED", false)
	FeedbackProvider        = getEnv("MINECHARTS_FEEDBACK_PROVIDER", "")
	FeedbackGitHubToken     = getEnv("MINECHARTS_FEEDBACK_GITHUB_TOKEN", "")
	FeedbackGitHubRepoOwner = getEnv("MINECHARTS_FEEDBACK_GITHUB_REPO_OWNER", "")
	FeedbackGitHubRepoName  = getEnv("MINECHARTS_FEEDBACK_GITHUB_REPO_NAME", "")
	FeedbackGitLabToken     = getEnv("MINECHARTS_FEEDBACK_GITLAB_TOKEN", "")
	FeedbackGitLabProject   = getEnv("MINECHARTS_FEEDBACK_GITLAB_PROJECT", "")
	FeedbackGitLabBaseURL   = getEnv("MINECHARTS_FEEDBACK_GITLAB_URL", "https://gitlab.com")
	FeedbackDefaultLabels   = getEnv("MINECHARTS_FEEDBACK_DEFAULT_LABELS", "feedback")
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

func clampBcryptCost(cost int) int {
	if cost < 4 {
		return 4
	}
	if cost > 31 {
		return 31
	}
	return cost
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
