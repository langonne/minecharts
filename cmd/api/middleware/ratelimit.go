package middleware

import (
	"context"
	"math"
	"net/http"
	"strconv"
	"sync/atomic"
	"time"

	"minecharts/cmd/database"
	"minecharts/cmd/logging"

	"github.com/gin-gonic/gin"
)

// DBRateLimiter applies a token bucket stored in the database so multiple instances share state.
type DBRateLimiter struct {
	capacity       float64
	refillInterval time.Duration
	cleanupEvery   int64
	retention      time.Duration
	requestCounter atomic.Int64
}

// NewDBRateLimiter creates a limiter with the given parameters.
// capacity is the maximum burst size in tokens, refillInterval controls how quickly tokens regenerate (one token per interval).
// cleanupEvery determines how often (in requests) a cleanup runs, retention defines how long inactive keys are kept.
func NewDBRateLimiter(capacity float64, refillInterval time.Duration, cleanupEvery int64, retention time.Duration) *DBRateLimiter {
	if capacity <= 0 {
		capacity = 1
	}
	if refillInterval <= 0 {
		refillInterval = time.Minute
	}
	if cleanupEvery <= 0 {
		cleanupEvery = 100
	}
	if retention <= 0 {
		retention = 30 * time.Minute
	}
	return &DBRateLimiter{
		capacity:       capacity,
		refillInterval: refillInterval,
		cleanupEvery:   cleanupEvery,
		retention:      retention,
	}
}

// IPKeyExtractor returns the client IP for rate limiting.
func IPKeyExtractor(c *gin.Context) string {
	return c.ClientIP()
}

// Middleware returns a Gin handler that enforces the rate limit.
func (r *DBRateLimiter) Middleware(keyFunc func(*gin.Context) string) gin.HandlerFunc {
	return func(c *gin.Context) {
		key := keyFunc(c)
		if key == "" {
			c.Next()
			return
		}

		allowed, retryAfter, err := database.GetDB().AllowRateLimit(c.Request.Context(), key, r.capacity, r.refillInterval, time.Now())
		if err != nil {
			logging.API.InvalidRequest.WithFields(
				"path", c.Request.URL.Path,
				"remote_ip", c.ClientIP(),
				"error", err.Error(),
			).Error("Rate limiter failed")
			c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "Rate limiting failed"})
			return
		}

		if !allowed {
			seconds := int(math.Ceil(retryAfter.Seconds()))
			if seconds > 0 {
				c.Header("Retry-After", strconv.Itoa(seconds))
			}
			logging.API.InvalidRequest.WithFields(
				"path", c.Request.URL.Path,
				"remote_ip", c.ClientIP(),
				"error", "rate_limited",
			).Warn("Request blocked by rate limiter")
			c.AbortWithStatusJSON(http.StatusTooManyRequests, gin.H{"error": "Too many requests"})
			return
		}

		if r.requestCounter.Add(1)%r.cleanupEvery == 0 {
			go r.cleanup(context.Background())
		}

		c.Next()
	}
}

func (r *DBRateLimiter) cleanup(ctx context.Context) {
	cutoff := time.Now().Add(-r.retention)
	if err := database.GetDB().CleanupRateLimits(ctx, cutoff); err != nil {
		logging.DB.WithFields(
			"cutoff", cutoff,
			"error", err.Error(),
		).Debug("Rate limiter cleanup failed")
	}
}
