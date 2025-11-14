// Package handlers contains the HTTP request handlers for the API endpoints.
package handlers

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"net/http"
	"net/url"
	"strings"
	"time"

	"minecharts/cmd/auth"
	"minecharts/cmd/config"
	"minecharts/cmd/database"
	"minecharts/cmd/logging"

	"github.com/gin-gonic/gin"
)

// LoginRequest represents the login request payload.
type LoginRequest struct {
	Username string `json:"username" binding:"required" example:"admin"`
	Password string `json:"password" binding:"required" example:"secretpassword"`
}

// RegisterRequest represents the user registration request payload.
type RegisterRequest struct {
	Username string `json:"username" binding:"required,min=3,max=50" example:"newuser"`
	Email    string `json:"email" binding:"required,email" example:"user@example.com"`
	Password string `json:"password" binding:"required,min=8" example:"securepass123"`
}

// LoginHandler authenticates a user with a username and password.
func LoginHandler(c *gin.Context) {
	var req LoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		logging.API.InvalidRequest.WithFields("error", err.Error(), "remote_ip", c.ClientIP(), "reason", "invalid_request").
			Warn("Invalid login request format")
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	logging.Auth.Login.WithFields("user", req.Username, "r_ip", c.ClientIP()).Info("User login attempt")

	// Get user from database
	db := database.GetDB()
	logging.DB.Debug("Using database implementation %T", db)

	user, err := db.GetUserByUsername(c.Request.Context(), req.Username)
	if err != nil {
		if err == database.ErrUserNotFound {
			logging.Auth.Login.WithFields("user", req.Username, "r_ip", c.ClientIP(), "reason", "user_not_found").
				Warn("Login failed: user not found")
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid username or password"})
			return
		}
		logging.DB.WithFields("user", req.Username, "r_ip", c.ClientIP(), "error", err.Error()).Error("Database error during login")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get user"})
		return
	}

	logging.DB.WithFields("username", req.Username, "user_id", user.ID).Debug("User found in database")

	// Verify password
	if err := auth.VerifyPassword(user.PasswordHash, req.Password); err != nil {
		logging.Auth.Login.WithFields("username", req.Username, "remote_ip", c.ClientIP(), "reason", "invalid_password").
			Warn("Login failed: invalid password")
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid username or password"})
		return
	}

	logging.Auth.WithFields("username", req.Username, "user_id", user.ID).Debug("Password verified successfully")

	// Check if user is active
	if !user.Active {
		logging.Auth.Login.WithFields("username", req.Username, "user_id", user.ID, "remote_ip", c.ClientIP(), "reason", "account_inactive").
			Warn("Login failed: account inactive")
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid username or password"})
		return
	}

	// Generate JWT token
	token, err := auth.GenerateJWT(user.ID, user.Username, user.Email, user.Permissions)
	if err != nil {
		logging.Auth.JWT.WithFields("username", req.Username, "user_id", user.ID, "error", err.Error()).
			Error("Failed to generate JWT token")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate token"})
		return
	}

	// Update last login time
	now := time.Now()
	user.LastLogin = &now
	if err := db.UpdateUser(c.Request.Context(), user); err != nil {
		logging.DB.WithFields("username", req.Username, "user_id", user.ID, "error", err.Error()).
			Warn("Failed to update last login time")
	}

	logging.Auth.Login.WithFields("username", req.Username, "user_id", user.ID, "remote_ip", c.ClientIP()).
		Info("User login successful")

	c.SetCookie(
		"auth_token",
		token,
		3600*24,
		"/",
		"",
		true,
		true,
	)

	c.JSON(http.StatusOK, gin.H{
		"user_id":     user.ID,
		"username":    user.Username,
		"email":       user.Email,
		"permissions": user.Permissions,
	})
}

// LogoutJWTHandler terminates the user's session by invalidating their JWT cookie.
func LogoutJWTHandler(c *gin.Context) {
	// Check if user is authenticated
	user, ok := auth.GetCurrentUser(c)
	if !ok {
		logging.Auth.Session.WithFields("remote_ip", c.ClientIP(), "reason", "not_authenticated").
			Info("Logout attempt from unauthenticated user")
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Not authenticated"})
		return
	}

	// Log the logout event
	logging.Auth.Session.WithFields("user_id", user.ID, "username", user.Username, "remote_ip", c.ClientIP()).
		Info("User logged out")

	// Invalidate the JWT token by setting an empty value and a negative expiration time
	c.SetCookie(
		"auth_token",
		"",
		-1,
		"/",
		"",
		true,
		true,
	)

	c.JSON(http.StatusOK, gin.H{
		"message": "Logout successful",
		"status":  "success",
	})
}

// RegisterHandler creates a new user account using the supplied credentials.
func RegisterHandler(c *gin.Context) {
	var req RegisterRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		logging.API.InvalidRequest.WithFields("error", err.Error(), "remote_ip", c.ClientIP()).
			Warn("Invalid registration request format")
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	logging.Auth.Register.WithFields("username", req.Username, "email", req.Email, "remote_ip", c.ClientIP()).
		Info("User registration attempt")

	// Hash password
	passwordHash, err := auth.HashPassword(req.Password)
	if err != nil {
		logging.Auth.WithFields("username", req.Username, "error", err.Error()).
			Error("Failed to hash password during registration")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to hash password"})
		return
	}

	// Create user
	user := &database.User{
		Username:     req.Username,
		Email:        req.Email,
		PasswordHash: passwordHash,
		Permissions:  int64(database.PermReadOnly), // Default to read-only permissions
		Active:       true,
	}

	db := database.GetDB()
	if err := db.CreateUser(c.Request.Context(), user); err != nil {
		if err == database.ErrUserExists {
			logging.Auth.Register.WithFields("username", req.Username, "email", req.Email, "remote_ip", c.ClientIP(), "reason", "user_exists").
				Warn("Registration failed: user already exists")
			c.JSON(http.StatusConflict, gin.H{"error": "Username or email already exists"})
			return
		}
		logging.DB.WithFields("username", req.Username, "email", req.Email, "error", err.Error()).
			Error("Database error during user registration")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create user"})
		return
	}

	// Generate JWT token
	token, err := auth.GenerateJWT(user.ID, user.Username, user.Email, user.Permissions)
	if err != nil {
		logging.Auth.JWT.WithFields("username", req.Username, "user_id", user.ID, "error", err.Error()).
			Error("Failed to generate JWT token during registration")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate token"})
		return
	}

	logging.Auth.Register.WithFields("username", req.Username, "user_id", user.ID, "email", req.Email, "remote_ip", c.ClientIP()).
		Info("User registration successful")

	c.JSON(http.StatusCreated, gin.H{
		"token":       token,
		"user_id":     user.ID,
		"username":    user.Username,
		"email":       user.Email,
		"permissions": user.Permissions,
	})
}

// GetUserInfoHandler returns information about the authenticated user.
func GetUserInfoHandler(c *gin.Context) {
	user, ok := auth.GetCurrentUser(c)
	if !ok {
		logging.Auth.Session.WithFields("remote_ip", c.ClientIP(), "reason", "not_authenticated").
			Warn("User info request from unauthenticated user")
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Not authenticated"})
		return
	}

	logging.Auth.Session.WithFields("user_id", user.ID, "username", user.Username, "remote_ip", c.ClientIP()).
		Debug("User info requested")

	c.JSON(http.StatusOK, gin.H{
		"user_id":     user.ID,
		"username":    user.Username,
		"email":       user.Email,
		"permissions": user.Permissions,
		"active":      user.Active,
		"last_login":  user.LastLogin,
		"created_at":  user.CreatedAt,
	})
}

// GenerateStateValue creates a random state value for OAuth flows.
// It returns a base64-encoded random string and any error encountered.
func GenerateStateValue() (string, error) {
	b := make([]byte, 32)
	_, err := rand.Read(b)
	if err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(b), nil
}

// OAuthLoginHandler initiates the OAuth login flow for a given provider.
func OAuthLoginHandler(c *gin.Context) {
	// Check if OAuth is enabled
	if !config.OAuthEnabled {
		logging.Auth.OAuth.WithFields("remote_ip", c.ClientIP(), "reason", "oauth_not_enabled").
			Warn("OAuth login failed: OAuth is not enabled")
		c.JSON(http.StatusBadRequest, gin.H{"error": "OAuth is not enabled"})
		return
	}

	// Get provider from URL parameter
	provider := c.Param("provider")
	if provider != "authentik" {
		logging.Auth.OAuth.WithFields("remote_ip", c.ClientIP(), "provider", provider, "reason", "unsupported_provider").
			Warn("OAuth login failed: unsupported provider")
		c.JSON(http.StatusBadRequest, gin.H{"error": "Unsupported OAuth provider"})
		return
	}

	logging.Auth.OAuth.WithFields("remote_ip", c.ClientIP(), "provider", provider).
		Info("OAuth login flow initiated")

	// Initialize OAuth provider
	oauthProvider, err := auth.NewAuthentikProvider()
	if err != nil {
		logging.Auth.OAuth.WithFields("remote_ip", c.ClientIP(), "provider", provider, "error", err.Error()).
			Error("Failed to initialize OAuth provider")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to initialize OAuth provider"})
		return
	}

	// Generate and store state parameter to prevent CSRF
	state, err := GenerateStateValue()
	if err != nil {
		logging.Auth.OAuth.WithFields("remote_ip", c.ClientIP(), "provider", provider, "error", err.Error()).
			Error("Failed to generate OAuth state parameter")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate state"})
		return
	}

	// Store state in a secure HTTP-only cookie for verification later
	stateTTLSeconds := int((15 * time.Minute).Seconds())
	c.SetCookie(
		"oauth_state",
		state,
		stateTTLSeconds,
		"/",
		"",
		true, // Secure (HTTPS only)
		true, // HTTP-only
	)

	logging.Auth.OAuth.WithFields("remote_ip", c.ClientIP(), "provider", provider).
		Debug("OAuth state parameter generated and stored")

	// Redirect to OAuth provider's auth page
	authURL := oauthProvider.GetAuthURL(state)

	logging.Auth.OAuth.WithFields("remote_ip", c.ClientIP(), "provider", provider).
		Info("Redirecting user to OAuth provider")

	c.Redirect(http.StatusTemporaryRedirect, authURL)
}

// OAuthCallbackHandler processes the provider callback and finalizes authentication.
func OAuthCallbackHandler(c *gin.Context) {
	// Check if OAuth is enabled
	if !config.OAuthEnabled {
		logging.Auth.OAuth.WithFields("remote_ip", c.ClientIP(), "reason", "oauth_not_enabled").
			Warn("OAuth callback failed: OAuth is not enabled")
		c.JSON(http.StatusBadRequest, gin.H{"error": "OAuth is not enabled"})
		return
	}

	// Get provider from URL parameter
	provider := c.Param("provider")
	if provider != "authentik" {
		logging.Auth.OAuth.WithFields("remote_ip", c.ClientIP(), "provider", provider, "reason", "unsupported_provider").
			Warn("OAuth callback failed: unsupported provider")
		c.JSON(http.StatusBadRequest, gin.H{"error": "Unsupported OAuth provider"})
		return
	}

	logging.Auth.OAuth.WithFields("remote_ip", c.ClientIP(), "provider", provider).
		Info("OAuth callback received")

	// Get code and state from query parameters
	code := c.Query("code")
	state := c.Query("state")

	if code == "" {
		logging.Auth.OAuth.WithFields("remote_ip", c.ClientIP(), "provider", provider, "reason", "missing_code").
			Warn("OAuth callback failed: missing code parameter")
		c.JSON(http.StatusBadRequest, gin.H{"error": "Missing code parameter"})
		return
	}

	// Retrieve and verify the state from cookie
	savedState, err := c.Cookie("oauth_state")
	if err != nil || savedState == "" || savedState != state {
		logging.Auth.OAuth.WithFields("remote_ip", c.ClientIP(), "provider", provider, "reason", "state_mismatch",
			"have_cookie", savedState != "", "state_match", savedState == state).
			Warn("OAuth callback failed: invalid state parameter")
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid OAuth state parameter"})
		c.Abort()
		return
	}

	logging.Auth.OAuth.Debug("OAuth state verification successful")

	// Clear the cookie after use
	c.SetCookie("oauth_state", "", -1, "/", "", true, true)

	// Initialize OAuth provider
	oauthProvider, err := auth.NewAuthentikProvider()
	if err != nil {
		logging.Auth.OAuth.WithFields("remote_ip", c.ClientIP(), "provider", provider, "error", err.Error()).
			Error("Failed to initialize OAuth provider during callback")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to initialize OAuth provider"})
		return
	}

	// Exchange code for token
	token, err := oauthProvider.Exchange(context.Background(), code)
	if err != nil {
		logging.Auth.OAuth.WithFields("remote_ip", c.ClientIP(), "provider", provider, "error", err.Error()).
			Error("Failed to exchange OAuth code for token")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to exchange OAuth code: " + err.Error()})
		return
	}

	logging.Auth.OAuth.Debug("OAuth code successfully exchanged for token")

	// Get user info from token
	userInfo, err := oauthProvider.GetUserInfo(context.Background(), token)
	if err != nil {
		logging.Auth.OAuth.WithFields("remote_ip", c.ClientIP(), "provider", provider, "error", err.Error()).
			Error("Failed to get user info from OAuth provider")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get user info: " + err.Error()})
		return
	}

	logging.Auth.OAuth.WithFields("remote_ip", c.ClientIP(), "provider", provider, "oauth_username", userInfo.Username, "oauth_email", userInfo.Email).
		Info("Successfully retrieved user info from OAuth provider")

	// Create or update user in database
	user, err := auth.SyncOAuthUser(c.Request.Context(), userInfo)
	if err != nil {
		logging.Auth.OAuth.WithFields("remote_ip", c.ClientIP(), "provider", provider, "oauth_username", userInfo.Username, "error", err.Error()).
			Error("Failed to sync OAuth user with database")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to sync user: " + err.Error()})
		return
	}

	// Generate JWT token
	jwtToken, err := auth.GenerateJWT(user.ID, user.Username, user.Email, user.Permissions)
	if err != nil {
		logging.Auth.JWT.WithFields("remote_ip", c.ClientIP(), "provider", provider, "user_id", user.ID, "username", user.Username, "error", err.Error()).
			Error("Failed to generate JWT token after OAuth authentication")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate token"})
		return
	}

	logging.Auth.OAuth.WithFields("remote_ip", c.ClientIP(), "provider", provider, "user_id", user.ID, "username", user.Username).
		Info("OAuth authentication successful, redirecting to frontend")

	// Redirect to frontend with token
	frontendBase := strings.TrimRight(config.FrontendURL, "/")
	tokenParam := url.QueryEscape(jwtToken)
	frontendRedirectURL := frontendBase + "/oauth-callback?token=" + tokenParam
	c.Redirect(http.StatusTemporaryRedirect, frontendRedirectURL)
}
