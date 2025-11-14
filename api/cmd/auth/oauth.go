package auth

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"minecharts/cmd/config"
	"minecharts/cmd/database"
	"minecharts/cmd/logging"

	"golang.org/x/oauth2"
)

var (
	ErrInvalidOAuthConfig    = errors.New("invalid OAuth configuration")
	ErrOAuthExchangeFailed   = errors.New("OAuth code exchange failed")
	ErrOAuthUserInfoFailed   = errors.New("failed to get OAuth user info")
	ErrOAuthNotEnabled       = errors.New("oauth is not enabled")
	ErrUnsupportedProvider   = errors.New("unsupported oauth provider")
	ErrMissingProviderConfig = errors.New("missing oauth provider configuration")
	ErrUserInfoRetrieval     = errors.New("failed to retrieve user information")
)

// OAuthProvider represents an OAuth 2.0 provider
type OAuthProvider struct {
	Config      *oauth2.Config
	Name        string
	UserInfoURL string
}

// OAuthUserInfo contains user information from the OAuth provider
type OAuthUserInfo struct {
	ID            string
	Email         string
	Username      string
	Name          string
	EmailVerified bool
	FirstName     string
	LastName      string
	Picture       string
	Provider      string
	Groups        []string
}

func optionalString(value string) *string {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil
	}
	return &value
}

// NewAuthentikProvider creates a new OAuth provider for Authentik
func NewAuthentikProvider() (*OAuthProvider, error) {
	logging.Auth.OAuth.Debug("Initializing Authentik OAuth provider")

	if !config.OAuthEnabled || !config.AuthentikEnabled {
		logging.Auth.OAuth.WithFields(
			"oauth_enabled", config.OAuthEnabled,
			"authentik_enabled", config.AuthentikEnabled,
		).Warn("Authentik OAuth is not enabled")
		return nil, ErrOAuthNotEnabled
	}

	if config.AuthentikClientID == "" || config.AuthentikClientSecret == "" ||
		config.AuthentikIssuer == "" || config.AuthentikRedirectURL == "" {
		logging.Auth.OAuth.WithFields(
			"client_id_set", config.AuthentikClientID != "",
			"client_secret_set", config.AuthentikClientSecret != "",
			"issuer_set", config.AuthentikIssuer != "",
			"redirect_url_set", config.AuthentikRedirectURL != "",
		).Error("Authentik OAuth configuration is incomplete")
		return nil, ErrMissingProviderConfig
	}

	authURL, tokenURL, userInfoURL, err := buildAuthentikEndpoints(config.AuthentikIssuer)
	if err != nil {
		logging.Auth.OAuth.WithFields(
			"issuer", config.AuthentikIssuer,
			"error", err.Error(),
		).Error("Failed to derive Authentik endpoints from issuer")
		return nil, ErrInvalidOAuthConfig
	}

	// Construct OAuth2 config
	oauthConfig := &oauth2.Config{
		ClientID:     config.AuthentikClientID,
		ClientSecret: config.AuthentikClientSecret,
		RedirectURL:  config.AuthentikRedirectURL,
		Scopes:       []string{"openid", "email", "profile"},
		Endpoint: oauth2.Endpoint{
			AuthURL:  authURL,
			TokenURL: tokenURL,
		},
	}

	logging.Auth.OAuth.WithFields(
		"issuer", config.AuthentikIssuer,
		"redirect_url", config.AuthentikRedirectURL,
		"auth_url", authURL,
		"token_url", tokenURL,
		"userinfo_url", userInfoURL,
	).Info("Authentik OAuth provider initialized successfully")

	return &OAuthProvider{
		Config:      oauthConfig,
		Name:        "authentik",
		UserInfoURL: userInfoURL,
	}, nil
}

// GetAuthURL returns the URL to redirect the user to for authorization
func (p *OAuthProvider) GetAuthURL(state string) string {
	url := p.Config.AuthCodeURL(state, oauth2.AccessTypeOnline)

	logging.Auth.OAuth.WithFields(
		"url", url,
		"state", state,
	).Debug("Generated Authentik OAuth authorization URL")

	return url
}

// Exchange exchanges the authorization code for a token
func (p *OAuthProvider) Exchange(ctx context.Context, code string) (*oauth2.Token, error) {
	logging.Auth.OAuth.Debug("Exchanging OAuth code for token")

	token, err := p.Config.Exchange(ctx, code)
	if err != nil {
		logging.Auth.OAuth.WithFields(
			"error", err.Error(),
		).Error("Failed to exchange OAuth code for token")
		return nil, err
	}

	logging.Auth.OAuth.WithFields(
		"token_type", token.TokenType,
		"expiry", token.Expiry,
	).Debug("Successfully exchanged OAuth code for token")

	return token, nil
}

// GetUserInfo retrieves user information from the OAuth provider
func (p *OAuthProvider) GetUserInfo(ctx context.Context, token *oauth2.Token) (*OAuthUserInfo, error) {
	logging.Auth.OAuth.Debug("Fetching user info from Authentik")

	client := p.Config.Client(ctx, token)

	// Get user info from Authentik's userinfo endpoint
	resp, err := client.Get(p.UserInfoURL)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, ErrOAuthUserInfoFailed
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var userInfo struct {
		Sub               string   `json:"sub"`
		Email             string   `json:"email"`
		EmailVerified     bool     `json:"email_verified"`
		PreferredUsername string   `json:"preferred_username"`
		Name              string   `json:"name"`
		Groups            []string `json:"groups"`
	}

	if err := json.Unmarshal(body, &userInfo); err != nil {
		return nil, err
	}

	// Use preferred_username or derive username from email if not provided
	username := userInfo.PreferredUsername
	if username == "" {
		if userInfo.Email != "" {
			parts := strings.Split(userInfo.Email, "@")
			username = parts[0]
		} else {
			username = "user_" + userInfo.Sub
		}
	}

	logging.Auth.OAuth.WithFields(
		"provider", "authentik",
		"username", username,
	).Debug("Successfully retrieved user info from Authentik")

	return &OAuthUserInfo{
		ID:            userInfo.Sub,
		Email:         userInfo.Email,
		Username:      username,
		Name:          userInfo.Name,
		EmailVerified: userInfo.EmailVerified,
		Provider:      "authentik",
		Groups:        userInfo.Groups,
	}, nil
}

func buildAuthentikEndpoints(rawIssuer string) (string, string, string, error) {
	base, err := normalizeAuthentikIssuer(rawIssuer)
	if err != nil {
		return "", "", "", err
	}

	authURL := ensureTrailingSlash(base + "/authorize")
	tokenURL := ensureTrailingSlash(base + "/token")
	userInfoURL := ensureTrailingSlash(base + "/userinfo")

	return authURL, tokenURL, userInfoURL, nil
}

func normalizeAuthentikIssuer(raw string) (string, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return "", ErrInvalidOAuthConfig
	}

	parsed, err := url.Parse(trimmed)
	if err != nil {
		return "", err
	}

	path := strings.TrimSuffix(parsed.Path, "/")
	if strings.HasPrefix(path, "/application/o/") || path == "/application/o" {
		path = "/application/o"
	}
	parsed.Path = path
	parsed.RawPath = ""
	parsed.RawQuery = ""
	parsed.Fragment = ""

	base := strings.TrimRight(parsed.String(), "/")
	if base == "" {
		return "", ErrInvalidOAuthConfig
	}

	return base, nil
}

func ensureTrailingSlash(value string) string {
	if strings.HasSuffix(value, "/") {
		return value
	}
	return value + "/"
}

func syncAdminPermissionsFromGroups(user *database.User, groups []string) (granted bool, revoked bool) {
	if !config.AuthentikGroupSyncEnabled {
		return false, false
	}

	adminGroup := strings.TrimSpace(config.AuthentikAdminGroup)
	if adminGroup == "" {
		return false, false
	}

	hasMembership := false
	for _, group := range groups {
		if strings.EqualFold(strings.TrimSpace(group), adminGroup) {
			hasMembership = true
			break
		}
	}

	if hasMembership {
		if user.Permissions&int64(database.PermAdmin) == 0 {
			user.Permissions |= int64(database.PermAdmin)
			return true, false
		}
		return false, false
	}

	if user.Permissions&int64(database.PermAdmin) != 0 {
		user.Permissions &^= int64(database.PermAdmin)
		return false, true
	}

	return false, false
}

// SyncOAuthUser creates or updates a user based on OAuth information
func SyncOAuthUser(ctx context.Context, userInfo *OAuthUserInfo) (*database.User, error) {
	logging.Auth.OAuth.WithFields(
		"provider", userInfo.Provider,
		"username", userInfo.Username,
		"email", userInfo.Email,
	).Info("Syncing OAuth user with database")

	db := database.GetDB()

	var (
		user *database.User
		err  error
	)

	provider := strings.TrimSpace(userInfo.Provider)
	subject := strings.TrimSpace(userInfo.ID)

	if provider != "" && subject != "" {
		user, err = db.GetUserByOAuthIdentity(ctx, provider, subject)
		if err != nil && err != database.ErrUserNotFound {
			logging.DB.WithFields(
				"provider", provider,
				"subject", subject,
				"error", err.Error(),
			).Error("Database error while looking up user by OAuth identity")
			return nil, err
		}
		if err == database.ErrUserNotFound {
			user = nil
		}
	}

	if user == nil && strings.TrimSpace(userInfo.Email) != "" {
		user, err = db.GetUserByEmail(ctx, userInfo.Email)
		if err != nil && err != database.ErrUserNotFound {
			logging.DB.WithFields(
				"email", userInfo.Email,
				"error", err.Error(),
			).Error("Database error while looking up user by email")
			return nil, err
		}
		if err == database.ErrUserNotFound {
			user = nil
		}
	}

	if user == nil {
		user, err = db.GetUserByUsername(ctx, userInfo.Username)
		if err != nil && err != database.ErrUserNotFound {
			logging.DB.WithFields(
				"username", userInfo.Username,
				"error", err.Error(),
			).Error("Database error while looking up user by username")
			return nil, err
		}
		if err == database.ErrUserNotFound {
			user = nil
		}
	}

	// If user doesn't exist, create one
	if user == nil {
		// Generate a secure random password (user will login via OAuth)
		randomPassword, err := GenerateRandomString(32)
		if err != nil {
			logging.Auth.OAuth.WithFields(
				"error", err.Error(),
			).Error("Failed to generate random password for OAuth user")
			return nil, err
		}

		passwordHash, err := HashPassword(randomPassword)
		if err != nil {
			logging.Auth.OAuth.WithFields(
				"error", err.Error(),
			).Error("Failed to hash random password for OAuth user")
			return nil, err
		}

		// Create new user with read-only permissions by default
		now := time.Now()
		newUser := &database.User{
			Username:      userInfo.Username,
			Email:         userInfo.Email,
			PasswordHash:  passwordHash,
			Permissions:   int64(database.PermReadOnly), // Default to read-only permissions
			Active:        true,
			LastLogin:     &now,
			OAuthProvider: optionalString(provider),
			OAuthSubject:  optionalString(subject),
		}

		if granted, revoked := syncAdminPermissionsFromGroups(newUser, userInfo.Groups); granted || revoked {
			logging.Auth.OAuth.WithFields(
				"username", newUser.Username,
				"group", config.AuthentikAdminGroup,
				"granted", granted,
				"revoked", revoked,
			).Info("Synced admin permissions from Authentik group during user creation")
		}

		if err := db.CreateUser(ctx, newUser); err != nil {
			logging.DB.WithFields(
				"username", userInfo.Username,
				"email", userInfo.Email,
				"error", err.Error(),
			).Error("Failed to create user from OAuth information")
			return nil, err
		}

		logging.Auth.OAuth.WithFields(
			"user_id", newUser.ID,
			"username", newUser.Username,
		).Info("New user created from OAuth information")

		return newUser, nil
	}

	// Update last login time
	now := time.Now()
	user.LastLogin = &now
	if provider != "" {
		user.OAuthProvider = optionalString(provider)
	}
	if subject != "" {
		user.OAuthSubject = optionalString(subject)
	}

	if granted, revoked := syncAdminPermissionsFromGroups(user, userInfo.Groups); granted || revoked {
		logging.Auth.OAuth.WithFields(
			"user_id", user.ID,
			"username", user.Username,
			"group", config.AuthentikAdminGroup,
			"granted", granted,
			"revoked", revoked,
		).Info("Synced admin permissions from Authentik group")
	}

	if err := db.UpdateUser(ctx, user); err != nil {
		logging.DB.WithFields(
			"user_id", user.ID,
			"username", user.Username,
			"error", err.Error(),
		).Warn("Failed to update last login time for OAuth user")
	}

	logging.Auth.OAuth.WithFields(
		"user_id", user.ID,
		"username", user.Username,
	).Info("Existing user updated from OAuth information")

	return user, nil
}
