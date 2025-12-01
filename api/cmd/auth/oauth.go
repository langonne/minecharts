package auth

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
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

type oidcDiscovery struct {
	AuthURL     string
	TokenURL    string
	UserInfoURL string
}

// NewOIDCProvider creates a single configured OAuth/OIDC provider using discovery.
func NewOIDCProvider() (*OAuthProvider, error) {
	providerName := strings.TrimSpace(config.OAuthProviderName)
	if providerName == "" {
		logging.Auth.OAuth.Error("OIDC provider name is not configured")
		return nil, ErrMissingProviderConfig
	}

	logging.Auth.OAuth.WithFields("provider", providerName).Debug("Initializing OIDC provider")

	if !config.OAuthEnabled {
		logging.Auth.OAuth.WithFields(
			"provider", providerName,
		).Warn("OIDC provider is not enabled")
		return nil, ErrOAuthNotEnabled
	}

	if config.OIDCClientID == "" || config.OIDCClientSecret == "" ||
		config.OIDCIssuer == "" || config.OIDCRedirectURL == "" {
		logging.Auth.OAuth.WithFields(
			"provider", providerName,
			"client_id_set", config.OIDCClientID != "",
			"client_secret_set", config.OIDCClientSecret != "",
			"issuer_set", config.OIDCIssuer != "",
			"redirect_url_set", config.OIDCRedirectURL != "",
		).Error("OIDC provider configuration is incomplete")
		return nil, ErrMissingProviderConfig
	}

	endpoints, err := discoverOIDCEndpoints(config.OIDCIssuer)
	if err != nil {
		logging.Auth.OAuth.WithFields(
			"provider", providerName,
			"issuer", config.OIDCIssuer,
			"error", err.Error(),
		).Error("Failed to discover OIDC endpoints from issuer")
		return nil, ErrInvalidOAuthConfig
	}

	// Construct OAuth2 config
	oauthConfig := &oauth2.Config{
		ClientID:     config.OIDCClientID,
		ClientSecret: config.OIDCClientSecret,
		RedirectURL:  config.OIDCRedirectURL,
		Scopes:       []string{"openid", "email", "profile"},
		Endpoint: oauth2.Endpoint{
			AuthURL:  endpoints.AuthURL,
			TokenURL: endpoints.TokenURL,
		},
	}

	logging.Auth.OAuth.WithFields(
		"provider", providerName,
		"issuer", config.OIDCIssuer,
		"redirect_url", config.OIDCRedirectURL,
		"auth_url", endpoints.AuthURL,
		"token_url", endpoints.TokenURL,
		"userinfo_url", endpoints.UserInfoURL,
	).Info("OIDC provider initialized successfully")

	return &OAuthProvider{
		Config:      oauthConfig,
		Name:        providerName,
		UserInfoURL: endpoints.UserInfoURL,
	}, nil
}

// GetAuthURL returns the URL to redirect the user to for authorization
func (p *OAuthProvider) GetAuthURL(state string) string {
	url := p.Config.AuthCodeURL(state, oauth2.AccessTypeOnline)

	logging.Auth.OAuth.WithFields(
		"url", url,
		"state", state,
		"provider", p.Name,
	).Debug("Generated OAuth authorization URL")

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
	logging.Auth.OAuth.WithFields("provider", p.Name).Debug("Fetching user info from OAuth provider")

	client := p.Config.Client(ctx, token)

	// Get user info from the provider's userinfo endpoint
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
		"provider", p.Name,
		"username", username,
	).Debug("Successfully retrieved user info from OAuth provider")

	return &OAuthUserInfo{
		ID:            userInfo.Sub,
		Email:         userInfo.Email,
		Username:      username,
		Name:          userInfo.Name,
		EmailVerified: userInfo.EmailVerified,
		Provider:      p.Name,
		Groups:        userInfo.Groups,
	}, nil
}

func discoverOIDCEndpoints(rawIssuer string) (*oidcDiscovery, error) {
	trimmed := strings.TrimSpace(rawIssuer)
	if trimmed == "" {
		return nil, ErrInvalidOAuthConfig
	}

	base := strings.TrimRight(trimmed, "/")
	wellKnown := base + "/.well-known/openid-configuration"

	client := http.Client{Timeout: 10 * time.Second}
	resp, err := client.Get(wellKnown)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, ErrInvalidOAuthConfig
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var metadata struct {
		AuthorizationEndpoint string `json:"authorization_endpoint"`
		TokenEndpoint         string `json:"token_endpoint"`
		UserInfoEndpoint      string `json:"userinfo_endpoint"`
	}

	if err := json.Unmarshal(body, &metadata); err != nil {
		return nil, err
	}

	if metadata.AuthorizationEndpoint == "" || metadata.TokenEndpoint == "" || metadata.UserInfoEndpoint == "" {
		return nil, ErrInvalidOAuthConfig
	}

	return &oidcDiscovery{
		AuthURL:     strings.TrimSpace(metadata.AuthorizationEndpoint),
		TokenURL:    strings.TrimSpace(metadata.TokenEndpoint),
		UserInfoURL: strings.TrimSpace(metadata.UserInfoEndpoint),
	}, nil
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
			Permissions:   DefaultUserPermissions(),
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
			).Info("Synced admin permissions from configured group during user creation")
		}

		syncUserPermissionsFromGroups(newUser, userInfo.Groups)

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
		).Info("Synced admin permissions from configured group")
	}

	syncUserPermissionsFromGroups(user, userInfo.Groups)

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
