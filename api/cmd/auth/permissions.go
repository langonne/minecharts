package auth

import (
	"fmt"
	"strconv"
	"strings"
	"sync"

	"minecharts/cmd/config"
	"minecharts/cmd/database"
	"minecharts/cmd/logging"
)

var (
	defaultUserPermissionsOnce   sync.Once
	defaultUserPermissions       int64
	authentikUserPermissionsOnce sync.Once
	authentikUserPermissions     int64
	permissionAliases            = map[string]int64{
		"none":     0,
		"read":     int64(database.PermReadOnly),
		"readonly": int64(database.PermReadOnly),
		"view":     int64(database.PermReadOnly),
		"operator": int64(database.PermOperator),
		"ops":      int64(database.PermOperator),
		"all":      int64(database.PermAll),
		"admin":    int64(database.PermAll),
	}
)

func parsePermissionSpec(raw string, fallback int64) (int64, error) {
	value := strings.TrimSpace(strings.ToLower(raw))
	if value == "" {
		return fallback, nil
	}

	if alias, ok := permissionAliases[value]; ok {
		return alias, nil
	}

	parsed, err := strconv.ParseInt(value, 10, 64)
	if err != nil {
		return fallback, fmt.Errorf("invalid permission value %q: %w", raw, err)
	}

	return parsed, nil
}

func stripAdminBit(permissions int64) (int64, bool) {
	if permissions&int64(database.PermAdmin) == 0 {
		return permissions, false
	}
	return permissions &^ int64(database.PermAdmin), true
}

// DefaultUserPermissions resolves the configured default permissions for new users.
// The admin bit is always stripped to avoid accidental escalation.
func DefaultUserPermissions() int64 {
	defaultUserPermissionsOnce.Do(func() {
		resolved, err := parsePermissionSpec(config.DefaultUserPermissions, int64(database.PermOperator))
		if err != nil {
			logging.Auth.WithFields(
				"source", "default_user_permissions",
				"raw", config.DefaultUserPermissions,
				"fallback", int64(database.PermOperator),
			).Warn("Invalid default user permissions configuration, using fallback")
			resolved = int64(database.PermOperator)
		}

		resolved, stripped := stripAdminBit(resolved)
		if stripped {
			logging.Auth.WithFields(
				"source", "default_user_permissions",
				"raw", config.DefaultUserPermissions,
				"resolved", resolved,
			).Warn("Admin bit stripped from default user permissions configuration")
		}

		defaultUserPermissions = resolved
	})

	return defaultUserPermissions
}

// AuthentikUserPermissions resolves the permissions to apply when a user is in the
// configured Authentik non-admin group. Falls back to the default user permissions
// when unset. The admin bit is always stripped.
func AuthentikUserPermissions() int64 {
	authentikUserPermissionsOnce.Do(func() {
		fallback := DefaultUserPermissions()
		raw := config.AuthentikUserPermissions
		if strings.TrimSpace(raw) == "" {
			authentikUserPermissions = fallback
			return
		}

		resolved, err := parsePermissionSpec(raw, fallback)
		if err != nil {
			logging.Auth.WithFields(
				"source", "authentik_user_permissions",
				"raw", raw,
				"fallback", fallback,
			).Warn("Invalid Authentik user permissions configuration, using fallback")
			resolved = fallback
		}

		resolved, stripped := stripAdminBit(resolved)
		if stripped {
			logging.Auth.WithFields(
				"source", "authentik_user_permissions",
				"raw", raw,
				"resolved", resolved,
			).Warn("Admin bit stripped from Authentik user permissions configuration")
		}

		authentikUserPermissions = resolved
	})

	return authentikUserPermissions
}

func hasGroupMembership(groups []string, target string) bool {
	target = strings.TrimSpace(target)
	if target == "" {
		return false
	}

	for _, group := range groups {
		if strings.EqualFold(strings.TrimSpace(group), target) {
			return true
		}
	}
	return false
}

// syncUserPermissionsFromGroups applies the Authentik user-group permissions when
// membership is present, or reverts to the default user permissions when absent.
// Returns (applied, reset) to indicate changes.
func syncUserPermissionsFromGroups(user *database.User, groups []string) (bool, bool) {
	if !config.AuthentikGroupSyncEnabled {
		return false, false
	}

	userGroup := strings.TrimSpace(config.AuthentikUserGroup)
	if userGroup == "" {
		return false, false
	}

	inGroup := hasGroupMembership(groups, userGroup)
	target := DefaultUserPermissions()
	action := "default_user_permissions"

	if inGroup {
		target = AuthentikUserPermissions()
		action = "authentik_user_permissions"
	}

	// Preserve admin bit if it was set by the admin group sync.
	target |= user.Permissions & int64(database.PermAdmin)

	if user.Permissions == target {
		return false, false
	}

	user.Permissions = target

	if inGroup {
		logging.Auth.OAuth.WithFields(
			"user_id", user.ID,
			"username", user.Username,
			"group", userGroup,
			"action", action,
			"permissions", target,
		).Info("Synced user permissions from Authentik group")
		return true, false
	}

	logging.Auth.OAuth.WithFields(
		"user_id", user.ID,
		"username", user.Username,
		"action", action,
		"permissions", target,
	).Info("Applied default user permissions after Authentik group sync")
	return false, true
}
