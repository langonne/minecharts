package database

import (
	"database/sql"
	"time"
)

type rowScanner interface {
	Scan(dest ...any) error
}

func scanUser(scanner rowScanner) (*User, error) {
	var (
		user          User
		lastLogin     sql.NullTime
		oauthProvider sql.NullString
		oauthSubject  sql.NullString
	)

	err := scanner.Scan(
		&user.ID,
		&user.Username,
		&user.Email,
		&user.PasswordHash,
		&user.Permissions,
		&user.Active,
		&lastLogin,
		&user.CreatedAt,
		&user.UpdatedAt,
		&oauthProvider,
		&oauthSubject,
	)
	if err != nil {
		return nil, err
	}

	if lastLogin.Valid {
		user.LastLogin = &lastLogin.Time
	}

	if oauthProvider.Valid {
		val := oauthProvider.String
		user.OAuthProvider = &val
	}

	if oauthSubject.Valid {
		val := oauthSubject.String
		user.OAuthSubject = &val
	}

	return &user, nil
}

func nullableTime(t *time.Time) any {
	if t == nil {
		return nil
	}
	return *t
}

func nullableString(s *string) any {
	if s == nil {
		return nil
	}
	return *s
}
