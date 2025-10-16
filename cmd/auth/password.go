package auth

import (
	"crypto/rand"
	"encoding/base64"
	"errors"

	"minecharts/cmd/logging"

	"golang.org/x/crypto/bcrypt"
)

const bcryptCost = 14

var (
	ErrInvalidPassword = errors.New("invalid password")
)

// HashPassword creates a bcrypt hash of the password
func HashPassword(password string) (string, error) {
	logging.Auth.Password.Debug("Hashing password")

	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcryptCost)
	if err != nil {
		logging.Auth.Password.WithFields(
			"error", err.Error(),
			"bcrypt_cost", bcrypt.DefaultCost,
		).Error("Failed to hash password")
		return "", err
	}

	logging.Auth.Password.Debug("Password hashed successfully")
	return string(hash), nil
}

// VerifyPassword compares a bcrypt hashed password with its possible plaintext equivalent
func VerifyPassword(hashedPassword, password string) error {
	logging.Auth.Password.Debug("Verifying password")

	err := bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(password))
	if err != nil {
		logging.Auth.Password.WithFields(
			"error", err.Error(),
		).Debug("Password verification failed")
		return err
	}

	logging.Auth.Password.Debug("Password verification successful")
	return nil
}

// GenerateRandomString returns a URL-safe, base64 encoded
// random string of the specified length
func GenerateRandomString(length int) (string, error) {
	logging.Auth.Password.WithFields(
		"length", length,
	).Debug("Generating random string")

	b := make([]byte, length)
	_, err := rand.Read(b)
	if err != nil {
		logging.Auth.Password.WithFields(
			"error", err.Error(),
			"length", length,
		).Error("Failed to generate random string")
		return "", err
	}

	result := base64.URLEncoding.EncodeToString(b)[:length]
	logging.Auth.Password.WithFields(
		"length", length,
	).Debug("Random string generated successfully")

	return result, nil
}

// GenerateAPIKey creates a new API key with the specified prefix
func GenerateAPIKey(prefix string) (string, error) {
	logging.API.Keys.WithFields(
		"prefix", prefix,
	).Debug("Generating API key")

	randomPart, err := GenerateRandomString(32)
	if err != nil {
		logging.API.Keys.WithFields(
			"error", err.Error(),
			"prefix", prefix,
		).Error("Failed to generate API key")
		return "", err
	}

	apiKey := prefix + "." + randomPart
	logging.API.Keys.WithFields(
		"prefix", prefix,
		"key_length", len(apiKey),
	).Debug("API key generated successfully")

	return apiKey, nil
}

// HashAPIKey hashes an API key using bcrypt so the raw value is not stored.
func HashAPIKey(key string) (string, error) {
	logging.API.Keys.Debug("Hashing API key for storage")
	hash, err := bcrypt.GenerateFromPassword([]byte(key), bcryptCost)
	if err != nil {
		logging.API.Keys.WithFields(
			"error", err.Error(),
		).Error("Failed to hash API key")
		return "", err
	}
	return string(hash), nil
}

// VerifyAPIKey compares a hashed API key with the provided plaintext value.
func VerifyAPIKey(hashedKey, key string) error {
	logging.API.Keys.Debug("Verifying API key against stored hash")
	return bcrypt.CompareHashAndPassword([]byte(hashedKey), []byte(key))
}
