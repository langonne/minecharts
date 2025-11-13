package secrets

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"strings"
)

const jwtSecretFilename = "jwt.secret"

// LoadOrCreateJWTSecret returns a persisted JWT signing key located under the provided data directory.
// It creates the directory/file if needed and indicates whether a new key was generated.
func LoadOrCreateJWTSecret(dataDir string) (secret string, secretPath string, generated bool, err error) {
	dir := strings.TrimSpace(dataDir)
	if dir == "" {
		dir = "./app/data"
	}

	if err = os.MkdirAll(dir, 0755); err != nil {
		return "", "", false, err
	}

	secretPath = filepath.Join(dir, jwtSecretFilename)

	if secretBytes, readErr := os.ReadFile(secretPath); readErr == nil {
		if decoded := strings.TrimSpace(string(secretBytes)); decoded != "" {
			return decoded, secretPath, false, nil
		}
	} else if !errors.Is(readErr, os.ErrNotExist) {
		return "", secretPath, false, readErr
	}

	randomBytes := make([]byte, 32)
	if _, err = rand.Read(randomBytes); err != nil {
		return "", secretPath, false, err
	}

	encoded := base64.StdEncoding.EncodeToString(randomBytes)
	if err = os.WriteFile(secretPath, []byte(encoded), 0600); err != nil {
		return "", secretPath, false, err
	}

	return encoded, secretPath, true, nil
}
