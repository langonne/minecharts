package database

import "strings"

const apiKeyBcryptCost = 14

func extractAPIKeyID(fullKey string) string {
	if idx := strings.Index(fullKey, "."); idx >= 0 && idx < len(fullKey)-1 {
		return fullKey[idx+1:]
	}
	return fullKey
}

func maskKeyForLog(key string) string {
	if len(key) <= 8 {
		return key
	}
	return key[:4] + "..." + key[len(key)-4:]
}
