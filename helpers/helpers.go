package helpers

import "regexp"

// Helper function to validate keyPrefix
func IsValidKeyPrefix(keyPrefix string) bool {
	// Allow only alphanumeric characters and hyphens
	matched, _ := regexp.MatchString("^[a-zA-Z0-9-]+$", keyPrefix)
	return matched && len(keyPrefix) <= 50
}
