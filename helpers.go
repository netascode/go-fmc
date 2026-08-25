package fmc

import (
	"math/rand/v2"
	"strconv"
	"strings"
)

// generate random string
func generateRequestID(length int) string {
	const charset = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
	b := make([]byte, length)
	for i := range b {
		b[i] = charset[rand.IntN(len(charset))]
	}
	return string(b)
}

// checks if the HTTP status code is retryable
func isRetryableStatus(code int) bool {
	return code == 429 || (code >= 500 && code <= 599)
}

// Create URL path with offset and limit
func pathWithOffset(path string, offset, limit int) string {
	sep := "?"
	if strings.Contains(path, sep) {
		sep = "&"
	}

	return path + sep + "offset=" + strconv.Itoa(offset) + "&limit=" + strconv.Itoa(limit)
}

// hasQueryParam checks if a URL path contains a specific query parameter name.
func hasQueryParam(path, param string) bool {
	return strings.Contains(path, "?"+param+"=") || strings.Contains(path, "&"+param+"=")
}
