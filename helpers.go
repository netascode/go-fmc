package fmc

import (
	"math/rand/v2"
	"net/url"
	"strconv"
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

// pathWithOffset returns path with the offset and limit query parameters set,
// replacing them if they are already present.
func pathWithOffset(path string, offset, limit int) string {
	u, err := url.Parse(path)
	if err != nil {
		return path
	}

	q := u.Query()
	q.Set("offset", strconv.Itoa(offset))
	q.Set("limit", strconv.Itoa(limit))
	u.RawQuery = q.Encode()

	return u.String()
}

// hasQueryParam reports whether path carries the named query parameter.
func hasQueryParam(path, param string) bool {
	u, err := url.Parse(path)
	if err != nil {
		return false
	}

	_, ok := u.Query()[param]
	return ok
}
