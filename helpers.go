package fmc

import "crypto/rand"

// defaultUserAgent returns the user agent string for HTTP requests
func defaultUserAgent() string {
	return "go-fmc/" + Version + " netascode"
}

// generate random string
func generateRequestID(length int) string {
	const charset = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
	b := make([]byte, length)
	rand.Read(b)
	for i := range b {
		b[i] = charset[b[i]%byte(len(charset))]
	}
	return string(b)
}
