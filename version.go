// Package fmc version information
package fmc

// Current version of the go-fmc library
const Version = "0.2.2"

// defaultUserAgent returns the user agent string for HTTP requests
func defaultUserAgent() string {
	return "go-fmc/" + Version + " netascode"
}
