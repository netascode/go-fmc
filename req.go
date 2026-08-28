package fmc

import (
	"net/http"
)

// Req wraps http.Request for API requests.
type Req struct {
	// HttpReq is the *http.Request object.
	HttpReq *http.Request
	// LogPayload indicates whether logging of payloads should be enabled.
	LogPayload bool
	// DomainName is the FMC domain to be used for the request.
	DomainName string
	// ID for the request.
	RequestID string
}

// NoLogPayload prevents logging of payloads.
// Primarily used by the Login and Refresh methods where this could expose secrets.
func NoLogPayload(req *Req) {
	req.LogPayload = false
}

// DomainName modifies the domain to be used for the request.
func DomainName(x string) func(*Req) {
	return func(req *Req) {
		req.DomainName = x
	}
}

// Set request ID
func RequestID(x string) func(*Req) {
	return func(req *Req) {
		req.RequestID = x
	}
}
