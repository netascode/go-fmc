package fmc

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGenerateRequestID(t *testing.T) {
	const charset = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"

	id := generateRequestID(16)
	assert.Len(t, id, 16)
	for _, c := range id {
		assert.Contains(t, charset, string(c))
	}

	assert.Equal(t, "", generateRequestID(0))

	// Two generated IDs should not collide in practice.
	assert.NotEqual(t, generateRequestID(8), generateRequestID(8))
}

func TestIsRetryableStatus(t *testing.T) {
	tests := []struct {
		name string
		code int
		want bool
	}{
		{"too many requests", 429, true},
		{"internal server error", 500, true},
		{"bad gateway", 502, true},
		{"gateway timeout upper bound", 599, true},
		{"ok", 200, false},
		{"bad request", 400, false},
		{"not found", 404, false},
		{"just below server error range", 499, false},
		{"just above server error range", 600, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, isRetryableStatus(tt.code))
		})
	}
}

func TestPathWithOffset(t *testing.T) {
	tests := []struct {
		name   string
		path   string
		offset int
		limit  int
		want   string
	}{
		{"no existing query", "/api/fmc_config/v1/domain/x/objects/hosts", 0, 25, "/api/fmc_config/v1/domain/x/objects/hosts?limit=25&offset=0"},
		{"replaces existing offset and limit", "/api/fmc_config/v1/domain/x/objects/hosts?limit=10&offset=5", 25, 50, "/api/fmc_config/v1/domain/x/objects/hosts?limit=50&offset=25"},
		{"preserves other query params", "/api/fmc_config/v1/domain/x/objects/hosts?expanded=true", 10, 20, "/api/fmc_config/v1/domain/x/objects/hosts?expanded=true&limit=20&offset=10"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, pathWithOffset(tt.path, tt.offset, tt.limit))
		})
	}

	t.Run("invalid path is returned unchanged", func(t *testing.T) {
		invalid := "http://[::1]:namedport"
		assert.Equal(t, invalid, pathWithOffset(invalid, 0, 25))
	})
}

func TestHasQueryParam(t *testing.T) {
	tests := []struct {
		name  string
		path  string
		param string
		want  bool
	}{
		{"param present", "/api/objects/hosts?offset=0&limit=25", "offset", true},
		{"param absent", "/api/objects/hosts?limit=25", "offset", false},
		{"no query at all", "/api/objects/hosts", "offset", false},
		{"param present with empty value", "/api/objects/hosts?offset=", "offset", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, hasQueryParam(tt.path, tt.param))
		})
	}

	t.Run("invalid path returns false", func(t *testing.T) {
		assert.False(t, hasQueryParam("http://[::1]:namedport", "offset"))
	})
}
