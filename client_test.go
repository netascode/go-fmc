package fmc

import (
	"errors"
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"golang.org/x/time/rate"
	"gopkg.in/h2non/gock.v1"
)

const (
	testURL = "https://10.0.0.1"
)

// Must be applied after NewClient returns, not as a modifier: NewClient applies
// modifiers before reading the FMC version, then overwrites RateLimiter for 7.4.1+.
func disableRateLimit(client *Client) {
	client.RateLimiter = rate.NewLimiter(rate.Inf, 1)
}

func newTestClient(fmcVersion string) Client {
	defer gock.Off()

	// Client will try to get FMC version on creation, so we need to mock those
	gock.New(testURL).Post("/api/fmc_platform/v1/auth/generatetoken").Reply(204).SetHeader("X-auth-access-token", "ABC")
	gock.New(testURL).Get("/api/fmc_platform/v1/info/serverversion").Reply(200).BodyString(`{"items":[{"serverVersion":"` + fmcVersion + `"}]}`)

	// Prepare client and intercept
	httpClient := &http.Client{}
	gock.InterceptClient(httpClient)

	// Create client
	client, _ := NewClient(testURL, "usr", "pwd", CustomHttpClient(httpClient), MaxRetries(0))

	return client
}

func testClient() Client {
	client := newTestClient("7.2.4 (build 123)")
	disableRateLimit(&client)
	return client
}

func authenticatedTestClient() Client {
	client := testClient()
	client.authToken = "ABC"
	client.LastRefresh = time.Now()
	client.RefreshCount = 0
	client.DomainUUID = "ABC123"
	client.Domains = map[string]string{"dom1": "DEF456"}
	return client
}

// ErrReader implements the io.Reader interface and fails on Read.
type ErrReader struct{}

// Read mocks failing io.Reader test cases.
func (r ErrReader) Read(buf []byte) (int, error) {
	return 0, errors.New("fail")
}

// TestNewClient tests the NewClient function.
func TestNewClient(t *testing.T) {
	defer gock.Off()

	// Client will try to get FMC version on creation, so we need to mock those
	gock.New(testURL).Post("/api/fmc_platform/v1/auth/generatetoken").Reply(204).SetHeader("X-auth-access-token", "ABC")
	gock.New(testURL).Get("/api/fmc_platform/v1/info/serverversion").Reply(200).BodyString(`{"items":[{"serverVersion":"7.2.4 (build 123)"}]}`)

	// Prepare client and intercept
	httpClient := &http.Client{}
	gock.InterceptClient(httpClient)

	// Create client
	client, _ := NewClient(testURL, "usr", "pwd", CustomHttpClient(httpClient), RequestTimeout(120*time.Second))
	assert.Equal(t, 120*time.Second, client.HttpClient.Timeout)
}

// TestClientLogin tests the Client::Login method.
func TestClientLogin(t *testing.T) {
	defer gock.Off()
	client := testClient()

	// Successful login
	gock.New(testURL).Post("/api/fmc_platform/v1/auth/generatetoken").Reply(204).SetHeader("X-auth-access-token", "ABC")
	assert.NoError(t, client.login())

	// Unsuccessful token retrieval
	gock.New(testURL).Post("/api/fmc_platform/v1/auth/generatetoken").Reply(401)
	assert.Error(t, client.login())

	// A failed login must not leave a stale token behind
	assert.Empty(t, client.authToken)

	// Success reported by FMC, but no token returned
	gock.New(testURL).Post("/api/fmc_platform/v1/auth/generatetoken").Reply(204)
	assert.Error(t, client.login())
	assert.Empty(t, client.authToken)
}

// TestClientLoginRetry tests the retry behaviour of the Client::login method.
func TestClientLoginRetry(t *testing.T) {
	defer gock.Off()

	// Client will try to get FMC version on creation, so we need to mock those
	gock.New(testURL).Post("/api/fmc_platform/v1/auth/generatetoken").Reply(204).SetHeader("X-auth-access-token", "ABC")
	gock.New(testURL).Get("/api/fmc_platform/v1/info/serverversion").Reply(200).BodyString(`{"items":[{"serverVersion":"7.2.4 (build 123)"}]}`)

	// Prepare client and intercept
	httpClient := &http.Client{}
	gock.InterceptClient(httpClient)

	// Create client
	client, _ := NewClient(testURL, "usr", "pwd", CustomHttpClient(httpClient), MaxRetries(3), BackoffMinDelay(0))
	disableRateLimit(&client)

	// Server-side error, retried and eventually successful
	gock.Flush()
	gock.New(testURL).Post("/api/fmc_platform/v1/auth/generatetoken").Reply(500)
	gock.New(testURL).Post("/api/fmc_platform/v1/auth/generatetoken").Reply(204).
		SetHeader("X-auth-access-token", "ABC").
		SetHeader("X-auth-refresh-token", "DEF").
		SetHeader("DOMAIN_UUID", "ABC123").
		SetHeader("DOMAINS", `[{"name":"Global","uuid":"ABC123"}]`)
	assert.NoError(t, client.login())
	assert.True(t, gock.IsDone())
	assert.Equal(t, "ABC", client.authToken)
	assert.Equal(t, "DEF", client.refreshToken)
	assert.Equal(t, "ABC123", client.DomainUUID)
	assert.Equal(t, map[string]string{"Global": "ABC123"}, client.Domains)

	// Rate limiting, retried and eventually successful
	gock.Flush()
	gock.New(testURL).Post("/api/fmc_platform/v1/auth/generatetoken").Reply(429)
	gock.New(testURL).Post("/api/fmc_platform/v1/auth/generatetoken").Reply(204).SetHeader("X-auth-access-token", "ABC")
	assert.NoError(t, client.login())
	assert.True(t, gock.IsDone())

	// Server-side error, all attempts fail as re-try counter is exceeded
	gock.Flush()
	for i := 0; i < 4; i++ {
		gock.New(testURL).Post("/api/fmc_platform/v1/auth/generatetoken").Reply(503)
	}
	assert.Error(t, client.login())
	assert.True(t, gock.IsDone())

	// Invalid credentials are terminal, the second mock must remain unconsumed
	gock.Flush()
	gock.New(testURL).Post("/api/fmc_platform/v1/auth/generatetoken").Reply(401)
	gock.New(testURL).Post("/api/fmc_platform/v1/auth/generatetoken").Reply(204).SetHeader("X-auth-access-token", "ABC")
	assert.Error(t, client.login())
	assert.False(t, gock.IsDone())

	// Locked account / insufficient privileges is terminal, the second mock must remain unconsumed
	gock.Flush()
	gock.New(testURL).Post("/api/fmc_platform/v1/auth/generatetoken").Reply(403)
	gock.New(testURL).Post("/api/fmc_platform/v1/auth/generatetoken").Reply(204).SetHeader("X-auth-access-token", "ABC")
	assert.Error(t, client.login())
	assert.False(t, gock.IsDone())
}

// TestClientRefresh tests the Client::refresh method.
func TestClientRefresh(t *testing.T) {
	defer gock.Off()
	client := authenticatedTestClient()

	// Successful refresh
	gock.New(testURL).Post("/api/fmc_platform/v1/auth/refreshtoken").Reply(204).
		SetHeader("X-auth-access-token", "NEW").
		SetHeader("X-auth-refresh-token", "NEWREF")
	assert.NoError(t, client.refresh())
	assert.Equal(t, "NEW", client.authToken)
	assert.Equal(t, "NEWREF", client.refreshToken)
	assert.Equal(t, 1, client.RefreshCount)
	// FMC returned no domain UUID, the known one must be kept
	assert.Equal(t, "ABC123", client.DomainUUID)

	// Expired refresh token. Tokens must be left untouched,
	// so that Authenticate can fall back to a full login.
	gock.New(testURL).Post("/api/fmc_platform/v1/auth/refreshtoken").Reply(401)
	assert.Error(t, client.refresh())
	assert.Equal(t, "NEW", client.authToken)
	assert.Equal(t, "NEWREF", client.refreshToken)

	// Success reported by FMC, but no token returned
	gock.New(testURL).Post("/api/fmc_platform/v1/auth/refreshtoken").Reply(204)
	assert.Error(t, client.refresh())
	assert.Equal(t, "NEW", client.authToken)
}

// TestClientRefreshRetry tests the retry behaviour of the Client::refresh method.
func TestClientRefreshRetry(t *testing.T) {
	defer gock.Off()

	// Client will try to get FMC version on creation, so we need to mock those
	gock.New(testURL).Post("/api/fmc_platform/v1/auth/generatetoken").Reply(204).SetHeader("X-auth-access-token", "ABC")
	gock.New(testURL).Get("/api/fmc_platform/v1/info/serverversion").Reply(200).BodyString(`{"items":[{"serverVersion":"7.2.4 (build 123)"}]}`)

	// Prepare client and intercept
	httpClient := &http.Client{}
	gock.InterceptClient(httpClient)

	// Create client
	client, _ := NewClient(testURL, "usr", "pwd", CustomHttpClient(httpClient), MaxRetries(3), BackoffMinDelay(0))
	disableRateLimit(&client)

	// Server-side error, retried and eventually successful
	gock.Flush()
	gock.New(testURL).Post("/api/fmc_platform/v1/auth/refreshtoken").Reply(500)
	gock.New(testURL).Post("/api/fmc_platform/v1/auth/refreshtoken").Reply(204).SetHeader("X-auth-access-token", "NEW")
	assert.NoError(t, client.refresh())
	assert.True(t, gock.IsDone())
	assert.Equal(t, "NEW", client.authToken)

	// Server-side error, all attempts fail as re-try counter is exceeded
	gock.Flush()
	for i := 0; i < 4; i++ {
		gock.New(testURL).Post("/api/fmc_platform/v1/auth/refreshtoken").Reply(503)
	}
	assert.Error(t, client.refresh())
	assert.True(t, gock.IsDone())

	// Expired token is terminal, the second mock must remain unconsumed
	gock.Flush()
	gock.New(testURL).Post("/api/fmc_platform/v1/auth/refreshtoken").Reply(401)
	gock.New(testURL).Post("/api/fmc_platform/v1/auth/refreshtoken").Reply(204).SetHeader("X-auth-access-token", "NEW2")
	assert.Error(t, client.refresh())
	assert.False(t, gock.IsDone())
	assert.Equal(t, "NEW", client.authToken)
}

// TestClientAuthenticateRefreshLimit tests that Authenticate stops refreshing and
// does a full login once the refresh token has been used MaxTokenRefreshes times.
func TestClientAuthenticateRefreshLimit(t *testing.T) {
	defer gock.Off()
	client := authenticatedTestClient()

	// Below the limit, the refresh token is used
	client.RefreshCount = MaxTokenRefreshes - 1
	gock.New(testURL).Post("/api/fmc_platform/v1/auth/refreshtoken").Reply(204).SetHeader("X-auth-access-token", "REFRESHED")
	assert.NoError(t, client.Authenticate("ABC"))
	assert.Equal(t, "REFRESHED", client.authToken)
	assert.Equal(t, MaxTokenRefreshes, client.RefreshCount)
	assert.True(t, gock.IsDone())

	// At the limit, refresh must not be attempted at all. The refresh mock must
	// remain unconsumed and the token must come from a full login.
	gock.Flush()
	gock.New(testURL).Post("/api/fmc_platform/v1/auth/refreshtoken").Reply(204).SetHeader("X-auth-access-token", "REFRESHED2")
	gock.New(testURL).Post("/api/fmc_platform/v1/auth/generatetoken").Reply(204).SetHeader("X-auth-access-token", "LOGGEDIN")
	assert.NoError(t, client.Authenticate("REFRESHED"))
	assert.Equal(t, "LOGGEDIN", client.authToken)
	assert.Equal(t, 0, client.RefreshCount)
	assert.False(t, gock.IsDone())
}

// TestClientGetFMCVersion tests the Client::GetFMCVersion method.
func TestClientGetFMCVersion(t *testing.T) {
	defer gock.Off()
	client := testClient()

	// Version already known
	assert.Equal(t, "7.2.4 (build 123)", client.FMCVersion)

	// Version parsed
	assert.Equal(t, "7.2.4", client.FMCVersionParsed.String())
}

func TestClientRateLimitValue(t *testing.T) {
	defer gock.Off()

	// newTestClient is used instead of testClient, as the latter disables the rate limit

	// Check rate limit for version 7.2.4
	client := newTestClient("7.2.4 (build 123)")
	assert.InDelta(t, 1.97, float64(client.RateLimiter.Limit()), 0.01)

	// Check rate limit for version 7.7.0
	client = newTestClient("7.7.0 (build 123)")
	assert.InDelta(t, 4.90, float64(client.RateLimiter.Limit()), 0.01)
}

// TestClientGet tests the Client::Get method.
func TestClientGet(t *testing.T) {
	defer gock.Off()
	client := authenticatedTestClient()
	var err error

	// Success
	gock.New(testURL).Get("/url").Reply(200)
	_, err = client.Get("/url")
	assert.NoError(t, err)

	// URL global domain uuid
	gock.New(testURL).Get("/url/ABC123/").Reply(200)
	_, err = client.Get("/url/{DOMAIN_UUID}/")
	assert.NoError(t, err)

	// URL select existing domain
	gock.New(testURL).Get("/url/DEF456/").Reply(200)
	_, err = client.Get("/url/{DOMAIN_UUID}/", DomainName("dom1"))
	assert.NoError(t, err)

	// URL select non-existing domain
	_, err = client.Get("/url/{DOMAIN_UUID}/", DomainName("dom_does_not_exist"))
	assert.Error(t, err)

	// HTTP error
	gock.New(testURL).Get("/url").ReplyError(errors.New("fail"))
	_, err = client.Get("/url")
	assert.Error(t, err)

	// Invalid HTTP status code
	gock.New(testURL).Get("/url").Reply(405)
	_, err = client.Get("/url")
	assert.Error(t, err)

	// Error decoding response body
	gock.New(testURL).
		Get("/url").
		Reply(200).
		Map(func(res *http.Response) *http.Response {
			res.Body = io.NopCloser(ErrReader{})
			return res
		})
	_, err = client.Get("/url")
	assert.Error(t, err)
}

func TestClientGetRetry(t *testing.T) {
	defer gock.Off()
	var err error

	// Client will try to get FMC version on creation, so we need to mock those
	gock.New(testURL).Post("/api/fmc_platform/v1/auth/generatetoken").Reply(204).SetHeader("X-auth-access-token", "ABC")
	gock.New(testURL).Get("/api/fmc_platform/v1/info/serverversion").Reply(200).BodyString(`{"items":[{"serverVersion":"7.2.4 (build 123)"}]}`)

	// Prepare client and intercept
	httpClient := &http.Client{}
	gock.InterceptClient(httpClient)

	// Create client
	client, _ := NewClient(testURL, "usr", "pwd", CustomHttpClient(httpClient), MaxRetries(3), BackoffMinDelay(0))
	disableRateLimit(&client)
	client.authToken = "ABC"
	client.LastRefresh = time.Now()

	// Request should fail
	gock.New(testURL).Get("/url_400").Reply(400)
	_, err = client.Get("/url_400")
	assert.Error(t, err)

	// First request should fail, subsequent should be successful
	gock.New(testURL).Get("/url_400_try_again").Reply(400).BodyString(`{"error":{"category":"FRAMEWORK","messages":[{"description":"Search Service n.a. Please try again."}],"severity":"ERROR"}}`)
	gock.New(testURL).Get("/url_400_try_again").Reply(200)
	_, err = client.Get("/url_400_try_again")
	assert.NoError(t, err)

	// All requests should fail, as re-try counter is exceeded
	gock.New(testURL).Get("/url_400_try_again_exceed_limit").Reply(400).BodyString(`{"error":{"category":"FRAMEWORK","messages":[{"description":"Search Service n.a. Please try again."}],"severity":"ERROR"}}`)
	gock.New(testURL).Get("/url_400_try_again_exceed_limit").Reply(400).BodyString(`{"error":{"category":"FRAMEWORK","messages":[{"description":"Search Service n.a. Please try again."}],"severity":"ERROR"}}`)
	gock.New(testURL).Get("/url_400_try_again_exceed_limit").Reply(400).BodyString(`{"error":{"category":"FRAMEWORK","messages":[{"description":"Search Service n.a. Please try again."}],"severity":"ERROR"}}`)
	gock.New(testURL).Get("/url_400_try_again_exceed_limit").Reply(400).BodyString(`{"error":{"category":"FRAMEWORK","messages":[{"description":"Search Service n.a. Please try again."}],"severity":"ERROR"}}`)
	_, err = client.Get("/url_400_try_again_exceed_limit")
	assert.Error(t, err)

	// First three request should fail, final one should be successful
	gock.New(testURL).Get("/url_510").Reply(510)
	gock.New(testURL).Get("/url_510").Reply(510)
	gock.New(testURL).Get("/url_510").Reply(510)
	gock.New(testURL).Get("/url_510").Reply(200)
	_, err = client.Get("/url_510")
	assert.NoError(t, err)
}

// TestClientDeleteDn tests the Client::Delete method.
func TestClientDelete(t *testing.T) {
	defer gock.Off()
	client := authenticatedTestClient()

	// Success
	gock.New(testURL).
		Delete("/url").
		Reply(200)
	_, err := client.Delete("/url")
	assert.NoError(t, err)

	// HTTP error
	gock.New(testURL).
		Delete("/url").
		ReplyError(errors.New("fail"))
	_, err = client.Delete("/url")
	assert.Error(t, err)
}

// TestClientPost tests the Client::Post method.
func TestClientPost(t *testing.T) {
	defer gock.Off()
	client := authenticatedTestClient()

	var err error

	// Success
	gock.New(testURL).Post("/url").Reply(200)
	_, err = client.Post("/url", "{}")
	assert.NoError(t, err)

	// HTTP error
	gock.New(testURL).Post("/url").ReplyError(errors.New("fail"))
	_, err = client.Post("/url", "{}")
	assert.Error(t, err)

	// Invalid HTTP status code
	gock.New(testURL).Post("/url").Reply(405)
	_, err = client.Post("/url", "{}")
	assert.Error(t, err)

	// Error decoding response body
	gock.New(testURL).
		Post("/url").
		Reply(200).
		Map(func(res *http.Response) *http.Response {
			res.Body = io.NopCloser(ErrReader{})
			return res
		})
	_, err = client.Post("/url", "{}")
	assert.Error(t, err)
}

// TestClientPost tests the Client::Post method.
func TestClientPut(t *testing.T) {
	defer gock.Off()
	client := authenticatedTestClient()

	var err error

	// Success
	gock.New(testURL).Put("/url").Reply(200)
	_, err = client.Put("/url", "{}")
	assert.NoError(t, err)

	// HTTP error
	gock.New(testURL).Put("/url").ReplyError(errors.New("fail"))
	_, err = client.Put("/url", "{}")
	assert.Error(t, err)

	// Invalid HTTP status code
	gock.New(testURL).Put("/url").Reply(405)
	_, err = client.Put("/url", "{}")
	assert.Error(t, err)

	// Error decoding response body
	gock.New(testURL).
		Put("/url").
		Reply(200).
		Map(func(res *http.Response) *http.Response {
			res.Body = io.NopCloser(ErrReader{})
			return res
		})
	_, err = client.Put("/url", "{}")
	assert.Error(t, err)
}
