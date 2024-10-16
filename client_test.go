package fmc

import (
	"errors"
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"gopkg.in/h2non/gock.v1"
)

const (
	testURL = "https://10.0.0.1"
)

func testClient() Client {
	defer gock.Off()

	// Client will try to get FMC version on creation, so we need to mock those
	gock.New(testURL).Post("/api/fmc_platform/v1/auth/generatetoken").Reply(204)
	gock.New(testURL).Get("/api/fmc_platform/v1/info/serverversion").Reply(200).BodyString(`{"items":[{"serverVersion":"7.2.4 (build 123)"}]}`)

	// Prepare client and intercept
	httpClient := &http.Client{}
	gock.InterceptClient(httpClient)

	// Create client
	client, _ := NewClient(testURL, "usr", "pwd", CustomHttpClient(httpClient), MaxRetries(0))

	return client
}

func authenticatedTestClient() Client {
	client := testClient()
	client.AuthToken = "ABC"
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
	gock.New(testURL).Post("/api/fmc_platform/v1/auth/generatetoken").Reply(204)
	gock.New(testURL).Get("/api/fmc_platform/v1/info/serverversion").Reply(200).BodyString(`{"items":[{"serverVersion":"7.2.4 (build 123)"}]}`)

	// Prepare client and intercept
	httpClient := &http.Client{}
	gock.InterceptClient(httpClient)

	// Create client
	client, _ := NewClient(testURL, "usr", "pwd", CustomHttpClient(httpClient), RequestTimeout(120))
	assert.Equal(t, client.HttpClient.Timeout, 120*time.Second)
}

// TestClientLogin tests the Client::Login method.
func TestClientLogin(t *testing.T) {
	defer gock.Off()
	client := testClient()

	// Successful login
	gock.New(testURL).Post("/api/fmc_platform/v1/auth/generatetoken").Reply(204)
	assert.NoError(t, client.Login())

	// Unsuccessful token retrieval
	gock.New(testURL).Post("/api/fmc_platform/v1/auth/generatetoken").Reply(401)
	assert.Error(t, client.Login())
}

// TestClientGetFMCVersion tests the Client::GetFMCVersion method.
func TestClientGetFMCVersion(t *testing.T) {
	defer gock.Off()
	client := testClient()

	// Version already known
	assert.Equal(t, "7.2.4 (build 123)", client.FMCVersion)
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

	// URL global domain uuid
	gock.New(testURL).Get("/url/DEF456/").Reply(200)
	_, err = client.Get("/url/{DOMAIN_UUID}/", DomainName("dom1"))
	assert.NoError(t, err)

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
