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

func testClientCDFMC() Client {
	defer gock.Off()

	// Client will try to get FMC version on creation, so we need to mock those
	gock.New(testURL).Get("/api/fmc_platform/v1/info/domain").Reply(200).BodyString(`{"items":[{"uuid": "ABC123","name": "Global",}]}`)
	gock.New(testURL).Get("/api/fmc_platform/v1/info/serverversion").Reply(200).BodyString(`{"items":[{"serverVersion":"7.7.0 (build 123)"}]}`)

	// Prepare client and intercept
	httpClient := &http.Client{}
	gock.InterceptClient(httpClient)

	// Create client
	client, _ := NewClientCDFMC(testURL, "usr", CustomHttpClient(httpClient), MaxRetries(0))

	return client
}

func TestNewClientCDFMC(t *testing.T) {
	defer gock.Off()

	// Client will try to get FMC version on creation, so we need to mock those
	gock.New(testURL).Get("/api/fmc_platform/v1/info/domain").Reply(200).BodyString(`{"items":[{"uuid": "e276abec-e0f2-11e3-8169-6d9ed49b625f","name": "Global",}]}`)
	gock.New(testURL).Get("/api/fmc_platform/v1/info/serverversion").Reply(200).BodyString(`{"items":[{"serverVersion":"7.7.0 (build 123)"}]}`)

	// Prepare client and intercept
	httpClient := &http.Client{}
	gock.InterceptClient(httpClient)

	// Create client
	client, ok := NewClientCDFMC(testURL, "usr", CustomHttpClient(httpClient), RequestTimeout(120))
	assert.NoError(t, ok)
	assert.Equal(t, client.HttpClient.Timeout, 120*time.Second)
}

// TestClientGetFMCVersion tests the Client::GetFMCVersion method.
func TestClientCDFMCGetFMCVersion(t *testing.T) {
	defer gock.Off()
	client := testClientCDFMC()

	// Version already known
	assert.Equal(t, "7.7.0 (build 123)", client.FMCVersion)
}

func TestClientCDFMCGet(t *testing.T) {
	defer gock.Off()
	client := testClientCDFMC()
	var err error

	// Success
	gock.New(testURL).Get("/url").Reply(200)
	_, err = client.Get("/url")
	assert.NoError(t, err)

	// URL global domain uuid
	gock.New(testURL).Get("/url/ABC123/").Reply(200)
	_, err = client.Get("/url/{DOMAIN_UUID}/")
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

func TestClientCDFMCGetRetry(t *testing.T) {
	defer gock.Off()
	var err error

	// Client will try to get FMC version on creation, so we need to mock those
	gock.New(testURL).Get("/api/fmc_platform/v1/info/domain").Reply(200).BodyString(`{"items":[{"uuid": "ABC123","name": "Global",}]}`)
	gock.New(testURL).Get("/api/fmc_platform/v1/info/serverversion").Reply(200).BodyString(`{"items":[{"serverVersion":"7.7.0 (build 123)"}]}`)

	// Prepare client and intercept
	httpClient := &http.Client{}
	gock.InterceptClient(httpClient)

	// Create client
	client, _ := NewClientCDFMC(testURL, "pwd", CustomHttpClient(httpClient), MaxRetries(3), BackoffMinDelay(0))
	client.authToken = "ABC"

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

func TestClientCDFMCDelete(t *testing.T) {
	defer gock.Off()
	client := testClientCDFMC()

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

func TestClientCDFMCPost(t *testing.T) {
	defer gock.Off()
	client := testClientCDFMC()

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

func TestClientCDFMCPut(t *testing.T) {
	defer gock.Off()
	client := testClientCDFMC()

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
