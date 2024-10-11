// Package fmc is a Cisco Secure FMC (Firewall Management Center) REST client library for Go.
package fmc

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"math"
	"math/rand"
	"net/http"
	"net/http/cookiejar"
	"strings"
	"sync"
	"time"

	"github.com/tidwall/gjson"

	"github.com/juju/ratelimit"
)

const DefaultMaxRetries int = 3
const DefaultBackoffMinDelay int = 2
const DefaultBackoffMaxDelay int = 60
const DefaultBackoffDelayFactor float64 = 3

// Client is an HTTP FMC client.
// Use fmc.NewClient to initiate a client.
// This will ensure proper cookie handling and processing of modifiers.
//
// Requests are protected from concurrent writing (concurrent DELETE/POST/PUT),
// across all API paths. Any GET requests, or requests from different clients
// are not protected against concurrent writing.
type Client struct {
	// HttpClient is the *http.Client used for API requests.
	HttpClient *http.Client
	// Url is the FMC IP or hostname, e.g. https://10.0.0.1:443 (port is optional).
	Url string
	// Authentication token is the current authentication token
	AuthToken string
	// Refresh token is the current authentication token
	RefreshToken string
	// Usr is the FMC username.
	Usr string
	// Pwd is the FMC password.
	Pwd string
	// Insecure determines if insecure https connections are allowed.
	Insecure bool
	// Maximum number of retries
	MaxRetries int
	// Minimum delay between two retries
	BackoffMinDelay int
	// Maximum delay between two retries
	BackoffMaxDelay int
	// Backoff delay factor
	BackoffDelayFactor float64
	// Authentication mutex
	authenticationMutex *sync.Mutex
	// LastRefresh is the timestamp of the last authentication token refresh
	LastRefresh time.Time
	// RefreshCount is the number to authentication token refreshes with the same refresh token
	RefreshCount int
	// DomainUUID is the UUID of the global domain returned when generating a token
	DomainUUID string
	// Map of domain names to domain UUIDs
	Domains map[string]string

	RateLimiterBucket *ratelimit.Bucket

	// writingMutex protects against concurrent DELETE/POST/PUT requests towards the API.
	writingMutex *sync.Mutex
}

// NewClient creates a new FMC HTTP client.
// Pass modifiers in to modify the behavior of the client, e.g.
//
//	client, _ := NewClient("fmc1.cisco.com", "user", "password", RequestTimeout(120))
func NewClient(url, usr, pwd string, mods ...func(*Client)) (Client, error) {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}

	cookieJar, _ := cookiejar.New(nil)
	httpClient := http.Client{
		Timeout:   60 * time.Second,
		Transport: tr,
		Jar:       cookieJar,
	}

	client := Client{
		HttpClient:          &httpClient,
		Url:                 url,
		Usr:                 usr,
		Pwd:                 pwd,
		MaxRetries:          DefaultMaxRetries,
		BackoffMinDelay:     DefaultBackoffMinDelay,
		BackoffMaxDelay:     DefaultBackoffMaxDelay,
		BackoffDelayFactor:  DefaultBackoffDelayFactor,
		authenticationMutex: &sync.Mutex{},
		RateLimiterBucket:   ratelimit.NewBucketWithRate(1.66, 1), // 1.66 req/s == 100 req/min
		writingMutex:        &sync.Mutex{},
	}

	for _, mod := range mods {
		mod(&client)
	}
	return client, nil
}

// Insecure determines if insecure https connections are allowed. Default value is true.
func Insecure(x bool) func(*Client) {
	return func(client *Client) {
		client.HttpClient.Transport.(*http.Transport).TLSClientConfig.InsecureSkipVerify = x
	}
}

// RequestTimeout modifies the HTTP request timeout from the default of 60 seconds.
func RequestTimeout(x time.Duration) func(*Client) {
	return func(client *Client) {
		client.HttpClient.Timeout = x * time.Second
	}
}

// MaxRetries modifies the maximum number of retries from the default of 3.
func MaxRetries(x int) func(*Client) {
	return func(client *Client) {
		client.MaxRetries = x
	}
}

// BackoffMinDelay modifies the minimum delay between two retries from the default of 2.
func BackoffMinDelay(x int) func(*Client) {
	return func(client *Client) {
		client.BackoffMinDelay = x
	}
}

// BackoffMaxDelay modifies the maximum delay between two retries from the default of 60.
func BackoffMaxDelay(x int) func(*Client) {
	return func(client *Client) {
		client.BackoffMaxDelay = x
	}
}

// BackoffDelayFactor modifies the backoff delay factor from the default of 3.
func BackoffDelayFactor(x float64) func(*Client) {
	return func(client *Client) {
		client.BackoffDelayFactor = x
	}
}

// NewReq creates a new Req request for this client.
// Use a "{DOMAIN_UUID}" placeholder in the URI to be replaced with the domain UUID.
func (client Client) NewReq(method, uri string, body io.Reader, mods ...func(*Req)) Req {
	httpReq, _ := http.NewRequest(method, client.Url+uri, body)
	req := Req{
		HttpReq:    httpReq,
		LogPayload: true,
		DomainName: "",
	}
	for _, mod := range mods {
		mod(&req)
	}
	if req.DomainName == "" {
		req.HttpReq.URL.Path = strings.ReplaceAll(req.HttpReq.URL.Path, "{DOMAIN_UUID}", client.DomainUUID)
	} else {
		req.HttpReq.URL.Path = strings.ReplaceAll(req.HttpReq.URL.Path, "{DOMAIN_UUID}", client.Domains[req.DomainName])
	}
	return req
}

// Do makes a request.
// Requests for Do are built ouside of the client, e.g.
//
//	req := client.NewReq("GET", "/api/fmc_config/v1/domain/{DOMAIN_UUID}/object/networks", nil)
//	res, _ := client.Do(req)
func (client *Client) Do(req Req) (Res, error) {
	// add token
	req.HttpReq.Header.Add("X-auth-access-token", client.AuthToken)
	req.HttpReq.Header.Add("Content-Type", "application/json")
	req.HttpReq.Header.Add("Accept", "application/json")
	// retain the request body across multiple attempts
	var body []byte
	if req.HttpReq.Body != nil {
		body, _ = io.ReadAll(req.HttpReq.Body)
	}

	var res Res

	for attempts := 0; ; attempts++ {
		httpRes, err := client.do(req, body)
		if err != nil {
			if ok := client.Backoff(attempts); !ok {
				log.Printf("[ERROR] HTTP Connection error occured: %+v", err)
				log.Printf("[DEBUG] Exit from Do method")
				return Res{}, err
			} else {
				log.Printf("[ERROR] HTTP Connection failed: %s, retries: %v", err, attempts)
				continue
			}
		}

		defer httpRes.Body.Close()
		bodyBytes, err := io.ReadAll(httpRes.Body)
		if err != nil {
			if ok := client.Backoff(attempts); !ok {
				log.Printf("[ERROR] Cannot decode response body: %+v", err)
				log.Printf("[DEBUG] Exit from Do method")
				return Res{}, err
			} else {
				log.Printf("[ERROR] Cannot decode response body: %s, retries: %v", err, attempts)
				continue
			}
		}
		res = Res(gjson.ParseBytes(bodyBytes))
		if req.LogPayload {
			log.Printf("[DEBUG] HTTP Response: %s", res.Raw)
		}

		if httpRes.StatusCode >= 200 && httpRes.StatusCode <= 299 {
			log.Printf("[DEBUG] Exit from Do method")
			break
		} else {
			if ok := client.Backoff(attempts); !ok {
				log.Printf("[ERROR] HTTP Request failed: StatusCode %v", httpRes.StatusCode)
				log.Printf("[DEBUG] Exit from Do method")
				return res, fmt.Errorf("HTTP Request failed: StatusCode %v", httpRes.StatusCode)
			} else if httpRes.StatusCode == 429 || (httpRes.StatusCode >= 500 && httpRes.StatusCode <= 599) {
				log.Printf("[ERROR] HTTP Request failed: StatusCode %v, Retries: %v", httpRes.StatusCode, attempts)
				continue
			} else if httpRes.StatusCode == 401 {
				// There are bugs in FMC, where the sessions are invalidated out of the blue
				// In case such a situation is detected, new authentication is forced
				log.Printf("[DEBUG] Invalid session detected. Forcing reauthentication")
				// Clear AuthToken (which is invalid anyways). This also ensures that Authenticate does full authentication
				client.AuthToken = ""
				// Force reauthentication, client.Authenticate() takes care of mutexes, hence not calling Login() directly
				err := client.Authenticate()
				if err != nil {
					log.Printf("[DEBUG] HTTP Request failed: StatusCode 401: Forced reauthentication failed: %s", err)
					return res, fmt.Errorf("HTTP Request failed: StatusCode 401: Forced reauthentication failed: %s", err)
				}
				req.HttpReq.Header.Set("X-auth-access-token", client.AuthToken)
				continue
			} else {
				log.Printf("[ERROR] HTTP Request failed: StatusCode %v", httpRes.StatusCode)
				log.Printf("[DEBUG] Exit from Do method")
				return res, fmt.Errorf("HTTP Request failed: StatusCode %v", httpRes.StatusCode)
			}
		}
	}

	if res.Get("error.messages.0").Exists() {
		log.Printf("[ERROR] JSON error: %s", res.Get("error.messages.0").String())
		return res, fmt.Errorf("JSON error: %s", res.Get("error.messages.0").String())
	}
	return res, nil
}

func (client *Client) do(req Req, body []byte) (*http.Response, error) {
	client.RateLimiterBucket.Wait(1) // Block until rate limit token available

	if req.HttpReq.Method != "GET" {
		client.writingMutex.Lock()
		defer client.writingMutex.Unlock()
	}

	req.HttpReq.Body = io.NopCloser(bytes.NewBuffer(body))
	if req.LogPayload {
		log.Printf("[DEBUG] HTTP Request: %s, %s, %s", req.HttpReq.Method, req.HttpReq.URL, string(body))
	} else {
		log.Printf("[DEBUG] HTTP Request: %s, %s", req.HttpReq.Method, req.HttpReq.URL)
	}

	return client.HttpClient.Do(req.HttpReq)
}

// Get makes a GET request and returns a GJSON result.
// Results will be the raw data structure as returned by FMC
func (client *Client) Get(path string, mods ...func(*Req)) (Res, error) {
	err := client.Authenticate()
	if err != nil {
		return Res{}, err
	}
	req := client.NewReq("GET", path, nil, mods...)
	return client.Do(req)
}

// Delete makes a DELETE request.
func (client *Client) Delete(path string, mods ...func(*Req)) (Res, error) {
	err := client.Authenticate()
	if err != nil {
		return Res{}, err
	}
	req := client.NewReq("DELETE", path, nil, mods...)
	return client.Do(req)
}

// Post makes a POST request and returns a GJSON result.
// Hint: Use the Body struct to easily create POST body data.
func (client *Client) Post(path, data string, mods ...func(*Req)) (Res, error) {
	err := client.Authenticate()
	if err != nil {
		return Res{}, err
	}
	req := client.NewReq("POST", path, strings.NewReader(data), mods...)
	return client.Do(req)
}

// Put makes a PUT request and returns a GJSON result.
// Hint: Use the Body struct to easily create PUT body data.
func (client *Client) Put(path, data string, mods ...func(*Req)) (Res, error) {
	err := client.Authenticate()
	if err != nil {
		return Res{}, err
	}
	req := client.NewReq("PUT", path, strings.NewReader(data), mods...)
	return client.Do(req)
}

// Login authenticates to the FMC instance.
func (client *Client) Login() error {
	for attempts := 0; ; attempts++ {
		req := client.NewReq("POST", "/api/fmc_platform/v1/auth/generatetoken", strings.NewReader(""), NoLogPayload)
		req.HttpReq.SetBasicAuth(client.Usr, client.Pwd)
		client.RateLimiterBucket.Wait(1)
		httpRes, err := client.HttpClient.Do(req.HttpReq)
		if err != nil {
			return err
		}
		defer httpRes.Body.Close()
		bodyBytes, _ := io.ReadAll(httpRes.Body)
		if httpRes.StatusCode != 204 {
			log.Printf("[ERROR] Authentication failed: StatusCode %v", httpRes.StatusCode)
			return fmt.Errorf("authentication failed, status code: %v", httpRes.StatusCode)
		}
		if len(bodyBytes) > 0 {
			if ok := client.Backoff(attempts); !ok {
				log.Printf("[ERROR] Authentication failed: Invalid credentials")
				return fmt.Errorf("authentication failed, invalid credentials")
			} else {
				log.Printf("[ERROR] Authentication failed: %s, retries: %v", err, attempts)
				continue
			}
		}
		client.AuthToken = httpRes.Header.Get("X-auth-access-token")
		client.RefreshToken = httpRes.Header.Get("X-auth-refresh-token")
		client.LastRefresh = time.Now()
		client.RefreshCount = 0
		client.DomainUUID = httpRes.Header.Get("DOMAIN_UUID")
		client.Domains = make(map[string]string)
		gjson.Parse(httpRes.Header.Get("DOMAINS")).ForEach(func(k, v gjson.Result) bool {
			domainName := v.Get("name").String()
			domainUuid := v.Get("uuid").String()
			client.Domains[domainName] = domainUuid
			log.Printf("[DEBUG] Found domain: %s, UUID: %s", domainName, domainUuid)
			return true // keep iterating
		})

		log.Printf("[DEBUG] Authentication successful")
		return nil
	}
}

// Refresh refreshes the authentication token.
// Note that this will be handled automatically by default.
// Refresh will be checked every request and the token will be refreshed after 25 minutes.
func (client *Client) Refresh() error {
	for attempts := 0; ; attempts++ {
		req := client.NewReq("POST", "/api/fmc_platform/v1/auth/refreshtoken", strings.NewReader(""), NoLogPayload)
		req.HttpReq.Header.Add("X-auth-access-token", client.AuthToken)
		req.HttpReq.Header.Add("X-auth-refresh-token", client.RefreshToken)
		client.RateLimiterBucket.Wait(1)
		httpRes, err := client.HttpClient.Do(req.HttpReq)
		if err != nil {
			return err
		}
		defer httpRes.Body.Close()
		bodyBytes, _ := io.ReadAll(httpRes.Body)
		if httpRes.StatusCode != 204 {
			log.Printf("[ERROR] Authentication failed: StatusCode %v", httpRes.StatusCode)
			return fmt.Errorf("authentication failed, status code: %v", httpRes.StatusCode)
		}
		if len(bodyBytes) > 0 {
			if ok := client.Backoff(attempts); !ok {
				log.Printf("[ERROR] Authentication failed: Invalid credentials")
				return fmt.Errorf("authentication failed, invalid credentials")
			} else {
				log.Printf("[ERROR] Authentication failed: %s, retries: %v", err, attempts)
				continue
			}
		}
		client.AuthToken = httpRes.Header.Get("X-auth-access-token")
		client.RefreshToken = httpRes.Header.Get("X-auth-refresh-token")
		client.LastRefresh = time.Now()
		client.RefreshCount = client.RefreshCount + 1
		client.DomainUUID = httpRes.Header.Get("DOMAIN_UUID")
		log.Printf("[DEBUG] Refresh successful")
		return nil
	}
}

// Login if no token available.
func (client *Client) Authenticate() error {
	var err error
	client.authenticationMutex.Lock()
	if client.AuthToken != "" && time.Since(client.LastRefresh) > 1500*time.Second && client.RefreshCount < 3 {
		err = client.Refresh()
	} else if client.AuthToken == "" || (time.Since(client.LastRefresh) >= 1500*time.Second && client.RefreshCount >= 3) {
		err = client.Login()
	}
	client.authenticationMutex.Unlock()
	return err
}

// Backoff waits following an exponential backoff algorithm
func (client *Client) Backoff(attempts int) bool {
	log.Printf("[DEBUG] Beginning backoff method: attempt %v of %v", attempts, client.MaxRetries)
	if attempts >= client.MaxRetries {
		log.Printf("[DEBUG] Exit from backoff method with return value false")
		return false
	}

	minDelay := time.Duration(client.BackoffMinDelay) * time.Second
	maxDelay := time.Duration(client.BackoffMaxDelay) * time.Second

	min := float64(minDelay)
	backoff := min * math.Pow(client.BackoffDelayFactor, float64(attempts))
	if backoff > float64(maxDelay) {
		backoff = float64(maxDelay)
	}
	backoff = (rand.Float64()/2+0.5)*(backoff-min) + min
	backoffDuration := time.Duration(backoff)
	log.Printf("[TRACE] Starting sleeping for %v", backoffDuration.Round(time.Second))
	time.Sleep(backoffDuration)
	log.Printf("[DEBUG] Exit from backoff method with return value true")
	return true
}
