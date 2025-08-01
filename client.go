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

	"github.com/hashicorp/go-version"
	"github.com/tidwall/gjson"
	"github.com/tidwall/sjson"

	"github.com/juju/ratelimit"
)

const DefaultMaxRetries int = 3
const DefaultBackoffMinDelay int = 2
const DefaultBackoffMaxDelay int = 60
const DefaultBackoffDelayFactor float64 = 3

// maximum number of Items retrieved in a single GET request
var maxItems = 1000

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
	// UserAgent is the HTTP User-Agent string
	UserAgent string
	// Usr is the FMC username. Not used for cdFMC.
	Usr string
	// Pwd is the FMC password or cdFMC API token
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
	// DomainUUID is the UUID of the user login domain.
	DomainUUID string
	// Map of domain names to domain UUIDs.
	Domains map[string]string
	// FMC Version string as returned by FMC - ex. 7.7.0 (build 91)
	FMCVersion string
	// FMC Version parsed to go-version library - ex. 7.7.0
	FMCVersionParsed *version.Version
	// Is this cdFMC connection
	IsCDFMC bool

	RateLimiterBucket *ratelimit.Bucket

	// writingMutex protects against concurrent DELETE/POST/PUT requests towards the API.
	writingMutex *sync.Mutex
}

// NewClient creates a new FMC HTTP client.
// Pass modifiers in to modify the behavior of the client, e.g.
//
//	client, _ := NewClient("fmc1.cisco.com", "user", "password", RequestTimeout(120))
func NewClient(url, usr, pwd string, mods ...func(*Client)) (Client, error) {
	log.Printf("[DEBUG] go-fmc version " + Version)
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		Proxy:           http.ProxyFromEnvironment,
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
		UserAgent:           defaultUserAgent(),
		Usr:                 usr,
		Pwd:                 pwd,
		MaxRetries:          DefaultMaxRetries,
		BackoffMinDelay:     DefaultBackoffMinDelay,
		BackoffMaxDelay:     DefaultBackoffMaxDelay,
		BackoffDelayFactor:  DefaultBackoffDelayFactor,
		authenticationMutex: &sync.Mutex{},
		RateLimiterBucket:   ratelimit.NewBucketWithRate(1.97, 1), // 1.97 req/s ~= 118 req/min (+/- 1% from 120 req/min that FMC allows)
		writingMutex:        &sync.Mutex{},
	}

	for _, mod := range mods {
		mod(&client)
	}

	err := client.GetFMCVersion()
	if err != nil {
		log.Printf("[ERROR] Failed to retrieve FMC version: %s", err.Error())
		return client, err
	}

	// Compile FMC version to go-version
	client.FMCVersionParsed, err = version.NewVersion(strings.Split(client.FMCVersion, " ")[0])
	if err != nil {
		log.Printf("[ERROR] Failed to parse FMC version (%s): %s", client.FMCVersion, err.Error())
		return client, fmt.Errorf("failed to parse FMC version (%s): %s", client.FMCVersion, err.Error())
	}

	log.Printf("[DEBUG] FMC Version: %s, FMC Version Parsed: %s", client.FMCVersion, client.FMCVersionParsed.String())

	// FMC 7.4.1, 6.6.0 and later have increased rate limits
	if client.FMCVersionParsed.GreaterThanOrEqual(version.Must(version.NewVersion("7.4.1"))) {
		log.Printf("[DEBUG] Increasing rate limit to 5 req/s (300 req/min)")
		client.RateLimiterBucket = ratelimit.NewBucketWithRate(5, 1) // 5 req/s = 300 req/min
	}

	return client, nil
}

// Create a new cdFMC HTTP client.
func NewClientCDFMC(url, apiToken string, mods ...func(*Client)) (Client, error) {
	// Set client mode to cdFMC
	mods = append(mods, cdFMC(true))

	// Create client as usual. Username is not used.
	client, err := NewClient(url, "", apiToken, mods...)
	if err != nil {
		return client, err
	}

	// Get the Global Domain UUID. cdFMC does not support multi-domain.
	// Global UUID is fixed (e276abec-e0f2-11e3-8169-6d9ed49b625f), though we get it from the cdFMC just in case.
	res, err := client.Get("/api/fmc_platform/v1/info/domain")
	if err != nil {
		return client, err
	}
	if uuid := res.Get("items.0.uuid"); !uuid.Exists() {
		return client, fmt.Errorf("failed to retrieve domain UUID from: %s", res.String())
	} else {
		client.DomainUUID = uuid.String()
		client.Domains = map[string]string{
			"Global": uuid.String(),
		}
	}

	return client, nil
}

// Replace the default HTTP client with a custom one.
func CustomHttpClient(httpClient *http.Client) func(*Client) {
	return func(client *Client) {
		client.HttpClient = httpClient
	}
}

// UserAgent modifies the HTTP user agent string. Default value is 'go-meraki netascode'.
func UserAgent(x string) func(*Client) {
	return func(client *Client) {
		client.UserAgent = x
	}
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

// cdFMC sets connector mode to cdFMC (true) or FMC (false).
func cdFMC(x bool) func(*Client) {
	return func(client *Client) {
		client.IsCDFMC = x
	}
}

// NewReq creates a new Req request for this client.
// Use a "{DOMAIN_UUID}" placeholder in the URI to be replaced with the domain UUID.
func (client Client) NewReq(method, uri string, body io.Reader, mods ...func(*Req)) (Req, error) {
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
		// Check if selected domains exists on FMC
		if _, ok := client.Domains[req.DomainName]; !ok {
			availableDomains := make([]string, len(client.Domains))
			i := 0
			for k := range client.Domains {
				availableDomains[i] = k
				i++
			}
			log.Printf("[ERROR] Requested domain not found: requested domain: %s, available domains: %s", req.DomainName, availableDomains)
			return Req{}, fmt.Errorf("requested domain not found: requested domain: %s, available domains: %s", req.DomainName, availableDomains)
		}
		req.HttpReq.URL.Path = strings.ReplaceAll(req.HttpReq.URL.Path, "{DOMAIN_UUID}", client.Domains[req.DomainName])
	}
	return req, nil
}

// Do makes a request.
// Requests for Do are built ouside of the client, e.g.
//
//	req := client.NewReq("GET", "/api/fmc_config/v1/domain/{DOMAIN_UUID}/object/networks", nil)
//	res, _ := client.Do(req)
func (client *Client) Do(req Req) (Res, error) {
	// add token
	if client.IsCDFMC {
		req.HttpReq.Header.Add("Authorization", "Bearer "+client.Pwd)
	} else {
		req.HttpReq.Header.Add("X-auth-access-token", client.AuthToken)
	}
	req.HttpReq.Header.Add("Content-Type", "application/json")
	req.HttpReq.Header.Add("Accept", "application/json")
	req.HttpReq.Header.Add("User-Agent", client.UserAgent)
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
				log.Printf("[ERROR] [ReqID: %s] HTTP Connection error occurred: %+v", req.RequestID, err)
				log.Printf("[DEBUG] [ReqID: %s] Exit from Do method", req.RequestID)
				return Res{}, err
			} else {
				log.Printf("[ERROR] [ReqID: %s] HTTP Connection failed: %s, retries: %v", req.RequestID, err, attempts)
				continue
			}
		}

		defer httpRes.Body.Close()
		bodyBytes, err := io.ReadAll(httpRes.Body)
		if err != nil {
			if ok := client.Backoff(attempts); !ok {
				log.Printf("[ERROR] [ReqID: %s] Cannot decode response body: %+v", req.RequestID, err)
				log.Printf("[DEBUG] [ReqID: %s] Exit from Do method", req.RequestID)
				return Res{}, err
			} else {
				log.Printf("[ERROR] [ReqID: %s] Cannot decode response body: %s, retries: %v", req.RequestID, err, attempts)
				continue
			}
		}
		res = Res(gjson.ParseBytes(bodyBytes))
		if req.LogPayload {
			log.Printf("[DEBUG] [ReqID: %s] HTTP Response: %s", req.RequestID, res.Raw)
		}

		if httpRes.StatusCode >= 200 && httpRes.StatusCode <= 299 {
			log.Printf("[DEBUG] [ReqID: %s] Exit from Do method", req.RequestID)
			break
		} else {
			if ok := client.Backoff(attempts); !ok {
				log.Printf("[ERROR] [ReqID: %s] HTTP Request failed: StatusCode %v", req.RequestID, httpRes.StatusCode)
				log.Printf("[DEBUG] [ReqID: %s] Exit from Do method", req.RequestID)
				return res, fmt.Errorf("HTTP Request failed: StatusCode %v", httpRes.StatusCode)
			} else if httpRes.StatusCode == 429 || (httpRes.StatusCode >= 500 && httpRes.StatusCode <= 599) {
				log.Printf("[ERROR] [ReqID: %s] HTTP Request failed: StatusCode %v, Retries: %v", req.RequestID, httpRes.StatusCode, attempts)
				continue
			} else if httpRes.StatusCode == 401 && !client.IsCDFMC {
				// There are bugs in FMC, where the sessions are invalidated out of the blue
				// In case such a situation is detected, new authentication is forced
				log.Printf("[DEBUG] [ReqID: %s] Invalid session detected. Forcing reauthentication", req.RequestID)

				// Lock authentication mutex to prevent other goroutines from modifying the authentication state
				client.authenticationMutex.Lock()
				// Create local error handling variable, which other goroutines cannot modify
				var authErr error
				// If there was no recent re-authentication, refresh the token
				if time.Since(client.LastRefresh) >= 2*time.Minute {
					authErr = client.Login()
				}
				client.authenticationMutex.Unlock()

				if authErr != nil {
					log.Printf("[DEBUG] [ReqID: %s] HTTP Request failed: StatusCode 401: Forced reauthentication failed: %s", req.RequestID, authErr.Error())
					return res, fmt.Errorf("HTTP Request failed: StatusCode 401: Forced reauthentication failed: %s", authErr.Error())
				}
				req.HttpReq.Header.Set("X-auth-access-token", client.AuthToken)
				continue
			} else if desc := res.Get("error.messages.0.description"); desc.Exists() {
				// FMC may return HTTP response code 400 with advice to retry the operation
				if strings.Contains(strings.ToLower(desc.String()), "please try again") ||
					strings.Contains(strings.ToLower(desc.String()), "retry the operation after sometime") {
					log.Printf("[ERROR] HTTP Request failed with advice to try again. Retrying.")
					continue
				}
			}
			// In case any previous conditions don't `continue`, return error
			log.Printf("[ERROR] [ReqID: %s] HTTP Request failed: StatusCode %v", req.RequestID, httpRes.StatusCode)
			log.Printf("[DEBUG] [ReqID: %s] Exit from Do method", req.RequestID)
			return res, fmt.Errorf("HTTP Request failed: StatusCode %v", httpRes.StatusCode)
		}
	}

	if res.Get("error.messages.0").Exists() {
		log.Printf("[ERROR] [ReqID: %s] JSON error: %s", req.RequestID, res.Get("error.messages.0").String())
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
		log.Printf("[DEBUG] [ReqID: %s] HTTP Request: %s, %s, %s", req.RequestID, req.HttpReq.Method, req.HttpReq.URL, string(body))
	} else {
		log.Printf("[DEBUG] [ReqID: %s] HTTP Request: %s, %s", req.RequestID, req.HttpReq.Method, req.HttpReq.URL)
	}

	return client.HttpClient.Do(req.HttpReq)
}

// Get makes a GET requests and returns a GJSON result.
// It handles pagination and returns all items in a single response.
func (client *Client) Get(path string, mods ...func(*Req)) (Res, error) {
	// Generate Request ID for tracking request inside go-fmc
	mods = append(mods, setRequestID(generateRequestID(8)))

	// Check if path contains words 'limit' or 'offset'
	// If so, assume user is doing a paginated request and return the raw data
	if strings.Contains(path, "limit") || strings.Contains(path, "offset") {
		return client.get(path, mods...)
	}

	// Execute query as provided by user
	raw, err := client.get(path, mods...)
	if err != nil {
		return raw, err
	}

	// If there are no more pages, return the response
	if !raw.Get("paging.next.0").Exists() {
		return raw, nil
	}

	log.Printf("[DEBUG] Paginated response detected")

	// Otherwise discard previous response and get all pages
	offset := 0
	fullOutput := `{"items":[]}`

	// Lock writing mutex to make sure the pages are not changed during reading
	client.writingMutex.Lock()
	defer client.writingMutex.Unlock()

	for {
		// Get URL path with offset and limit set
		urlPath := pathWithOffset(path, offset, maxItems)

		// Execute query
		raw, err := client.get(urlPath, mods...)
		if err != nil {
			return raw, err
		}

		// Check if there are any items in the response
		items := raw.Get("items")
		if !items.Exists() {
			return gjson.Parse("null"), fmt.Errorf("no items found in response")
		}

		// Remove first and last character (square brackets) from the output
		// If resItems is not empty, attach it to full output
		if resItems := items.String()[1 : len(items.String())-1]; resItems != "" {
			fullOutput, _ = sjson.SetRaw(fullOutput, "items.-1", resItems)
		}

		// If there are no more pages, break the loop
		if !raw.Get("paging.next.0").Exists() {
			// Create new response with all the items
			return gjson.Parse(fullOutput), nil
		}

		// Increase offset to get next bulk of data
		offset += maxItems
	}
}

// get makes a GET request and returns a GJSON result.
// It does the exact request it is told to do.
// Results will be the raw data structure as returned by FMC
func (client *Client) get(path string, mods ...func(*Req)) (Res, error) {
	err := client.Authenticate()
	if err != nil {
		return Res{}, err
	}
	req, err := client.NewReq("GET", path, nil, mods...)
	if err != nil {
		return Res{}, err
	}
	return client.Do(req)
}

// Delete makes a DELETE request.
func (client *Client) Delete(path string, mods ...func(*Req)) (Res, error) {
	// Generate Request ID for tracking request inside go-fmc
	mods = append(mods, setRequestID(generateRequestID(8)))
	err := client.Authenticate()
	if err != nil {
		return Res{}, err
	}
	req, err := client.NewReq("DELETE", path, nil, mods...)
	if err != nil {
		return Res{}, err
	}
	return client.Do(req)
}

// Post makes a POST request and returns a GJSON result.
// Hint: Use the Body struct to easily create POST body data.
func (client *Client) Post(path, data string, mods ...func(*Req)) (Res, error) {
	// Generate Request ID for tracking request inside go-fmc
	mods = append(mods, setRequestID(generateRequestID(8)))
	err := client.Authenticate()
	if err != nil {
		return Res{}, err
	}
	req, err := client.NewReq("POST", path, strings.NewReader(data), mods...)
	if err != nil {
		return Res{}, err
	}
	return client.Do(req)
}

// Put makes a PUT request and returns a GJSON result.
// Hint: Use the Body struct to easily create PUT body data.
func (client *Client) Put(path, data string, mods ...func(*Req)) (Res, error) {
	// Generate Request ID for tracking request inside go-fmc
	mods = append(mods, setRequestID(generateRequestID(8)))
	err := client.Authenticate()
	if err != nil {
		return Res{}, err
	}
	req, err := client.NewReq("PUT", path, strings.NewReader(data), mods...)
	if err != nil {
		return Res{}, err
	}
	return client.Do(req)
}

// Login authenticates to the FMC instance.
func (client *Client) Login() error {
	for attempts := 0; ; attempts++ {
		req, _ := client.NewReq("POST", "/api/fmc_platform/v1/auth/generatetoken", strings.NewReader(""), NoLogPayload)
		req.HttpReq.Header.Add("User-Agent", client.UserAgent)
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
		req, _ := client.NewReq("POST", "/api/fmc_platform/v1/auth/refreshtoken", strings.NewReader(""), NoLogPayload)
		req.HttpReq.Header.Add("X-auth-access-token", client.AuthToken)
		req.HttpReq.Header.Add("X-auth-refresh-token", client.RefreshToken)
		req.HttpReq.Header.Add("User-Agent", client.UserAgent)
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
	// cdFMC uses fixed token, no need to do separate authentication
	if client.IsCDFMC {
		return nil
	}

	var err error
	client.authenticationMutex.Lock()
	// Check if we can attempt to refresh the token (there is old token, it's between 25 and 29 minutes since last refresh, and less than 3 refreshes done)
	if client.AuthToken != "" && time.Since(client.LastRefresh) > 1500*time.Second && time.Since(client.LastRefresh) < 1740*time.Second && client.RefreshCount < 3 {
		err = client.Refresh()
		// Check if we need to login (no token available or more than 25 minutes since last refresh)
	} else if client.AuthToken == "" || time.Since(client.LastRefresh) >= 1500*time.Second {
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

// Get FMC Version
func (client *Client) GetFMCVersion() error {
	// If version is already known, no need to get it from FMC
	if client.FMCVersion != "" {
		return nil
	}

	res, err := client.Get("/api/fmc_platform/v1/info/serverversion")
	if err != nil {
		log.Printf("[ERROR] Failed to retrieve FMC version: %s", err.Error())
		return fmt.Errorf("failed to retrieve FMC version: %s", err.Error())
	}

	fmcVersion := res.Get("items.0.serverVersion")
	if !fmcVersion.Exists() {
		log.Printf("[ERROR] Failed to retrieve FMC version: version not found in FMC responses")
		return fmt.Errorf("failed to retrieve FMC version: version not found in FMC response")
	}

	client.FMCVersion = fmcVersion.String()

	return nil
}

// Create URL path with offset and limit
func pathWithOffset(path string, offset, limit int) string {
	sep := "?"
	if strings.Contains(path, sep) {
		sep = "&"
	}

	return fmt.Sprintf("%s%soffset=%d&limit=%d", path, sep, offset, limit)
}
