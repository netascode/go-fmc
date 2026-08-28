## 0.4.0 (Unreleased)

- BREAKING CHANGE: `Pwd` field of `Client` is no longer exported
- BREAKING CHANGE: `Insecure` field of `Client` is removed, as it has never been used (dead field)
- BREAKING CHANGE: `RateLimiterBucket` field of `Client` renamed to `RateLimiter` and changed type from `*ratelimit.Bucket` to `*rate.Limiter` (replace `juju/ratelimit` with `golang.org/x/time/rate`)
- Enh: Update `login()` and `refresh()` logic
- Change: Rate limit for FMC 7.4.1, 7.6.0 and later lowered from 300 req/min to 294 req/min, to keep a safety margin
- Other minor fixes

## 0.3.1

- Fix: RequestTimeout() wrongly sets timeout value
- Other minor fixes

## 0.3.0

- BREAKING CHANGE: `login()` and `refresh()` functions are no logner exported
- BREAKING CHANGE: `Authenticate()` is now defined as `Authenticate(currentAuthToken string)`
- Fix: Mishandling of the FMC authentication token could lead to failures and redundant authentications
- Enh: Introduced ReqID to correlate events in the logs
- Enh: FMC 7.4.1, 7.6.0 and later releases have rate-limit increased to 300 req/min

## 0.2.1

- Fix: cdFMC client fails if user sets `DomainName` modifier, even it was for `Global` domain
- Fix: FMC may return an error indicating, "Retry the operation after some time." In such cases, the client will adhere to this guidance rather than failing immediately.

## 0.2.0

- Add User-Agent to HTTP requests
- Add cdFMC support (`func NewClientCDFMC()`)

## 0.1.1

- Honor proxy settings (`HTTP_PROXY`, `HTTPS_PROXY`, `NO_PROXY` environment variables)

## 0.1.0

- Initial release
