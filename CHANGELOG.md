## 0.2.2 (Unreleased)

- Fix: Improper handling of re-authentication may disrupt communication with FMC
- Enh: Support for increased rate-limit (300 req/min) in FMC 7.4.1, 7.6.0 and later
- Enh: Introduced ReqID to correlate events in the logs

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
