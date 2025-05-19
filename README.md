[![Tests](https://github.com/netascode/go-fmc/actions/workflows/test.yml/badge.svg)](https://github.com/netascode/go-fmc/actions/workflows/test.yml)

# go-fmc

`go-fmc` is a Go client library for Cisco Secure FMC (Firewall Management Center) and cdFMC (Cloud-Delivered FMC). It is based on Nathan's excellent [goaci](https://github.com/brightpuddle/goaci) module and features a simple, extensible API and [advanced JSON manipulation](#result-manipulation).

## Getting Started

### Installing

To start using `go-fmc`, install Go and `go get`:

`$ go get -u github.com/netascode/go-fmc`

### Basic Usage

#### Self-managed FMC
```go
package main

import "github.com/netascode/go-fmc"

func main() {
    client, _ := fmc.NewClient("https://1.1.1.1", "user", "pwd")

    res, _ := client.Get("/api/fmc_config/v1/domain/{DOMAIN_UUID}/object/networks")
    println(res.Get("items.0.name").String())
}
```

#### Cloud-managed FMC
```go
package main

import "github.com/netascode/go-fmc"

func main() {
    client, _ := fmc.NewClientCDFMC("https://<YOUR_TENNANT_URL>.cdo.cisco.com", "apiToken")

    res, _ := client.Get("/api/fmc_config/v1/domain/{DOMAIN_UUID}/object/networks")
    println(res.Get("items.0.name").String())
}
```

#### Output

Both of those examples will print something like:

```
any-ipv4
```

#### Result manipulation

`fmc.Result` uses GJSON to simplify handling JSON results. See the [GJSON](https://github.com/tidwall/gjson) documentation for more detail.

```go
res, _ := client.Get("/api/fmc_config/v1/domain/{DOMAIN_UUID}/object/networks")

for _, obj := range res.Get("items").Array() {
    println(obj.Get("@pretty").String()) // pretty print network objects
}
```

#### POST data creation

`fmc.Body` is a wrapper for [SJSON](https://github.com/tidwall/sjson). SJSON supports a path syntax simplifying JSON creation.

```go
body := fmc.Body{}.
    Set("name", "net1").
    Set("value", "1.5.4.0/24")
client.Post("/api/fmc_config/v1/domain/{DOMAIN_UUID}/object/networks", body.Str)
```

## Documentation

See the [documentation](https://godoc.org/github.com/netascode/go-fmc) for more details.
