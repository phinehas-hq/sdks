# `phinehas-go`

> Active-defense in-process security middleware for Golang HTTP applications (`net/http`, Gin, Chi, Echo) with immediate TCP socket severance (`http.Hijacker`), zero-allocation LRU, and RFC 8615-compliant wildcard detection.

[![Go Reference](https://pkg.go.dev/badge/github.com/phinehas-hq/sdks/packages/go.svg)](https://pkg.go.dev/github.com/phinehas-hq/sdks/packages/go)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![Go Report Card](https://goreportcard.com/badge/github.com/phinehas-hq/sdks/packages/go)](https://goreportcard.com/report/github.com/phinehas-hq/sdks/packages/go)

---

## Overview

Traditional web servers return HTTP 403 or 404 responses when automated vulnerability scanners probe for sensitive dotfiles (`/.env`, `/.git`) or database management endpoints (`/phpmyadmin`). This wastes server CPU, database connections, and bandwidth while confirming endpoint presence to attackers.

`phinehas-go` hijacks the underlying TCP socket via `http.Hijacker` and terminates the connection immediately (`conn.Close()`). Attackers receive an abrupt connection reset (`ECONNRESET`) with zero HTTP headers and zero diagnostic bytes.

---

## Installation

```bash
go get github.com/phinehas-hq/sdks/packages/go
```

---

## Quick Start (`net/http`)

```go
package main

import (
	"log"
	"net/http"
	"time"

	"github.com/phinehas-hq/sdks/packages/go"
)

func main() {
	guard := phinehas.New(phinehas.Config{
		TTL:    24 * time.Hour,            // Ban attacking IPs for 24 hours
		Action: phinehas.ActionTerminate, // Hijack & close TCP socket immediately (Default)
		OnStrike: func(strike phinehas.StrikeEvent) {
			log.Printf("[PHINEHAS STRIKE] Severed %s probing %s", strike.IP, strike.Path)
		},
	})
	defer guard.Close()

	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"status":"ok"}`))
	})

	server := &http.Server{
		Addr:    ":8080",
		Handler: guard.Wrap(mux), // Wrap entire HTTP mux with Phinehas
	}

	log.Fatal(server.ListenAndServe())
}
```

---

## Framework Integrations

### Chi Router

```go
r := chi.NewRouter()
guard := phinehas.New(phinehas.Config{Action: phinehas.ActionTerminate})

r.Use(guard.Wrap)
```

### Gin Framework

```go
r := gin.Default()
guard := phinehas.New(phinehas.Config{Action: phinehas.ActionTerminate})

r.Use(func(c *gin.Context) {
    guard.Wrap(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
        c.Next()
    })).ServeHTTP(c.Writer, c.Request)
})
```

---

## Configuration Options

| Option | Type | Default | Description |
| :--- | :--- | :--- | :--- |
| `Action` | `Action` | `ActionTerminate` | Defense action executed on attack (`ActionTerminate`, `ActionReject`, `ActionTarpit`). |
| `TTL` | `time.Duration` | `1 * time.Hour` | Ban duration (`0` for permanent). |
| `Store` | `store.BanStore` | `store.NewMemoryStore()` | Custom ban storage driver. |
| `AllowList` | `[]string` | `[]string{"127.0.0.1", "::1"}` | Whitelisted IP addresses exempt from bans. |
| `Proxy.Trust` | `bool` | `false` | Whether to parse reverse proxy headers. |
| `Proxy.Header` | `string` | `""` | Custom header (e.g. `"CF-Connecting-IP"`). |
| `Proxy.Depth` | `int` | `0` | Number of proxy hops to inspect in `X-Forwarded-For`. |
| `CustomTraps` | `[]string` | `nil` | Extra paths to trap. |
| `ExcludeDefaults` | `bool` | `false` | Disable standard non-dot threat signatures. |
| `LogFormat` | `LogFormat` | `LogFormatStructured` | Structured JSON vs compact stderr text. |
| `OnStrike` | `StrikeCallback` | `nil` | Callback hook for alerts (Slack, Discord, Datadog). |

---

## Action Modes Explained

* **`ActionTerminate` (Default):** Calls `http.Hijacker.Hijack()` and closes the connection abruptly (`conn.Close()`), returning zero bytes to the attacker.
* **`ActionReject`:** Returns an immediate HTTP `403 Forbidden` with a zero-length body and `X-Phinehas-Verdict: blocked`.
* **`ActionTarpit`:** Holds the connection open, delaying response to consume attacker resources.

---

## License

Apache-2.0. Maintained by [Phinehas HQ](https://github.com/phinehas-hq).
