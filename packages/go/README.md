# `phinehas-go`

> Active-defense in-process security middleware for Golang HTTP applications (`net/http`, Gin, Chi, Echo) with immediate TCP socket severance (`http.Hijacker`), zero-allocation LRU, and RFC 8615-compliant wildcard detection.

[![Go Reference](https://pkg.go.dev/badge/github.com/phinehas-hq/sdks/packages/go.svg)](https://pkg.go.dev/github.com/phinehas-hq/sdks/packages/go)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](../../LICENSE)
[![Go Report Card](https://goreportcard.com/badge/github.com/phinehas-hq/sdks/packages/go)](https://goreportcard.com/report/github.com/phinehas-hq/sdks/packages/go)
[![Compliance Parity](https://img.shields.io/badge/compliance-100%25-brightgreen.svg)](../../compliance/)

---

## 1. Overview & `http.Hijacker` Severance

Traditional web servers return HTTP 403 or 404 responses when automated vulnerability scanners probe for sensitive dotfiles (`/.env`, `/.git`) or database management endpoints (`/phpmyadmin`). This wastes server CPU, database connections, and bandwidth while confirming endpoint presence to attackers.

`phinehas-go` takes over the underlying TCP connection via `http.Hijacker`:
```go
if hijacker, ok := w.(http.Hijacker); ok {
    conn, _, err := hijacker.Hijack()
    if err == nil {
        _ = conn.Close() // Physical transport termination
        return
    }
}
```
Attackers receive an abrupt connection reset (`ECONNRESET`) with **zero HTTP response bytes and zero diagnostic headers**, starving automated reconnaissance tools of feedback and crashing vulnerable scanner worker threads.

---

## 2. Installation

```bash
go get github.com/phinehas-hq/sdks/packages/go
```

---

## 3. Production Quick Start (`net/http`)

```go
package main

import (
	"log"
	"net/http"
	"time"

	"github.com/phinehas-hq/sdks/packages/go"
	"github.com/phinehas-hq/sdks/packages/go/store"
)

func main() {
	// =========================================================================
	// PHINEHAS CONFIGURATION (Required vs Optional Showcase)
	// =========================================================================
	cfg := phinehas.Config{
		// [OPTIONAL - DEFAULT: phinehas.ActionTerminate]
		// Action to take upon malicious probe detection:
		// - ActionTerminate: Calls http.Hijacker and closes TCP socket immediately (ECONNRESET)
		// - ActionReject:    Returns HTTP 403 Forbidden with empty body and Connection: close
		// - ActionTarpit:    Holds socket open to exhaust crawler concurrency
		Action: phinehas.ActionTerminate,

		// [OPTIONAL - DEFAULT: 1 * time.Hour]
		// Ban duration for offending IPs. Set to 0 for permanent bans.
		TTL: 24 * time.Hour,

		// [PRODUCTION RECOMMENDED - DEFAULT: false]
		// Set to true when deployed behind Cloudflare, AWS ALB, Nginx, or Google Cloud Armor.
		Proxy: phinehas.ProxyConfig{
			Trust:  true,
			Header: "CF-Connecting-IP", // Cloudflare / ALB trusted proxy header
			Depth:  1,
		},

		// [OPTIONAL - DEFAULT: []string{"127.0.0.1", "::1"}]
		// Whitelisted IP addresses exempt from bans and threat evaluation
		AllowList: []string{"127.0.0.1", "::1", "10.0.0.1"},

		// [OPTIONAL - DEFAULT: nil]
		// Additional application-specific honeypots or custom trap paths
		CustomTraps: []string{
			"/api/internal/debug",
			"/admin-secret.json",
		},

		// [OPTIONAL - DEFAULT: false]
		// Set to true to disable default CMS/DB/debugger traps
		ExcludeDefaults: false,

		// [OPTIONAL - DEFAULT: store.NewMemoryStore()]
		// In-memory $O(1)$ LRU cache capped at 25,000 IPs with thread-safe RWMutex
		Store: store.NewMemoryStore(),

		// [OPTIONAL - DEFAULT: true]
		LoggingEnabled: true,

		// [OPTIONAL - DEFAULT: phinehas.LogFormatStructured]
		// Output format: LogFormatStructured (JSON) or LogFormatCompact
		LogFormat: phinehas.LogFormatStructured,

		// [OPTIONAL] Real-time callback hook for metrics/alerting (Prometheus, Datadog)
		OnStrike: func(strike phinehas.StrikeEvent) {
			log.Printf("[SECURITY ALERT] Dropped %s probing %s (Rule: %s)", strike.IP, strike.Path, strike.RuleMatched)
		},
	}

	// [REQUIRED] Initialize Guard
	guard := phinehas.New(cfg)
	defer guard.Close()

	// [REQUIRED] Application HTTP router
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"status":"ok"}`))
	})

	server := &http.Server{
		Addr:         ":8080",
		Handler:      guard.Wrap(mux), // [REQUIRED] Wrap entire HTTP router with Phinehas
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
	}

	log.Println("Listening on :8080 with Phinehas active defense...")
	log.Fatal(server.ListenAndServe())
}
```

---

## 4. Framework Integrations

### Gin Framework

```go
package main

import (
	"net/http"
	"github.com/gin-gonic/gin"
	"github.com/phinehas-hq/sdks/packages/go"
)

func main() {
	r := gin.Default()

	guard := phinehas.New(phinehas.Config{
		Action: phinehas.ActionTerminate,
		Proxy:  phinehas.ProxyConfig{Trust: true},
	})
	defer guard.Close()

	// [REQUIRED] Register Phinehas middleware in Gin
	r.Use(func(c *gin.Context) {
		guard.Wrap(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			c.Next()
		})).ServeHTTP(c.Writer, c.Request)
	})

	r.GET("/api/health", func(c *gin.Context) {
		c.JSON(200, gin.H{"status": "ok"})
	})

	r.Run(":8080")
}
```

### Chi Router

```go
package main

import (
	"net/http"
	"github.com/go-chi/chi/v5"
	"github.com/phinehas-hq/sdks/packages/go"
)

func main() {
	r := chi.NewRouter()

	guard := phinehas.New(phinehas.Config{
		Action: phinehas.ActionTerminate,
		Proxy:  phinehas.ProxyConfig{Trust: true},
	})
	defer guard.Close()

	// [REQUIRED] Use Wrap directly as Chi middleware
	r.Use(guard.Wrap)

	r.Get("/api/health", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"status":"ok"}`))
	})

	http.ListenAndServe(":8080", r)
}
```

### Echo Framework

```go
package main

import (
	"github.com/labstack/echo/v4"
	"github.com/phinehas-hq/sdks/packages/go"
)

func main() {
	e := echo.New()

	guard := phinehas.New(phinehas.Config{
		Action: phinehas.ActionTerminate,
		Proxy:  phinehas.ProxyConfig{Trust: true},
	})
	defer guard.Close()

	// [REQUIRED] Wrap with echo.WrapMiddleware
	e.Use(echo.WrapMiddleware(guard.Wrap))

	e.GET("/api/health", func(c echo.Context) error {
		return c.String(200, "OK")
	})

	e.Start(":8080")
}
```

---

## 5. Concurrency & Thread-Safety Guarantees

In Go, HTTP handlers execute concurrently across multiple goroutines. `phinehas-go` is fully thread-safe:
* The built-in in-memory LRU cache uses `sync.RWMutex` to protect its internal doubly linked list and hash index.
* Read operations (checking if an IP is banned on benign traffic) acquire a shared read-lock (`RLock`), yielding sub-microsecond latency without goroutine contention.
* Zero memory allocations are performed on standard benign paths.

---

## 6. Testing Your Go Application with Phinehas

When writing unit tests with Go's `net/http/httptest` package, use `ActionReject` to assert on HTTP 403 status codes rather than dealing with hijacked socket drops:

```go
package main

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/phinehas-hq/sdks/packages/go"
)

func TestPhinehasMiddleware(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	// Use ActionReject for unit tests
	guard := phinehas.New(phinehas.Config{
		Action: phinehas.ActionReject,
	})
	handler := guard.Wrap(mux)

	// 1. Benign request
	req := httptest.NewRequest("GET", "/api/health", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	// 2. RFC 8615 Safe Pass
	req = httptest.NewRequest("GET", "/.well-known/security.txt", nil)
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code == http.StatusForbidden {
		t.Fatalf("expected .well-known not to be blocked, got %d", w.Code)
	}

	// 3. Dotfile attack
	req = httptest.NewRequest("GET", "/.env", nil)
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", w.Code)
	}
}
```

---

## 7. Navigation

* [Root SDK Documentation](../../README.md)
* [Shared Compliance Vectors (`compliance/`)](../../compliance/)

---

## 8. License

Licensed under the [Apache-2.0 License](../../LICENSE). Maintained by [Phinehas HQ](https://github.com/phinehas-hq).
