package phinehas_test

import (
	"bufio"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/phinehas-hq/sdks/packages/go"
)

// mockHijackableResponse implements http.ResponseWriter and http.Hijacker
type mockHijackableResponse struct {
	*httptest.ResponseRecorder
	hijacked bool
	closed   bool
}

func newMockHijackableResponse() *mockHijackableResponse {
	return &mockHijackableResponse{
		ResponseRecorder: httptest.NewRecorder(),
	}
}

type dummyConn struct {
	net.Conn
	closed bool
}

func (d *dummyConn) Close() error {
	d.closed = true
	return nil
}

func (m *mockHijackableResponse) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	m.hijacked = true
	conn := &dummyConn{}
	return conn, bufio.NewReadWriter(bufio.NewReader(conn), bufio.NewWriter(conn)), nil
}

func dummyHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	})
}

func TestMiddlewareCleanRoutePassThrough(t *testing.T) {
	guard := phinehas.New(phinehas.Config{
		AllowList: []string{"127.0.0.1"},
	})
	defer guard.Close()

	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/api/v1/health", nil)
	req.RemoteAddr = "127.0.0.1:12345"

	guard.Wrap(dummyHandler()).ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("Expected status 200, got %d", rec.Code)
	}
	if rec.Body.String() != `{"status":"ok"}` {
		t.Errorf("Expected body status ok, got %s", rec.Body.String())
	}
}

func TestMiddlewareImmediateSocketSeveranceOnAttack(t *testing.T) {
	var strikes []phinehas.StrikeEvent
	attackerIP := "198.51.100.77"

	guard := phinehas.New(phinehas.Config{
		Action:    phinehas.ActionTerminate,
		AllowList: []string{}, // clear localhost
		Proxy: phinehas.ProxyConfig{
			Trust:  true,
			Header: "CF-Connecting-IP",
		},
		OnStrike: func(strike phinehas.StrikeEvent) {
			strikes = append(strikes, strike)
		},
	})
	defer guard.Close()

	// 1. Attack on /.env
	w := newMockHijackableResponse()
	req := httptest.NewRequest("GET", "/.env", nil)
	req.Header.Set("CF-Connecting-IP", attackerIP)
	req.RemoteAddr = "10.0.0.1:54321"

	guard.Wrap(dummyHandler()).ServeHTTP(w, req)

	if !w.hijacked {
		t.Errorf("Expected TCP connection to be hijacked and severed")
	}
	if len(strikes) != 1 {
		t.Fatalf("Expected 1 strike, got %d", len(strikes))
	}
	if strikes[0].IP != attackerIP {
		t.Errorf("Expected strike IP %s, got %s", attackerIP, strikes[0].IP)
	}
	if strikes[0].RuleMatched != phinehas.RuleRFC8615Wildcard {
		t.Errorf("Expected rule rfc8615_wildcard, got %s", strikes[0].RuleMatched)
	}

	// 2. Subsequent request from same banned IP to clean route should also be severed
	w2 := newMockHijackableResponse()
	req2 := httptest.NewRequest("GET", "/api/v1/profile", nil)
	req2.Header.Set("CF-Connecting-IP", attackerIP)
	req2.RemoteAddr = "10.0.0.1:54321"

	guard.Wrap(dummyHandler()).ServeHTTP(w2, req2)
	if !w2.hijacked {
		t.Errorf("Expected subsequent request from banned IP to be severed")
	}
	if len(strikes) != 2 {
		t.Errorf("Expected 2 strikes recorded, got %d", len(strikes))
	}
}

func TestMiddlewareRejectAction(t *testing.T) {
	attackerIP := "203.0.113.66"

	guard := phinehas.New(phinehas.Config{
		Action:    phinehas.ActionReject,
		AllowList: []string{},
		Proxy: phinehas.ProxyConfig{
			Trust:  true,
			Header: "CF-Connecting-IP",
		},
		LoggingEnabled: false,
	})
	defer guard.Close()

	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/wp-login.php", nil)
	req.Header.Set("CF-Connecting-IP", attackerIP)
	req.RemoteAddr = "10.0.0.1:54321"

	guard.Wrap(dummyHandler()).ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Errorf("Expected status 403, got %d", rec.Code)
	}
	if rec.Header().Get("X-Phinehas-Verdict") != "blocked" {
		t.Errorf("Expected X-Phinehas-Verdict: blocked")
	}
}

func TestMiddlewareAllowListAndWellKnown(t *testing.T) {
	guard := phinehas.New(phinehas.Config{
		AllowList:      []string{"127.0.0.1"},
		LoggingEnabled: false,
		TTL:            time.Hour,
	})
	defer guard.Close()

	// 1. RFC 8615 .well-known route must pass
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/.well-known/jwks.json", nil)
	req.RemoteAddr = "198.51.100.9:12345"
	guard.Wrap(dummyHandler()).ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("Expected .well-known to return 200, got %d", rec.Code)
	}

	// 2. Allowlisted IP probing dotfile must pass without ban
	rec2 := httptest.NewRecorder()
	req2 := httptest.NewRequest("GET", "/.env", nil)
	req2.RemoteAddr = "127.0.0.1:12345"
	guard.Wrap(dummyHandler()).ServeHTTP(rec2, req2)
	if rec2.Code != http.StatusOK {
		t.Errorf("Expected allowlisted IP to return 200, got %d", rec2.Code)
	}
}
