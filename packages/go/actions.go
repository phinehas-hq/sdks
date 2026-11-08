package phinehas

import (
	"net/http"
	"time"
)

// ExecuteAction applies the configured security action against attacking or banned clients.
func ExecuteAction(action Action, w http.ResponseWriter) {
	switch action {
	case ActionTerminate:
		if hijacker, ok := w.(http.Hijacker); ok {
			conn, _, err := hijacker.Hijack()
			if err == nil {
				_ = conn.Close() // Sever raw TCP socket immediately!
				return
			}
		}
		// Fallback if Hijacker is not supported by wrapper (e.g. HTTP/2 or mock response writer)
		w.Header().Set("Content-Length", "0")
		w.Header().Set("Connection", "close")
		w.Header().Set("X-Phinehas-Verdict", "terminated")
		w.WriteHeader(http.StatusForbidden)

	case ActionReject:
		w.Header().Set("Content-Type", "text/plain")
		w.Header().Set("Content-Length", "0")
		w.Header().Set("Connection", "close")
		w.Header().Set("X-Phinehas-Verdict", "blocked")
		w.WriteHeader(http.StatusForbidden)

	case ActionTarpit:
		time.Sleep(5 * time.Second)
		w.Header().Set("Content-Length", "0")
		w.Header().Set("Connection", "close")
		w.Header().Set("X-Phinehas-Verdict", "tarpit")
		w.WriteHeader(http.StatusForbidden)
	}
}
