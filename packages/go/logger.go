package phinehas

import (
	"encoding/json"
	"fmt"
	"os"
)

// Logger outputs structured audit telemetry upon strikes.
type Logger struct {
	enabled  bool
	format   LogFormat
	onStrike StrikeCallback
}

// NewLogger creates a new logging emitter.
func NewLogger(enabled bool, format LogFormat, onStrike StrikeCallback) *Logger {
	if format == "" {
		format = LogFormatStructured
	}
	return &Logger{
		enabled:  enabled,
		format:   format,
		onStrike: onStrike,
	}
}

// LogStrike records an attack event.
func (l *Logger) LogStrike(
	strike StrikeEvent,
	action Action,
	banStoreName string,
	banTTLSeconds int,
	userAgent string,
	host string,
) {
	if l.onStrike != nil {
		defer func() {
			_ = recover() // Suppress user callback panics to preserve fail-open safety
		}()
		l.onStrike(strike)
	}

	if !l.enabled {
		return
	}

	if l.format == LogFormatCompact {
		actionLabel := "Blocked"
		if action == ActionTerminate {
			actionLabel = "Severed"
		}
		fmt.Fprintf(os.Stderr, "[PHINEHAS STRIKE] %s %s accessing %s\n", actionLabel, strike.IP, strike.Path)
		return
	}

	actionDesc := "TCP_SOCKET_TERMINATED"
	switch action {
	case ActionReject:
		actionDesc = "HTTP_403_REJECTED"
	case ActionTarpit:
		actionDesc = "TARPIT_ENFORCED"
	}

	ua := userAgent
	if ua == "" {
		ua = strike.Headers["user-agent"]
	}
	if ua == "" {
		ua = "unknown"
	}

	h := host
	if h == "" {
		h = strike.Headers["host"]
	}
	if h == "" {
		h = "unknown"
	}

	structuredLog := map[string]interface{}{
		"timestamp": strike.Timestamp,
		"level":     "WARN",
		"event":     "PHINEHAS_SPEAR_STRIKE",
		"actor": map[string]string{
			"ip":         strike.IP,
			"user_agent": ua,
		},
		"target": map[string]string{
			"path":   strike.Path,
			"method": strike.Method,
			"host":   h,
		},
		"verdict": map[string]interface{}{
			"rule_matched":    strike.RuleMatched,
			"action_taken":    actionDesc,
			"ban_store":       banStoreName,
			"ban_ttl_seconds": banTTLSeconds,
		},
	}

	raw, err := json.Marshal(structuredLog)
	if err == nil {
		fmt.Fprintln(os.Stderr, string(raw))
	}
}
