package phinehas

import (
	"time"

	"github.com/phinehas-hq/sdks/packages/go/store"
)

// Action defines the enforcement behavior upon detecting an attack or banned IP.
type Action string

const (
	ActionTerminate Action = "terminate" // Hijacks and severs raw TCP socket immediately (Default)
	ActionReject    Action = "reject"    // Returns HTTP 403 Forbidden with empty body
	ActionTarpit    Action = "tarpit"    // Holds connection open and drips bytes
)

// LogFormat defines the structured vs compact log output format.
type LogFormat string

const (
	LogFormatCompact    LogFormat = "compact"
	LogFormatStructured LogFormat = "structured"
)

// RuleMatched identifies which detection rule was triggered.
type RuleMatched string

const (
	RuleRFC8615Wildcard RuleMatched = "rfc8615_wildcard"
	RuleExplicitTrap    RuleMatched = "explicit_trap"
	RuleCustomTrap      RuleMatched = "custom_trap"
)

// StrikeEvent represents structured metadata about a detected attack.
type StrikeEvent struct {
	IP          string            `json:"ip"`
	Path        string            `json:"path"`
	Method      string            `json:"method"`
	Headers     map[string]string `json:"headers"`
	RuleMatched RuleMatched       `json:"ruleMatched"`
	Timestamp   string            `json:"timestamp"` // ISO 8601
}

// StrikeCallback defines a custom listener for strike notifications.
type StrikeCallback func(strike StrikeEvent)

// EvaluationResult contains the outcome of a path evaluation.
type EvaluationResult struct {
	IsBlocked      bool
	NormalizedPath string
	RuleMatched    RuleMatched
	Reason         string
}

// ProxyConfig defines reverse proxy parsing rules.
type ProxyConfig struct {
	Trust  bool   // Whether to trust proxy headers
	Header string // Custom IP header (e.g. "CF-Connecting-IP")
	Depth  int    // Number of proxy hops to inspect in X-Forwarded-For
}

// Config specifies the runtime configuration for the Phinehas guard.
type Config struct {
	Store          store.BanStore
	TTL            time.Duration  // Ban duration (Default: 1 hour)
	Action         Action         // Action to take on strike (Default: ActionTerminate)
	CustomTraps    []string       // Extra paths to trap
	ExcludeDefaults bool          // Disable default non-dot traps
	AllowList      []string       // Whitelisted IP addresses (Default: 127.0.0.1, ::1)
	Proxy          ProxyConfig    // Trusted reverse proxy settings
	LoggingEnabled bool           // Whether logging is active (Default: true)
	LogFormat      LogFormat      // "structured" or "compact"
	OnStrike       StrikeCallback // Custom strike notification callback
}
