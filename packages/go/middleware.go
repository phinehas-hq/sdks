package phinehas

import (
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/phinehas-hq/sdks/packages/go/store"
)

// NormalizeIP cleans IPv6-mapped IPv4 addresses (::ffff:127.0.0.1 -> 127.0.0.1).
func NormalizeIP(ip string) string {
	ip = strings.TrimSpace(ip)
	if strings.HasPrefix(ip, "::ffff:") {
		ip = ip[7:]
	}
	return ip
}

// ExtractClientIP extracts the remote client IP according to proxy configuration.
func ExtractClientIP(r *http.Request, proxy ProxyConfig) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	socketIP := NormalizeIP(host)

	if !proxy.Trust {
		return socketIP
	}

	// 1. Custom proxy header
	if proxy.Header != "" {
		customVal := r.Header.Get(proxy.Header)
		if customVal != "" {
			parts := strings.Split(customVal, ",")
			return NormalizeIP(parts[0])
		}
	}

	// 2. Cloudflare header
	if cfIP := r.Header.Get("CF-Connecting-IP"); cfIP != "" {
		parts := strings.Split(cfIP, ",")
		return NormalizeIP(parts[0])
	}

	// 3. X-Real-IP
	if realIP := r.Header.Get("X-Real-IP"); realIP != "" {
		return NormalizeIP(realIP)
	}

	// 4. X-Forwarded-For with depth
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		var ips []string
		for _, part := range strings.Split(xff, ",") {
			ips = append(ips, NormalizeIP(part))
		}
		if proxy.Depth > 0 {
			targetIdx := len(ips) - proxy.Depth
			if targetIdx >= 0 && targetIdx < len(ips) {
				return ips[targetIdx]
			}
		}
		return ips[0]
	}

	return socketIP
}

// IsIPAllowed checks if an IP is included in the exempt whitelist.
func IsIPAllowed(ip string, allowList []string) bool {
	norm := NormalizeIP(ip)
	for _, allowed := range allowList {
		normAllowed := NormalizeIP(allowed)
		if norm == normAllowed {
			return true
		}
		if (norm == "127.0.0.1" || norm == "::1") &&
			(normAllowed == "127.0.0.1" || normAllowed == "::1" || normAllowed == "localhost") {
			return true
		}
	}
	return false
}

// Guard is the Phinehas HTTP middleware guard.
type Guard struct {
	store     store.BanStore
	storeName string
	evaluator *ThreatEvaluator
	logger    *Logger
	ttl       time.Duration
	action    Action
	allowList []string
	proxy     ProxyConfig
}

// New initializes a Phinehas Guard with the provided configuration.
func New(cfg Config) *Guard {
	s := cfg.Store
	sName := "memory"
	if s == nil {
		s = store.NewMemoryStore(25000, cfg.TTL)
	} else {
		sName = "custom"
	}

	action := cfg.Action
	if action == "" {
		action = ActionTerminate
	}

	ttl := cfg.TTL
	if ttl <= 0 {
		ttl = time.Hour
	}

	allows := cfg.AllowList
	if len(allows) == 0 {
		allows = []string{"127.0.0.1", "::1"}
	}

	eval := NewThreatEvaluator(cfg.CustomTraps, cfg.ExcludeDefaults)
	log := NewLogger(cfg.LoggingEnabled, cfg.LogFormat, cfg.OnStrike)

	return &Guard{
		store:     s,
		storeName: sName,
		evaluator: eval,
		logger:    log,
		ttl:       ttl,
		action:    action,
		allowList: allows,
		proxy:     cfg.Proxy,
	}
}

// Wrap returns an http.Handler wrapping the downstream handler.
func (g *Guard) Wrap(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			// Fail-open: catch panics in security logic and yield to next handler
			if rec := recover(); rec != nil {
				next.ServeHTTP(w, r)
			}
		}()

		clientIP := ExtractClientIP(r, g.proxy)

		// 1. Allowlist exemption
		if IsIPAllowed(clientIP, g.allowList) {
			next.ServeHTTP(w, r)
			return
		}

		headers := make(map[string]string)
		for k, v := range r.Header {
			if len(v) > 0 {
				headers[strings.ToLower(k)] = v[0]
			}
		}

		// 2. Check existing ban
		isBanned, err := g.store.IsBanned(clientIP)
		if err == nil && isBanned {
			strike := StrikeEvent{
				IP:          clientIP,
				Path:        r.URL.Path,
				Method:      r.Method,
				Headers:     headers,
				RuleMatched: RuleExplicitTrap,
				Timestamp:   time.Now().UTC().Format(time.RFC3339),
			}
			g.logger.LogStrike(strike, g.action, g.storeName, int(g.ttl.Seconds()), r.UserAgent(), r.Host)
			ExecuteAction(g.action, w)
			return
		}

		// 3. Evaluate Request Path
		res := g.evaluator.Evaluate(r.URL.Path)
		if res.IsBlocked {
			_ = g.store.Ban(clientIP, g.ttl)

			strike := StrikeEvent{
				IP:          clientIP,
				Path:        r.URL.Path,
				Method:      r.Method,
				Headers:     headers,
				RuleMatched: res.RuleMatched,
				Timestamp:   time.Now().UTC().Format(time.RFC3339),
			}
			g.logger.LogStrike(strike, g.action, g.storeName, int(g.ttl.Seconds()), r.UserAgent(), r.Host)
			ExecuteAction(g.action, w)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// HandlerFunc wraps a standard http.HandlerFunc.
func (g *Guard) HandlerFunc(next http.HandlerFunc) http.HandlerFunc {
	return g.Wrap(next).ServeHTTP
}

// Close disposes store resources.
func (g *Guard) Close() error {
	return g.store.Close()
}
