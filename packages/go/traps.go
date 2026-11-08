package phinehas

import (
	"regexp"
	"strings"
)

// DefaultExplicitTraps defines the canonical list of non-dot honeypot endpoints.
var DefaultExplicitTraps = []string{
	// CMS & Common Admin Consoles
	"/wp-login.php",
	"/wp-admin",
	"/xmlrpc.php",
	"/wp-config.php",
	"/administrator",
	"/user/login",

	// Database Management Consoles
	"/phpmyadmin",
	"/pma",
	"/adminer.php",
	"/mysql",
	"/dbadmin",

	// Framework Debuggers & Sensitive Endpoints
	"/_ignition/execute-solution",
	"/__debug__",
	"/actuator",
	"/actuator/env",
	"/actuator/health",
	"/telescope",
	"/elmah.axd",

	// Sensitive File Dumps & Archives
	"/dump.sql",
	"/backup.sql",
	"/database.sql",
	"/db.sqlite3",
	"/backup.tar.gz",
	"/backup.zip",
}

// dotfileTokenPattern matches dotfile root tokens
var dotfileTokenPattern = regexp.MustCompile(`^\/\.[a-zA-Z0-9_\-\.]+`)

// MatchRFC8615Wildcard evaluates paths against the RFC 8615 rule:
// Matches ^/\.(?!well-known(/|$))[a-zA-Z0-9_\-\.]+
// In Go, splitting the lookahead into an explicit prefix guard maintains linear O(1) matching.
func MatchRFC8615Wildcard(path string) bool {
	if !strings.HasPrefix(path, "/.") {
		return false
	}
	if path == "/.well-known" || strings.HasPrefix(path, "/.well-known/") {
		return false
	}
	return dotfileTokenPattern.MatchString(path)
}
