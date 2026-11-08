package phinehas

import (
	"net/url"
	"path"
	"strings"
)

// SafeURLDecode iteratively unescapes percent-encoded URI strings up to 3 passes.
func SafeURLDecode(rawPath string) string {
	decoded := rawPath
	for i := 0; i < 3; i++ {
		next, err := url.PathUnescape(decoded)
		if err != nil || next == decoded {
			break
		}
		decoded = next
	}

	// Fallback replacement for known evasion tokens if unescape did not process them
	decoded = strings.ReplaceAll(decoded, "%2e", ".")
	decoded = strings.ReplaceAll(decoded, "%2E", ".")
	decoded = strings.ReplaceAll(decoded, "%2f", "/")
	decoded = strings.ReplaceAll(decoded, "%2F", "/")
	decoded = strings.ReplaceAll(decoded, "%5c", "\\")
	decoded = strings.ReplaceAll(decoded, "%5C", "\\")

	return decoded
}

// NormalizePath executes the complete 6-stage anti-bypass normalization pipeline:
// 1. Hex URL decoding (%2e, %2f, %5c)
// 2. Windows backslash conversion (\ -> /)
// 3. Slash collapsing (//+ -> /)
// 4. Directory traversal resolution (/api/v1/../../.env -> /.env)
// 5. Lowercasing
// 6. Trailing slash removal
func NormalizePath(rawPath string) string {
	if rawPath == "" {
		return "/"
	}

	// 1. URL Decoding
	normalized := SafeURLDecode(rawPath)

	// 2. Windows Backslash Conversion
	normalized = strings.ReplaceAll(normalized, "\\", "/")

	// Ensure leading slash
	if !strings.HasPrefix(normalized, "/") {
		normalized = "/" + normalized
	}

	// 3 & 4. Slash Collapsing & Traversal Resolution using path.Clean
	normalized = path.Clean(normalized)

	// 5. Lowercasing
	normalized = strings.ToLower(normalized)

	// 6. Trailing Slash Removal (preserve single root '/')
	if len(normalized) > 1 && strings.HasSuffix(normalized, "/") {
		normalized = strings.TrimSuffix(normalized, "/")
	}

	return normalized
}
