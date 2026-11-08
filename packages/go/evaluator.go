package phinehas

import "strings"

// ThreatEvaluator evaluates request paths against RFC 8615 lookaheads and honeypot registries.
type ThreatEvaluator struct {
	explicitTraps map[string]struct{}
	customTraps   map[string]struct{}
	prefixTraps   []string
}

// NewThreatEvaluator creates a new threat evaluation engine.
func NewThreatEvaluator(customTraps []string, excludeDefaults bool) *ThreatEvaluator {
	explicit := make(map[string]struct{})
	if !excludeDefaults {
		for _, trap := range DefaultExplicitTraps {
			explicit[trap] = struct{}{}
		}
	}

	custom := make(map[string]struct{})
	for _, c := range customTraps {
		custom[NormalizePath(c)] = struct{}{}
	}

	var prefixes []string
	for trap := range explicit {
		if !strings.Contains(trap, ".") {
			prefixes = append(prefixes, trap)
		}
	}

	return &ThreatEvaluator{
		explicitTraps: explicit,
		customTraps:   custom,
		prefixTraps:   prefixes,
	}
}

// Evaluate analyzes a raw path against the Phinehas detection pipeline.
func (e *ThreatEvaluator) Evaluate(rawPath string) EvaluationResult {
	normalized := NormalizePath(rawPath)

	// 1. Check RFC 8615 Wildcard Rule
	if MatchRFC8615Wildcard(normalized) {
		return EvaluationResult{
			IsBlocked:      true,
			NormalizedPath: normalized,
			RuleMatched:    RuleRFC8615Wildcard,
			Reason:         "Matched RFC 8615 hidden path wildcard: " + normalized,
		}
	}

	// 2. Check Custom Honeypots
	for custom := range e.customTraps {
		if normalized == custom || strings.HasPrefix(normalized, custom+"/") {
			return EvaluationResult{
				IsBlocked:      true,
				NormalizedPath: normalized,
				RuleMatched:    RuleCustomTrap,
				Reason:         "Matched custom honeypot trap: " + custom,
			}
		}
	}

	// 3. Check Explicit Non-Dot Traps (Exact match)
	if _, exists := e.explicitTraps[normalized]; exists {
		return EvaluationResult{
			IsBlocked:      true,
			NormalizedPath: normalized,
			RuleMatched:    RuleExplicitTrap,
			Reason:         "Matched explicit threat signature: " + normalized,
		}
	}

	// 4. Check Explicit Prefix Traps (e.g. /wp-admin/foo, /actuator/bar)
	for _, prefix := range e.prefixTraps {
		if strings.HasPrefix(normalized, prefix+"/") {
			return EvaluationResult{
				IsBlocked:      true,
				NormalizedPath: normalized,
				RuleMatched:    RuleExplicitTrap,
				Reason:         "Matched explicit prefix threat signature: " + prefix,
			}
		}
	}

	return EvaluationResult{
		IsBlocked:      false,
		NormalizedPath: normalized,
	}
}
