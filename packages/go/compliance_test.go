package phinehas_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/phinehas-hq/sdks/packages/go"
)

func getCompliancePath(t *testing.T, filename string) string {
	// From packages/go to compliance/ is ../../compliance
	p := filepath.Join("..", "..", "compliance", filename)
	abs, err := filepath.Abs(p)
	if err != nil {
		t.Fatalf("Failed to resolve compliance path: %v", err)
	}
	return abs
}

type normCase struct {
	RawInput           string `json:"raw_input"`
	ExpectedNormalized string `json:"expected_normalized"`
	Description        string `json:"description"`
}

type normFixture struct {
	Cases []normCase `json:"cases"`
}

func TestNormalizationCompliance(t *testing.T) {
	data, err := os.ReadFile(getCompliancePath(t, "normalization_vectors.json"))
	if err != nil {
		t.Fatalf("Failed to read normalization fixture: %v", err)
	}

	var fixture normFixture
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatalf("Failed to parse JSON: %v", err)
	}

	for _, tc := range fixture.Cases {
		actual := phinehas.NormalizePath(tc.RawInput)
		if actual != tc.ExpectedNormalized {
			t.Errorf("[%s] Expected %s, got %s", tc.RawInput, tc.ExpectedNormalized, actual)
		}
	}
}

type rfcCase struct {
	Path           string `json:"path"`
	ExpectedStrike bool   `json:"expected_strike"`
	Reason         string `json:"reason"`
}

type rfcFixture struct {
	Cases []rfcCase `json:"cases"`
}

func TestRFC8615Compliance(t *testing.T) {
	data, err := os.ReadFile(getCompliancePath(t, "rfc8615_vectors.json"))
	if err != nil {
		t.Fatalf("Failed to read RFC 8615 fixture: %v", err)
	}

	var fixture rfcFixture
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatalf("Failed to parse JSON: %v", err)
	}

	evaluator := phinehas.NewThreatEvaluator(nil, false)
	for _, tc := range fixture.Cases {
		res := evaluator.Evaluate(tc.Path)
		if res.IsBlocked != tc.ExpectedStrike {
			t.Errorf("[%s] (%s) Expected isBlocked=%v, got %v", tc.Path, tc.Reason, tc.ExpectedStrike, res.IsBlocked)
		}
		if tc.ExpectedStrike && res.RuleMatched != phinehas.RuleRFC8615Wildcard {
			t.Errorf("[%s] Expected rule rfc8615_wildcard, got %s", tc.Path, res.RuleMatched)
		}
	}
}

type explicitFixture struct {
	Traps []string `json:"traps"`
}

func TestExplicitTrapsCompliance(t *testing.T) {
	data, err := os.ReadFile(getCompliancePath(t, "explicit_traps.json"))
	if err != nil {
		t.Fatalf("Failed to read explicit traps fixture: %v", err)
	}

	var fixture explicitFixture
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatalf("Failed to parse JSON: %v", err)
	}

	evaluator := phinehas.NewThreatEvaluator(nil, false)
	for _, trap := range fixture.Traps {
		res := evaluator.Evaluate(trap)
		if !res.IsBlocked {
			t.Errorf("Expected trap [%s] to be blocked", trap)
		}
		if res.RuleMatched != phinehas.RuleExplicitTrap {
			t.Errorf("[%s] Expected rule explicit_trap, got %s", trap, res.RuleMatched)
		}
	}

	// Prefix traps
	prefixes := []string{
		"/wp-admin/install.php",
		"/actuator/env",
		"/phpmyadmin/index.php",
	}
	for _, p := range prefixes {
		res := evaluator.Evaluate(p)
		if !res.IsBlocked {
			t.Errorf("Expected prefix trap [%s] to be blocked", p)
		}
	}
}
