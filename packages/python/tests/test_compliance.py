import json
import unittest
from pathlib import Path
import sys

# Ensure src/ is on python path
SRC_DIR = Path(__file__).resolve().parents[1] / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from phinehas import ThreatEvaluator, normalize_path

COMPLIANCE_DIR = Path(__file__).resolve().parents[3] / "compliance"


class TestCompliance(unittest.TestCase):
    def test_normalization_compliance(self):
        with open(COMPLIANCE_DIR / "normalization_vectors.json", encoding="utf-8") as f:
            data = json.load(f)

        for case in data["cases"]:
            actual = normalize_path(case["raw_input"])
            self.assertEqual(
                actual,
                case["expected_normalized"],
                f"Failed on [{case['raw_input']}]: expected {case['expected_normalized']}, got {actual}",
            )

    def test_rfc8615_compliance(self):
        with open(COMPLIANCE_DIR / "rfc8615_vectors.json", encoding="utf-8") as f:
            data = json.load(f)

        evaluator = ThreatEvaluator()
        for case in data["cases"]:
            result = evaluator.evaluate(case["path"])
            self.assertEqual(
                result.is_blocked,
                case["expected_strike"],
                f"Failed on [{case['path']}] ({case['reason']}): "
                f"expected is_blocked={case['expected_strike']}, got {result.is_blocked}",
            )
            if case["expected_strike"]:
                self.assertEqual(result.rule_matched, "rfc8615_wildcard")

    def test_explicit_traps_compliance(self):
        with open(COMPLIANCE_DIR / "explicit_traps.json", encoding="utf-8") as f:
            data = json.load(f)

        evaluator = ThreatEvaluator()
        for trap_path in data["traps"]:
            result = evaluator.evaluate(trap_path)
            self.assertTrue(result.is_blocked, f"Explicit trap [{trap_path}] was not blocked")
            self.assertEqual(result.rule_matched, "explicit_trap")

        prefix_cases = [
            "/wp-admin/install.php",
            "/actuator/env",
            "/phpmyadmin/index.php",
        ]
        for p in prefix_cases:
            res = evaluator.evaluate(p)
            self.assertTrue(res.is_blocked)
            self.assertEqual(res.rule_matched, "explicit_trap")


if __name__ == "__main__":
    unittest.main()
