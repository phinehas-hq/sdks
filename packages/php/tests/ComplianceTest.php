<?php

declare(strict_types=1);

namespace Phinehas\Tests;

use Phinehas\Normalizer;
use Phinehas\ThreatEvaluator;

final class ComplianceTest
{
    private string $complianceDir;

    public function __construct()
    {
        $this->complianceDir = dirname(__DIR__, 3) . '/compliance';
    }

    public function testNormalizationCompliance(): void
    {
        $fixture = json_decode(
            (string) file_get_contents($this->complianceDir . '/normalization_vectors.json'),
            true
        );

        foreach ($fixture['cases'] as $case) {
            $actual = Normalizer::normalize($case['raw_input']);
            if ($actual !== $case['expected_normalized']) {
                throw new \RuntimeException(
                    "Normalization failed for [{$case['raw_input']}]: expected {$case['expected_normalized']}, got {$actual}"
                );
            }
        }
    }

    public function testRFC8615Compliance(): void
    {
        $fixture = json_decode(
            (string) file_get_contents($this->complianceDir . '/rfc8615_vectors.json'),
            true
        );

        $evaluator = new ThreatEvaluator();
        foreach ($fixture['cases'] as $case) {
            $res = $evaluator->evaluate($case['path']);
            if ($res['is_blocked'] !== $case['expected_strike']) {
                throw new \RuntimeException(
                    "RFC 8615 failed for [{$case['path']}] ({$case['reason']}): expected " .
                    ($case['expected_strike'] ? 'true' : 'false') . ", got " . ($res['is_blocked'] ? 'true' : 'false')
                );
            }
            if ($case['expected_strike'] && $res['rule_matched'] !== 'rfc8615_wildcard') {
                throw new \RuntimeException("Expected rule rfc8615_wildcard, got {$res['rule_matched']}");
            }
        }
    }

    public function testExplicitTrapsCompliance(): void
    {
        $fixture = json_decode(
            (string) file_get_contents($this->complianceDir . '/explicit_traps.json'),
            true
        );

        $evaluator = new ThreatEvaluator();
        foreach ($fixture['traps'] as $trap) {
            $res = $evaluator->evaluate($trap);
            if (!$res['is_blocked']) {
                throw new \RuntimeException("Explicit trap [{$trap}] was not blocked");
            }
            if ($res['rule_matched'] !== 'explicit_trap') {
                throw new \RuntimeException("Expected explicit_trap, got {$res['rule_matched']}");
            }
        }

        // Prefix traps
        $prefixes = [
            '/wp-admin/install.php',
            '/actuator/env',
            '/phpmyadmin/index.php',
        ];
        foreach ($prefixes as $p) {
            $res = $evaluator->evaluate($p);
            if (!$res['is_blocked']) {
                throw new \RuntimeException("Prefix trap [{$p}] was not blocked");
            }
        }
    }
}
