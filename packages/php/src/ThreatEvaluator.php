<?php

declare(strict_types=1);

namespace Phinehas;

final class ThreatEvaluator
{
    private array $explicitTraps;
    private array $customTraps;
    private array $prefixTraps;

    public function __construct(array $customTraps = [], bool $excludeDefaults = false)
    {
        $defaultTraps = $excludeDefaults ? [] : Traps::DEFAULT_EXPLICIT_TRAPS;
        $this->explicitTraps = array_flip($defaultTraps);

        $normalizedCustom = array_map(fn($p) => Normalizer::normalize($p), $customTraps);
        $this->customTraps = array_flip($normalizedCustom);

        $this->prefixTraps = array_filter(
            $defaultTraps,
            fn($trap) => !str_contains($trap, '.')
        );
    }

    public function evaluate(string $rawPath): array
    {
        $normalized = Normalizer::normalize($rawPath);

        // 1. Check RFC 8615 Wildcard Rule
        if (preg_match(Traps::RFC8615_PATTERN, $normalized) === 1) {
            return [
                'is_blocked' => true,
                'normalized_path' => $normalized,
                'rule_matched' => 'rfc8615_wildcard',
                'reason' => 'Matched RFC 8615 hidden path wildcard: ' . $normalized,
            ];
        }

        // 2. Check Custom Honeypots
        foreach (array_keys($this->customTraps) as $custom) {
            if ($normalized === $custom || str_starts_with($normalized, $custom . '/')) {
                return [
                    'is_blocked' => true,
                    'normalized_path' => $normalized,
                    'rule_matched' => 'custom_trap',
                    'reason' => 'Matched custom honeypot trap: ' . $custom,
                ];
            }
        }

        // 3. Check Explicit Non-Dot Traps (Exact match)
        if (isset($this->explicitTraps[$normalized])) {
            return [
                'is_blocked' => true,
                'normalized_path' => $normalized,
                'rule_matched' => 'explicit_trap',
                'reason' => 'Matched explicit threat signature: ' . $normalized,
            ];
        }

        // 4. Check Explicit Prefix Traps (e.g. /wp-admin/foo, /actuator/bar)
        foreach ($this->prefixTraps as $prefix) {
            if (str_starts_with($normalized, $prefix . '/')) {
                return [
                    'is_blocked' => true,
                    'normalized_path' => $normalized,
                    'rule_matched' => 'explicit_trap',
                    'reason' => 'Matched explicit prefix threat signature: ' . $prefix,
                ];
            }
        }

        return [
            'is_blocked' => false,
            'normalized_path' => $normalized,
        ];
    }
}
