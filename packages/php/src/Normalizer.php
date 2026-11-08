<?php

declare(strict_types=1);

namespace Phinehas;

final class Normalizer
{
    /**
     * Iteratively decodes percent-encoded hex sequences up to 3 passes.
     */
    public static function safeUrlDecode(string $rawPath): string
    {
        $decoded = $rawPath;
        for ($i = 0; $i < 3; $i++) {
            $next = rawurldecode($decoded);
            if ($next === $decoded) {
                break;
            }
            $decoded = $next;
        }

        // Defensive hex substitution for critical evasion tokens
        $decoded = str_ireplace(['%2e', '%2f', '%5c'], ['.', '/', '\\'], $decoded);

        return $decoded;
    }

    /**
     * Resolves relative directory traversals (. and ..) without escaping root.
     */
    public static function resolvePathTraversal(string $path): string
    {
        $parts = explode('/', $path);
        $resolved = [];

        foreach ($parts as $part) {
            if ($part === '' || $part === '.') {
                continue;
            }
            if ($part === '..') {
                if (!empty($resolved)) {
                    array_pop($resolved);
                }
            } else {
                $resolved[] = $part;
            }
        }

        return '/' . implode('/', $resolved);
    }

    /**
     * Executes the 6-stage anti-bypass normalization pipeline:
     * 1. Hex URL decoding (%2e, %2f, %5c)
     * 2. Windows backslash conversion (\ -> /)
     * 3. Slash collapsing (//+ -> /)
     * 4. Path traversal resolution (/api/v1/../../.env -> /.env)
     * 5. Lowercasing
     * 6. Trailing slash removal
     */
    public static function normalize(string $rawPath): string
    {
        if ($rawPath === '') {
            return '/';
        }

        // 1. URL Decoding
        $normalized = self::safeUrlDecode($rawPath);

        // 2. Windows Backslash Conversion
        $normalized = str_replace('\\', '/', $normalized);

        // Ensure leading slash
        if (!str_starts_with($normalized, '/')) {
            $normalized = '/' . $normalized;
        }

        // 3. Slash Collapsing
        $normalized = (string) preg_replace('#/{2,}#', '/', $normalized);

        // 4. Path Traversal Resolution
        $normalized = self::resolvePathTraversal($normalized);

        // 5. Lowercasing
        $normalized = strtolower($normalized);

        // 6. Trailing Slash Removal (preserve single root '/')
        if (strlen($normalized) > 1 && str_ends_with($normalized, '/')) {
            $normalized = rtrim($normalized, '/');
        }

        return $normalized;
    }
}
