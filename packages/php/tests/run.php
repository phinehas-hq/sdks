<?php

declare(strict_types=1);

// Lightweight test runner with zero external dependencies
spl_autoload_register(function ($class) {
    $prefix = 'Phinehas\\';
    $baseDir = dirname(__DIR__) . '/src/';

    if (str_starts_with($class, 'Phinehas\\Tests\\')) {
        $testFile = dirname(__DIR__) . '/tests/' . str_replace('\\', '/', substr($class, strlen('Phinehas\\Tests\\'))) . '.php';
        if (file_exists($testFile)) {
            require_once $testFile;
            return;
        }
    }

    $len = strlen($prefix);
    if (strncmp($prefix, $class, $len) !== 0) {
        return;
    }

    $relativeClass = substr($class, $len);
    $file = $baseDir . str_replace('\\', '/', $relativeClass) . '.php';

    if (file_exists($file)) {
        require_once $file;
    }
});

use Phinehas\Tests\ComplianceTest;
use Phinehas\Tests\MemoryStoreTest;
use Phinehas\Tests\LaravelMiddlewareTest;

$tests = [
    [new ComplianceTest(), 'testNormalizationCompliance', 'Anti-Bypass Path Normalization Compliance'],
    [new ComplianceTest(), 'testRFC8615Compliance', 'RFC 8615 Wildcard Rule Compliance'],
    [new ComplianceTest(), 'testExplicitTrapsCompliance', 'Explicit Traps Registry Compliance'],
    [new MemoryStoreTest(), 'testLRUEvictionAndCapacity', 'MemoryStore: LRU Eviction & Capacity Cap'],
    [new MemoryStoreTest(), 'testTTLExpiration', 'MemoryStore: TTL Expiration'],
    [new LaravelMiddlewareTest(), 'testCleanRoutePassThrough', 'Laravel Middleware: Clean Route Pass-Through'],
    [new LaravelMiddlewareTest(), 'testStrikeAndSubsequentBan', 'Laravel Middleware: Strike Interception & Subsequent Ban'],
];

$passed = 0;
$failed = 0;

foreach ($tests as [$instance, $method, $label]) {
    try {
        $instance->$method();
        echo "✔ {$label}\n";
        $passed++;
    } catch (\Throwable $e) {
        echo "✖ {$label}: {$e->getMessage()}\n";
        $failed++;
    }
}

echo "\nSummary: {$passed} passed, {$failed} failed\n";
exit($failed > 0 ? 1 : 0);
