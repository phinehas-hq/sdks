<?php

declare(strict_types=1);

namespace Phinehas\Tests;

use Phinehas\Laravel\PhinehasMiddleware;
use Phinehas\Store\MemoryStore;

class MockLaravelRequest
{
    private string $path;
    private string $ip;
    private array $headers;

    public function __construct(string $path, string $ip = '127.0.0.1', array $headers = [])
    {
        $this->path = $path;
        $this->ip = $ip;
        $this->headers = array_change_key_case($headers, CASE_LOWER);
    }

    public function path(): string
    {
        return $this->path;
    }

    public function ip(): string
    {
        return $this->ip;
    }

    public function header(string $key): ?string
    {
        return $this->headers[strtolower($key)] ?? null;
    }

    public function method(): string
    {
        return 'GET';
    }
}

final class LaravelMiddlewareTest
{
    public function testCleanRoutePassThrough(): void
    {
        $store = new MemoryStore();
        $middleware = new PhinehasMiddleware($store);

        $request = new MockLaravelRequest('/api/v1/health', '127.0.0.1');
        $nextCalled = false;

        $response = $middleware->handle($request, function ($req) use (&$nextCalled) {
            $nextCalled = true;
            return 'passed';
        });

        if (!$nextCalled || $response !== 'passed') {
            throw new \RuntimeException('Clean route must call next() and pass through');
        }
    }

    public function testStrikeAndSubsequentBan(): void
    {
        $store = new MemoryStore();
        $middleware = new PhinehasMiddleware($store);

        $attackerIp = '198.51.100.99';
        $attackReq = new MockLaravelRequest('/.env.backup', $attackerIp);

        $nextCalled = false;
        // Mock global abort function behaviour or intercept response
        $middleware->handle($attackReq, function ($req) use (&$nextCalled) {
            $nextCalled = true;
        });

        if ($nextCalled) {
            throw new \RuntimeException('Attack request must not reach next handler');
        }

        // Verify attacker IP was banned in the store
        if (!$store->isBanned($attackerIp)) {
            throw new \RuntimeException('Attacker IP was not stored in ban registry');
        }

        // Subsequent clean request from banned IP must also be intercepted
        $cleanReq = new MockLaravelRequest('/api/v1/health', $attackerIp);
        $nextCalled2 = false;
        $middleware->handle($cleanReq, function ($req) use (&$nextCalled2) {
            $nextCalled2 = true;
        });

        if ($nextCalled2) {
            throw new \RuntimeException('Subsequent request from banned IP must not reach next handler');
        }
    }
}
