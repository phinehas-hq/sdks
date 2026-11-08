# `phinehas/phinehas-php`

> Active-defense in-process security middleware for Laravel 11, Symfony, and PHP web applications with RFC 8615-compliant wildcard detection and zero-allocation LRU.

[![Latest Version on Packagist](https://img.shields.io/packagist/v/phinehas/phinehas-php.svg)](https://packagist.org/packages/phinehas/phinehas-php)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](../../LICENSE)
[![PHP](https://img.shields.io/badge/PHP-8.2%2B-777BB4.svg)](https://www.php.net/)
[![Compliance Parity](https://img.shields.io/badge/compliance-100%25-brightgreen.svg)](../../compliance/)

---

## 1. Overview & FastCGI Worker Liberation

Traditional web applications log attacks and return standard 404 or verbose 403 error pages. This consumes PHP-FPM worker pool capacity, runs framework bootstrapping, burns database connection pool slots, and leaks headers (e.g. `X-Powered-By: PHP/8.3`) confirming endpoint presence to automated botnets.

`phinehas/phinehas-php` intercepts incoming request paths at the absolute earliest middleware boundary before session state, authentication guards, or Eloquent ORM queries run. It terminates malicious scans with a **zero-byte HTTP `403 Forbidden` (`Content-Length: 0`, `Connection: close`)** and immediately dispatches `fastcgi_finish_request()`, releasing the PHP-FPM worker back to the concurrency pool in microseconds.

---

## 2. Installation

Install via **Composer**:
```bash
composer require phinehas/phinehas-php
```

---

## 3. Laravel 11+ Integration

### Step 1: Prepend Middleware in `bootstrap/app.php`

In Laravel 11, register Phinehas at the very front of the global middleware stack:

```php
// bootstrap/app.php
use Illuminate\Foundation\Application;
use Illuminate\Foundation\Configuration\Middleware;
use Phinehas\Laravel\PhinehasMiddleware;

return Application::configure(basePath: dirname(__DIR__))
    ->withRouting(
        web: __DIR__.'/../routes/web.php',
        api: __DIR__.'/../routes/api.php',
        commands: __DIR__.'/../routes/console.php',
        health: '/up',
    )
    ->withMiddleware(function (Middleware $middleware) {
        // [REQUIRED] Prepend Phinehas to execute before authentication, session, or encryption
        $middleware->prepend(PhinehasMiddleware::class);
    })
    ->create();
```

---

### Step 2: Publish and Customize Configuration (`config/phinehas.php`)

Publish the configuration file via Artisan:
```bash
php artisan vendor:publish --provider="Phinehas\Laravel\PhinehasServiceProvider"
```

```php
<?php
// config/phinehas.php (Required vs Optional Showcase)

return [
    // [OPTIONAL - DEFAULT: 'reject']
    // Enforcement action on detected reconnaissance:
    // - 'reject':    Returns HTTP 403 Forbidden with empty body and Connection: close
    // - 'terminate': Forcefully exits script execution immediately
    // - 'tarpit':    Sleeps for tarpit_delay_ms before terminating
    'action' => env('PHINEHAS_ACTION', 'reject'),

    // [OPTIONAL - DEFAULT: 86400 (24 hours)]
    // Ban duration in seconds. Set to 0 or null for permanent bans.
    'ttl' => (int) env('PHINEHAS_TTL', 86400),

    // [PRODUCTION RECOMMENDED FOR MULTI-SERVER CLUSTERS - DEFAULT: 'memory']
    // 'memory' (in-process LRU cache) or 'redis' (cluster-wide shared state)
    'driver' => env('PHINEHAS_DRIVER', 'memory'),

    // [PRODUCTION RECOMMENDED - DEFAULT: false]
    // Set to true when running behind Cloudflare, AWS ALB, Nginx, or HAProxy
    'proxy' => [
        'trust' => (bool) env('PHINEHAS_PROXY_TRUST', true),
        'header' => env('PHINEHAS_PROXY_HEADER', 'CF-Connecting-IP'),
        'depth' => (int) env('PHINEHAS_PROXY_DEPTH', 0),
    ],

    // [OPTIONAL - DEFAULT: ['127.0.0.1', '::1']]
    // Whitelisted IP addresses exempt from bans and threat evaluation
    'allow_list' => [
        '127.0.0.1',
        '::1',
        '10.0.0.1',
    ],

    // [OPTIONAL - DEFAULT: []]
    // Custom application-specific paths or regex patterns to trap
    'custom_traps' => [
        '/^\/artisan-debug(\/.*)?$/',
        '/^\/telescope\/api\/dump/',
        '/super-secret-backdoor.php',
    ],

    // [OPTIONAL - DEFAULT: false]
    // Set to true to disable default CMS/DB/debugger trap signatures
    'exclude_defaults' => false,

    // [OPTIONAL - DEFAULT: 5000]
    // Delay in milliseconds when action is 'tarpit'
    'tarpit_delay_ms' => 5000,
];
```

---

## 4. Symfony Integration

Register `PhinehasListener` as a high-priority kernel event listener in `config/services.yaml`:

```yaml
# config/services.yaml
services:
    Phinehas\Symfony\PhinehasListener:
        arguments:
            $config:
                # [OPTIONAL - DEFAULT: 'reject']
                action: 'reject'

                # [OPTIONAL - DEFAULT: 86400]
                ttl: 86400

                # [PRODUCTION RECOMMENDED - DEFAULT: false]
                proxy:
                    trust: true
                    header: 'CF-Connecting-IP'

                # [OPTIONAL - DEFAULT: ['127.0.0.1', '::1']]
                allow_list:
                    - '127.0.0.1'
                    - '::1'

                # [OPTIONAL - DEFAULT: []]
                custom_traps:
                    - '/^\/app_dev\.php/'
                    - '/^\/_profiler\/open/'
        tags:
            # High priority (4096) ensures Phinehas executes before routing & firewall
            - { name: kernel.event_listener, event: kernel.request, priority: 4096 }
```

---

## 5. Standalone PHP / PSR-15 Middleware

You can use Phinehas directly in vanilla PHP or any PSR-15 compatible framework (Slim, Mezzio, RoadRunner):

```php
<?php
use Phinehas\Normalizer;
use Phinehas\ThreatEvaluator;
use Phinehas\Store\MemoryStore;

// [REQUIRED] Initialize core components
$evaluator = new ThreatEvaluator();
$store = new MemoryStore(maxCapacity: 25000);

$clientIp = $_SERVER['HTTP_CF_CONNECTING_IP'] ?? $_SERVER['REMOTE_ADDR'] ?? '127.0.0.1';
$rawUri = $_SERVER['REQUEST_URI'] ?? '/';

// 1. Check if IP is already banned
if ($store->isBanned($clientIp)) {
    http_response_code(403);
    header('Connection: close');
    header('Content-Length: 0');
    exit;
}

// 2. Evaluate URI path
$verdict = $evaluator->evaluate($rawUri);
if ($verdict['is_blocked']) {
    $store->ban($clientIp, 86400); // 24-hour ban

    http_response_code(403);
    header('Connection: close');
    header('Content-Length: 0');
    if (function_exists('fastcgi_finish_request')) {
        fastcgi_finish_request();
    }
    exit;
}

// 3. Normal application logic continues below
header('Content-Type: application/json');
echo json_encode(['status' => 'healthy']);
```

---

## 6. Testing Your PHP Application with Phinehas

In PHPUnit or Pest, verify that Phinehas protects your routes while allowing legitimate endpoints:

```php
<?php
namespace Tests\Feature;

use Tests\TestCase;

class PhinehasSecurityTest extends TestCase
{
    /** @test */
    public function legitimate_traffic_passes_through(): void
    {
        $response = $this->getJson('/api/v1/health');
        $response->assertStatus(200);
    }

    /** @test */
    public function rfc_8615_well_known_discovery_is_exempt(): void
    {
        $response = $this->get('/.well-known/security.txt');
        // Passes through Phinehas to 404 (route not defined, but not blocked by security guard)
        $this->assertNotEquals(403, $response->getStatusCode());
    }

    /** @test */
    public function dotfile_reconnaissance_is_blocked(): void
    {
        $response = $this->get('/.env');
        $response->assertStatus(403);
    }

    /** @test */
    public function obfuscated_traversal_is_blocked(): void
    {
        $response = $this->get('//%2e%2e/wp-config.php');
        $response->assertStatus(403);
    }
}
```

---

## 7. Navigation

* [Root SDK Documentation](../../README.md)
* [Shared Compliance Vectors (`compliance/`)](../../compliance/)

---

## 8. License

Licensed under the [Apache-2.0 License](../../LICENSE). Maintained by [Phinehas HQ](https://github.com/phinehas-hq).
