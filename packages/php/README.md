# `phinehas/phinehas-php`

> Active-defense in-process security middleware for Laravel 11, Symfony, and PHP web applications with RFC 8615-compliant wildcard detection and zero-allocation LRU.

[![Latest Version on Packagist](https://img.shields.io/packagist/v/phinehas/phinehas-php.svg)](https://packagist.org/packages/phinehas/phinehas-php)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![PHP](https://img.shields.io/badge/PHP-8.2%2B-777BB4.svg)](https://www.php.net/)

---

## Overview

Traditional web applications log attacks and return standard 404 or verbose 403 error responses. This burns server worker capacity, consumes database connections, and confirms to automated botnets that an endpoint exists.

`phinehas/phinehas-php` inspects incoming request paths at the earliest middleware boundary. It terminates malicious scans (environment dotfiles, git repositories, database dumps, and CMS admin consoles) immediately with zero-byte 403 drops, starving attacker crawlers of diagnostic data.

---

## Installation

```bash
composer require phinehas/phinehas-php
```

---

## Quick Start (Laravel 11)

In Laravel 11, register the middleware inside `bootstrap/app.php`:

```php
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
        // Register Phinehas at the front of the middleware pipeline
        $middleware->prepend(PhinehasMiddleware::class);
    })->create();
```

---

## Configuration (`config/phinehas.php`)

Publish the configuration file (optional):

```bash
php artisan vendor:publish --provider="Phinehas\Laravel\PhinehasServiceProvider"
```

Configuration shape:

```php
return [
    // Action executed on attack: "reject", "terminate", or "tarpit"
    'action' => env('PHINEHAS_ACTION', 'reject'),

    // Ban duration in seconds (Default: 86400 / 24 hours). 0 or null for permanent.
    'ttl' => env('PHINEHAS_TTL', 86400),

    // Storage driver: "memory" (In-Memory LRU) or "redis"
    'driver' => env('PHINEHAS_DRIVER', 'memory'),

    // IP addresses exempt from bans and honeypots
    'allow_list' => [
        '127.0.0.1',
        '::1',
    ],

    // Reverse proxy header resolution (Cloudflare, AWS ALB)
    'proxy' => [
        'trust' => env('PHINEHAS_PROXY_TRUST', false),
        'header' => env('PHINEHAS_PROXY_HEADER', 'CF-Connecting-IP'),
        'depth' => env('PHINEHAS_PROXY_DEPTH', 0),
    ],

    // Additional custom routes to trap
    'custom_traps' => [
        // '/internal/secret.json',
    ],
];
```

---

## Symfony Integration

In Symfony, register `PhinehasListener` as a request event subscriber in `config/services.yaml`:

```yaml
services:
    Phinehas\Symfony\PhinehasListener:
        tags:
            - { name: kernel.event_listener, event: kernel.request, priority: 256 }
```

---

## Standalone PHP Usage

```php
use Phinehas\Normalizer;
use Phinehas\ThreatEvaluator;
use Phinehas\Store\MemoryStore;

$store = new MemoryStore(maxCapacity: 25000);
$evaluator = new ThreatEvaluator();

$result = $evaluator->evaluate($_SERVER['REQUEST_URI'] ?? '/');
if ($result['is_blocked']) {
    $store->ban($_SERVER['REMOTE_ADDR'] ?? '127.0.0.1', 86400);
    http_response_code(403);
    header('Connection: close');
    header('Content-Length: 0');
    exit;
}
```

---

## License

Apache-2.0. Maintained by [Phinehas HQ](https://github.com/phinehas-hq).
