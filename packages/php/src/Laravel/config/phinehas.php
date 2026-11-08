<?php

return [
    /*
    |--------------------------------------------------------------------------
    | Default Action
    |--------------------------------------------------------------------------
    |
    | Supported: "terminate", "reject", "tarpit"
    | Laravel applications generally use "reject" (abort 403 with empty body).
    |
    */
    'action' => env('PHINEHAS_ACTION', 'reject'),

    /*
    |--------------------------------------------------------------------------
    | Ban Duration (TTL in Seconds)
    |--------------------------------------------------------------------------
    |
    | Duration an attacking IP remains banned. Default: 86400 (24 hours).
    | Set to 0 or null for indefinite bans.
    |
    */
    'ttl' => env('PHINEHAS_TTL', 86400),

    /*
    |--------------------------------------------------------------------------
    | Storage Driver
    |--------------------------------------------------------------------------
    |
    | Supported: "memory", "redis"
    |
    */
    'driver' => env('PHINEHAS_DRIVER', 'memory'),

    /*
    |--------------------------------------------------------------------------
    | IP Allow List
    |--------------------------------------------------------------------------
    |
    | IP addresses exempted from honeypots and threat bans (e.g. localhost).
    |
    */
    'allow_list' => [
        '127.0.0.1',
        '::1',
    ],

    /*
    |--------------------------------------------------------------------------
    | Reverse Proxy Settings
    |--------------------------------------------------------------------------
    |
    | Enable if behind Cloudflare, AWS ALB, or reverse proxies.
    |
    */
    'proxy' => [
        'trust' => env('PHINEHAS_PROXY_TRUST', false),
        'header' => env('PHINEHAS_PROXY_HEADER', 'CF-Connecting-IP'),
        'depth' => env('PHINEHAS_PROXY_DEPTH', 0),
    ],

    /*
    |--------------------------------------------------------------------------
    | Custom Honeypots
    |--------------------------------------------------------------------------
    |
    | Additional application routes to trap.
    |
    */
    'custom_traps' => [
        // '/api/v1/internal_debug',
    ],

    'exclude_defaults' => false,

    /*
    |--------------------------------------------------------------------------
    | Audit Logging
    |--------------------------------------------------------------------------
    |
    | Format: "structured" (JSON to stderr) or "compact"
    |
    */
    'logging' => [
        'enabled' => env('PHINEHAS_LOGGING', true),
        'format' => env('PHINEHAS_LOG_FORMAT', 'structured'),
    ],
];
