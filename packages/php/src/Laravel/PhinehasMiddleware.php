<?php

declare(strict_types=1);

namespace Phinehas\Laravel;

use Closure;
use DateTimeImmutable;
use DateTimeZone;
use Phinehas\Logger;
use Phinehas\Normalizer;
use Phinehas\Store\BanStoreInterface;
use Phinehas\Store\MemoryStore;
use Phinehas\StrikeEvent;
use Phinehas\ThreatEvaluator;
use Throwable;

final class PhinehasMiddleware
{
    private static ?BanStoreInterface $store = null;
    private ThreatEvaluator $evaluator;
    private Logger $logger;
    private string $action;
    private ?int $ttl;
    private array $allowList;
    private bool $proxyTrust;
    private ?string $proxyHeader;
    private int $proxyDepth;

    public function __construct(?BanStoreInterface $customStore = null)
    {
        $config = function_exists('config') ? (array) config('phinehas', []) : [];

        $this->action = $config['action'] ?? 'reject';
        $this->ttl = isset($config['ttl']) ? (int) $config['ttl'] : 86400;
        $this->allowList = $config['allow_list'] ?? ['127.0.0.1', '::1'];

        $proxy = $config['proxy'] ?? [];
        $this->proxyTrust = (bool) ($proxy['trust'] ?? false);
        $this->proxyHeader = $proxy['header'] ?? null;
        $this->proxyDepth = (int) ($proxy['depth'] ?? 0);

        $customTraps = $config['custom_traps'] ?? [];
        $excludeDefaults = (bool) ($config['exclude_defaults'] ?? false);
        $this->evaluator = new ThreatEvaluator($customTraps, $excludeDefaults);

        $logging = $config['logging'] ?? [];
        $this->logger = new Logger(
            enabled: (bool) ($logging['enabled'] ?? true),
            format: $logging['format'] ?? 'structured'
        );

        if ($customStore !== null) {
            self::$store = $customStore;
        } elseif (self::$store === null) {
            self::$store = new MemoryStore(defaultTtlSeconds: $this->ttl);
        }
    }

    public static function getStore(): BanStoreInterface
    {
        if (self::$store === null) {
            self::$store = new MemoryStore();
        }
        return self::$store;
    }

    private function normalizeIp(string $ip): string
    {
        $cleaned = trim($ip);
        if (str_starts_with($cleaned, '::ffff:')) {
            $cleaned = substr($cleaned, 7);
        }
        return $cleaned;
    }

    private function isIpAllowed(string $ip): bool
    {
        $norm = $this->normalizeIp($ip);
        foreach ($this->allowList as $allowed) {
            $normAllowed = $this->normalizeIp($allowed);
            if ($norm === $normAllowed) {
                return true;
            }
            if (($norm === '127.0.0.1' || $norm === '::1') &&
                ($normAllowed === '127.0.0.1' || $normAllowed === '::1' || $normAllowed === 'localhost')) {
                return true;
            }
        }
        return false;
    }

    private function extractClientIp(mixed $request): string
    {
        $socketIp = '127.0.0.1';
        if (is_object($request) && method_exists($request, 'ip')) {
            $socketIp = (string) $request->ip();
        } elseif (isset($_SERVER['REMOTE_ADDR'])) {
            $socketIp = (string) $_SERVER['REMOTE_ADDR'];
        }

        if (!$this->proxyTrust) {
            return $this->normalizeIp($socketIp);
        }

        // 1. Custom proxy header
        if ($this->proxyHeader !== null && is_object($request) && method_exists($request, 'header')) {
            $customVal = $request->header($this->proxyHeader);
            if (is_string($customVal) && trim($customVal) !== '') {
                return $this->normalizeIp(explode(',', $customVal)[0]);
            }
        }

        // 2. Cloudflare header
        if (is_object($request) && method_exists($request, 'header')) {
            $cf = $request->header('cf-connecting-ip');
            if (is_string($cf) && trim($cf) !== '') {
                return $this->normalizeIp(explode(',', $cf)[0]);
            }
        }

        return $this->normalizeIp($socketIp);
    }

    public function handle(mixed $request, Closure $next): mixed
    {
        try {
            $clientIp = $this->extractClientIp($request);

            // 1. Check AllowList exemption
            if ($this->isIpAllowed($clientIp)) {
                return $next($request);
            }

            $rawPath = '/';
            if (is_object($request)) {
                if (method_exists($request, 'path')) {
                    $rawPath = '/' . ltrim((string) $request->path(), '/');
                } elseif (method_exists($request, 'getRequestUri')) {
                    $rawPath = (string) parse_url((string) $request->getRequestUri(), PHP_URL_PATH);
                }
            }

            // 2. Check if IP is actively banned
            $store = self::getStore();
            if ($store->isBanned($clientIp)) {
                $strike = new StrikeEvent(
                    ip: $clientIp,
                    path: $rawPath,
                    method: is_object($request) && method_exists($request, 'method') ? (string) $request->method() : 'GET',
                    headers: [],
                    ruleMatched: 'explicit_trap',
                    timestamp: (new DateTimeImmutable('now', new DateTimeZone('UTC')))->format(DateTimeImmutable::ATOM)
                );
                $this->logger->logStrike($strike, $this->action, 'memory', $this->ttl);
                return $this->enforceAction();
            }

            // 3. Evaluate Request Path
            $result = $this->evaluator->evaluate($rawPath);
            if ($result['is_blocked']) {
                $store->ban($clientIp, $this->ttl);

                $strike = new StrikeEvent(
                    ip: $clientIp,
                    path: $rawPath,
                    method: is_object($request) && method_exists($request, 'method') ? (string) $request->method() : 'GET',
                    headers: [],
                    ruleMatched: $result['rule_matched'],
                    timestamp: (new DateTimeImmutable('now', new DateTimeZone('UTC')))->format(DateTimeImmutable::ATOM)
                );
                $this->logger->logStrike($strike, $this->action, 'memory', $this->ttl);
                return $this->enforceAction();
            }

            return $next($request);
        } catch (Throwable) {
            // Fail-open: security inspection must never take down host application
            return $next($request);
        }
    }

    private function enforceAction(): mixed
    {
        if (function_exists('abort')) {
            abort(403, '', [
                'Content-Type' => 'text/plain',
                'Content-Length' => '0',
                'Connection' => 'close',
                'X-Phinehas-Verdict' => 'blocked',
            ]);
        }

        // Fallback for standalone/mock testing without Laravel runtime
        if (!headers_sent()) {
            http_response_code(403);
            header('Content-Type: text/plain');
            header('Content-Length: 0');
            header('Connection: close');
            header('X-Phinehas-Verdict: blocked');
        }
        return null;
    }
}
