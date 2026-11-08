<?php

declare(strict_types=1);

namespace Phinehas\Store;

use Throwable;

final class RedisStore implements BanStoreInterface
{
    private mixed $client;
    private string $keyPrefix;
    private ?int $defaultTtl;
    private float $l1TtlSeconds;
    private array $l1Cache = [];

    public function __construct(
        mixed $client,
        string $keyPrefix = 'phinehas:ban:',
        ?int $defaultTtlSeconds = 3600,
        float $l1TtlSeconds = 5.0
    ) {
        $this->client = $client;
        $this->keyPrefix = $keyPrefix;
        $this->defaultTtl = $defaultTtlSeconds;
        $this->l1TtlSeconds = $l1TtlSeconds;
    }

    private function getKey(string $ip): string
    {
        return $this->keyPrefix . $ip;
    }

    public function isBanned(string $ip): bool
    {
        $now = microtime(true);

        if (isset($this->l1Cache[$ip]) && $now < $this->l1Cache[$ip]['expiresAt']) {
            return $this->l1Cache[$ip]['isBanned'];
        }

        try {
            $key = $this->getKey($ip);
            $res = $this->client->get($key);
            $isBanned = ($res !== false && $res !== null);

            $this->l1Cache[$ip] = [
                'isBanned' => $isBanned,
                'expiresAt' => $now + $this->l1TtlSeconds,
            ];

            return $isBanned;
        } catch (Throwable) {
            // Fail-open
            return false;
        }
    }

    public function ban(string $ip, ?int $ttlSeconds = 3600): void
    {
        $effectiveTtl = $ttlSeconds !== null ? $ttlSeconds : $this->defaultTtl;
        $key = $this->getKey($ip);

        try {
            if ($effectiveTtl !== null && $effectiveTtl > 0) {
                $this->client->setex($key, $effectiveTtl, '1');
            } else {
                $this->client->set($key, '1');
            }

            $this->l1Cache[$ip] = [
                'isBanned' => true,
                'expiresAt' => microtime(true) + $this->l1TtlSeconds,
            ];
        } catch (Throwable) {
            // Fail-open
        }
    }

    public function unban(string $ip): void
    {
        $key = $this->getKey($ip);
        unset($this->l1Cache[$ip]);

        try {
            $this->client->del($key);
        } catch (Throwable) {
            // Fail-open
        }
    }

    public function close(): void
    {
        $this->l1Cache = [];
    }
}
