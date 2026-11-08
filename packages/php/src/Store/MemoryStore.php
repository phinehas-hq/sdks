<?php

declare(strict_types=1);

namespace Phinehas\Store;

final class MemoryStore implements BanStoreInterface
{
    private array $cache = [];
    private int $maxCapacity;
    private ?int $defaultTtl;

    public function __construct(int $maxCapacity = 25000, ?int $defaultTtlSeconds = 3600)
    {
        $this->maxCapacity = $maxCapacity > 0 ? $maxCapacity : 25000;
        $this->defaultTtl = $defaultTtlSeconds;
    }

    public function size(): int
    {
        return count($this->cache);
    }

    public function isBanned(string $ip): bool
    {
        if (!array_key_exists($ip, $this->cache)) {
            return false;
        }

        $expiresAt = $this->cache[$ip];
        $now = time();

        if ($expiresAt !== null && $now > $expiresAt) {
            unset($this->cache[$ip]);
            return false;
        }

        // Move to MRU position (end of array)
        $val = $this->cache[$ip];
        unset($this->cache[$ip]);
        $this->cache[$ip] = $val;

        return true;
    }

    public function ban(string $ip, ?int $ttlSeconds = 3600): void
    {
        $effectiveTtl = $ttlSeconds !== null ? $ttlSeconds : $this->defaultTtl;
        $expiresAt = ($effectiveTtl !== null && $effectiveTtl > 0) ? time() + $effectiveTtl : null;

        if (array_key_exists($ip, $this->cache)) {
            unset($this->cache[$ip]);
            $this->cache[$ip] = $expiresAt;
            return;
        }

        // Capacity enforcement: evict oldest entry
        if (count($this->cache) >= $this->maxCapacity) {
            $oldestKey = array_key_first($this->cache);
            if ($oldestKey !== null) {
                unset($this->cache[$oldestKey]);
            }
        }

        $this->cache[$ip] = $expiresAt;
    }

    public function unban(string $ip): void
    {
        unset($this->cache[$ip]);
    }

    public function close(): void
    {
        $this->cache = [];
    }
}
