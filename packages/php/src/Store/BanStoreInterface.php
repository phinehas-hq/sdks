<?php

declare(strict_types=1);

namespace Phinehas\Store;

interface BanStoreInterface
{
    /**
     * Check if an IP address is actively banned.
     */
    public function isBanned(string $ip): bool;

    /**
     * Ban an IP address with optional TTL in seconds. 0 or null denotes permanent ban.
     */
    public function ban(string $ip, ?int $ttlSeconds = 3600): void;

    /**
     * Remove an IP address from the ban store.
     */
    public function unban(string $ip): void;

    /**
     * Optional cleanup hook.
     */
    public function close(): void;
}
