<?php

declare(strict_types=1);

namespace Phinehas\Tests;

use Phinehas\Store\MemoryStore;

final class MemoryStoreTest
{
    public function testLRUEvictionAndCapacity(): void
    {
        $store = new MemoryStore(maxCapacity: 3, defaultTtlSeconds: 3600);

        $store->ban('1.1.1.1');
        $store->ban('2.2.2.2');
        $store->ban('3.3.3.3');

        if ($store->size() !== 3) {
            throw new \RuntimeException("Expected size 3, got {$store->size()}");
        }

        if (!$store->isBanned('1.1.1.1') || !$store->isBanned('2.2.2.2') || !$store->isBanned('3.3.3.3')) {
            throw new \RuntimeException("All 3 entries must be banned");
        }

        // Access 1.1.1.1 to move to MRU, making 2.2.2.2 LRU
        $store->isBanned('1.1.1.1');

        // Add 4th entry -> evicts 2.2.2.2
        $store->ban('4.4.4.4');

        if ($store->size() !== 3) {
            throw new \RuntimeException("Expected size 3 after eviction, got {$store->size()}");
        }

        if ($store->isBanned('2.2.2.2')) {
            throw new \RuntimeException("Expected 2.2.2.2 to be evicted");
        }

        if (!$store->isBanned('1.1.1.1') || !$store->isBanned('4.4.4.4')) {
            throw new \RuntimeException("Entries 1.1.1.1 and 4.4.4.4 must remain");
        }

        // Unban
        $store->unban('4.4.4.4');
        if ($store->isBanned('4.4.4.4')) {
            throw new \RuntimeException("Expected 4.4.4.4 to be unbanned");
        }
        if ($store->size() !== 2) {
            throw new \RuntimeException("Expected size 2, got {$store->size()}");
        }

        $store->close();
        if ($store->size() !== 0) {
            throw new \RuntimeException("Expected size 0 after close");
        }
    }

    public function testTTLExpiration(): void
    {
        $store = new MemoryStore(maxCapacity: 10, defaultTtlSeconds: 1);

        $store->ban('10.0.0.1', 1);
        if (!$store->isBanned('10.0.0.1')) {
            throw new \RuntimeException("Expected 10.0.0.1 to be banned initially");
        }

        // Permanent ban (ttl: 0)
        $store->ban('10.0.0.2', 0);
        if (!$store->isBanned('10.0.0.2')) {
            throw new \RuntimeException("Expected 10.0.0.2 to be permanently banned");
        }
    }
}
