<?php

declare(strict_types=1);

namespace Phinehas;

use Throwable;

final class Logger
{
    private bool $enabled;
    private string $format;
    /** @var callable|null */
    private $onStrike;

    public function __construct(
        bool $enabled = true,
        string $format = 'structured',
        ?callable $onStrike = null
    ) {
        $this->enabled = $enabled;
        $this->format = $format;
        $this->onStrike = $onStrike;
    }

    public function logStrike(
        StrikeEvent $strike,
        string $action,
        string $banStoreName,
        ?int $banTtlSeconds,
        ?string $userAgent = null,
        ?string $host = null
    ): void {
        if ($this->onStrike !== null) {
            try {
                ($this->onStrike)($strike);
            } catch (Throwable) {
                // Suppress user callback errors to preserve fail-open safety
            }
        }

        if (!$this->enabled) {
            return;
        }

        if ($this->format === 'compact') {
            $actionLabel = $action === 'terminate' ? 'Severed' : 'Blocked';
            fwrite(STDERR, "[PHINEHAS STRIKE] {$actionLabel} {$strike->ip} accessing {$strike->path}\n");
            return;
        }

        $actionDesc = match ($action) {
            'terminate' => 'TCP_SOCKET_TERMINATED',
            'reject' => 'HTTP_403_REJECTED',
            'tarpit' => 'TARPIT_ENFORCED',
            default => 'BLOCKED',
        };

        $structured = [
            'timestamp' => $strike->timestamp,
            'level' => 'WARN',
            'event' => 'PHINEHAS_SPEAR_STRIKE',
            'actor' => [
                'ip' => $strike->ip,
                'user_agent' => $userAgent ?? ($strike->headers['user-agent'] ?? 'unknown'),
            ],
            'target' => [
                'path' => $strike->path,
                'method' => $strike->method,
                'host' => $host ?? ($strike->headers['host'] ?? 'unknown'),
            ],
            'verdict' => [
                'rule_matched' => $strike->ruleMatched,
                'action_taken' => $actionDesc,
                'ban_store' => $banStoreName,
                'ban_ttl_seconds' => $banTtlSeconds,
            ],
        ];

        fwrite(STDERR, (string) json_encode($structured) . "\n");
    }
}
