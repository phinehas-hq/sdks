<?php

declare(strict_types=1);

namespace Phinehas;

final readonly class StrikeEvent
{
    public function __construct(
        public string $ip,
        public string $path,
        public string $method,
        public array $headers,
        public string $ruleMatched,
        public string $timestamp
    ) {}

    public function toArray(): array
    {
        return [
            'ip' => $this->ip,
            'path' => $this->path,
            'method' => $this->method,
            'headers' => $this->headers,
            'ruleMatched' => $this->ruleMatched,
            'timestamp' => $this->timestamp,
        ];
    }
}
