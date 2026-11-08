<?php

declare(strict_types=1);

namespace Phinehas\Symfony;

use Phinehas\Normalizer;
use Phinehas\Store\BanStoreInterface;
use Phinehas\Store\MemoryStore;
use Phinehas\ThreatEvaluator;
use Throwable;

final class PhinehasListener
{
    private ThreatEvaluator $evaluator;
    private BanStoreInterface $store;
    private array $allowList;
    private int $ttl;

    public function __construct(
        ?BanStoreInterface $store = null,
        array $allowList = ['127.0.0.1', '::1'],
        int $ttl = 86400,
        array $customTraps = []
    ) {
        $this->store = $store ?? new MemoryStore(defaultTtlSeconds: $ttl);
        $this->allowList = $allowList;
        $this->ttl = $ttl;
        $this->evaluator = new ThreatEvaluator($customTraps);
    }

    public function onKernelRequest(mixed $event): void
    {
        try {
            if (!is_object($event) || !method_exists($event, 'getRequest')) {
                return;
            }

            $request = $event->getRequest();
            $clientIp = method_exists($request, 'getClientIp') ? (string) $request->getClientIp() : '127.0.0.1';

            if (in_array($clientIp, $this->allowList, true)) {
                return;
            }

            $rawPath = method_exists($request, 'getPathInfo') ? (string) $request->getPathInfo() : '/';

            if ($this->store->isBanned($clientIp)) {
                $this->blockEvent($event);
                return;
            }

            $result = $this->evaluator->evaluate($rawPath);
            if ($result['is_blocked']) {
                $this->store->ban($clientIp, $this->ttl);
                $this->blockEvent($event);
            }
        } catch (Throwable) {
            // Fail-open
        }
    }

    private function blockEvent(mixed $event): void
    {
        // If Symfony Response class is available, set 403 Response on event
        if (class_exists('\\Symfony\\Component\\HttpFoundation\\Response') && method_exists($event, 'setResponse')) {
            $response = new \Symfony\Component\HttpFoundation\Response('', 403, [
                'Content-Type' => 'text/plain',
                'Content-Length' => '0',
                'Connection' => 'close',
                'X-Phinehas-Verdict' => 'blocked',
            ]);
            $event->setResponse($response);
        }
    }
}
