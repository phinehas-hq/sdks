<?php

declare(strict_types=1);

namespace Phinehas\Laravel;

/**
 * Phinehas Service Provider for Laravel Auto-Discovery.
 */
class PhinehasServiceProvider
{
    public function boot(): void
    {
        // Publishes config/phinehas.php to Laravel's config directory
        $configPath = __DIR__ . '/config/phinehas.php';
        if (function_exists('config_path')) {
            $target = config_path('phinehas.php');
            if (!file_exists($target)) {
                @copy($configPath, $target);
            }
        }
    }

    public function register(): void
    {
        // Merges default configuration
        $configPath = __DIR__ . '/config/phinehas.php';
        if (function_exists('config')) {
            $default = include $configPath;
            $current = config('phinehas') ?? [];
            config(['phinehas' => array_merge($default, (array) $current)]);
        }
    }
}
