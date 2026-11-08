<?php

declare(strict_types=1);

namespace Phinehas;

final class Traps
{
    /**
     * Default list of non-dot honeypot threat signatures.
     */
    public const DEFAULT_EXPLICIT_TRAPS = [
        // CMS & Common Admin Consoles
        '/wp-login.php',
        '/wp-admin',
        '/xmlrpc.php',
        '/wp-config.php',
        '/administrator',
        '/user/login',

        // Database Management Consoles
        '/phpmyadmin',
        '/pma',
        '/adminer.php',
        '/mysql',
        '/dbadmin',

        // Framework Debuggers & Sensitive Endpoints
        '/_ignition/execute-solution',
        '/__debug__',
        '/actuator',
        '/actuator/env',
        '/actuator/health',
        '/telescope',
        '/elmah.axd',

        // Sensitive File Dumps & Archives
        '/dump.sql',
        '/backup.sql',
        '/database.sql',
        '/db.sqlite3',
        '/backup.tar.gz',
        '/backup.zip',
    ];

    /**
     * RFC 8615-compliant hidden dotfile regex with negative lookahead.
     * Safely permits .well-known RFC discovery routes while severing dotfiles.
     */
    public const RFC8615_PATTERN = '/^\/\.(?!well-known(\/|$))[a-zA-Z0-9_\-\.]+/';
}
