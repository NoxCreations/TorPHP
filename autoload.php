<?php

declare(strict_types=1);

/**
 * PSR-4 autoloader for the Torv3\ namespace.
 *
 * Required PHP extensions: openssl, sodium, gmp, hash (always built in), zlib.
 */
spl_autoload_register(static function (string $class): void {
    $prefix = 'Torv3\\';
    $prefixLen = strlen($prefix);

    if (strncmp($class, $prefix, $prefixLen) !== 0) {
        return;
    }

    $relative = substr($class, $prefixLen);
    if ($relative === '' || $relative === false) {
        return;
    }

    $path = __DIR__ . '/src/' . str_replace('\\', '/', $relative) . '.php';
    if (is_file($path)) {
        require $path;

        return;
    }

    // The exception hierarchy lives in a single file (src/TorException.php).
    if (str_starts_with($relative, 'Tor') && str_ends_with($relative, 'Exception')) {
        require __DIR__ . '/src/TorException.php';
    }
});
