<?php

declare(strict_types=1);

/**
 * Shared random value test: the disaster-mode value must match Tor's own
 * test vector (src/test/test_hs_common.c, test_disaster_srv).
 *
 * Run: php tests/srv_test.php
 */

require __DIR__ . '/../autoload.php';

use Torv3\TorClient;

$failures = 0;

function expect(string $name, bool $ok, string $detail = ''): void
{
    global $failures;
    if ($ok) {
        echo "  PASS  {$name}\n";
    } else {
        $failures++;
        echo "  FAIL  {$name}" . ($detail !== '' ? " ({$detail})" : '') . "\n";
    }
}

$expected = 'f8a4948707653837fa44abb5bbc75a12f6f101e7f8faf699b9715f4965d3507d';
$srv = TorClient::disasterSharedRandom(1, 1440);
expect('disaster SRV matches the Tor test vector', bin2hex($srv) === $expected, bin2hex($srv));
expect('disaster SRV is 32 bytes', strlen($srv) === 32, (string) strlen($srv));
expect(
    'different periods give different values',
    TorClient::disasterSharedRandom(1, 1440) !== TorClient::disasterSharedRandom(2, 1440)
);
expect(
    'period length is part of the hash',
    TorClient::disasterSharedRandom(1, 1440) !== TorClient::disasterSharedRandom(1, 120)
);

echo $failures === 0 ? "All shared-random checks passed.\n" : "{$failures} shared-random checks failed.\n";
exit($failures === 0 ? 0 : 1);
