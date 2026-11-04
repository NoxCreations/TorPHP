<?php

declare(strict_types=1);

/**
 * Tor test vectors for HS key blinding, descriptor IDs and the HSDir ring
 * (src/test/test_hs_common.c: test_blinding_basics, test_hs_indexes).
 */

require __DIR__ . '/../autoload.php';

use Torv3\Onion\OnionV3;
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

$identity = hex2bin('833990B085C1A688C1D4C8B1F6B56AFAF5A2ECA674449E1D704F83765CCB7BC6');
$blinded = OnionV3::blindedPublicKey($identity, 1234, 1440);
expect(
    'blinded public key matches Tor',
    bin2hex($blinded) === '3a50bf210e8f9ee955ae0014f7a6917fb65ebf098a86305abb508d1a7291b6d5',
    bin2hex($blinded)
);
expect(
    'subcredential matches Tor',
    bin2hex(OnionV3::subcredentialFor($identity, $blinded))
        === '635d55907816e8d76398a675a50b1c2f3e36b42a5ca77ba3a0441285161ae07d'
);

$pk = str_repeat("\x42", 32);
expect(
    'hs index (store-at-idx) matches Tor (period 42)',
    bin2hex(OnionV3::storeAtIndex($pk, 1, 42, 1440))
        === '37e5cbbd56a22823714f18f1623ece5983a0d64c78495a8cfab854245e5f9a8a'
);
expect(
    'HSDir index matches Tor (period 42)',
    bin2hex(TorClient::hsdirIndex($pk, str_repeat("\x43", 32), 42, 1440))
        === 'db475361014a09965e7e5e4d4a25b8f8d4b8f16cb1d8a7e95eed50249cc1a2d5'
);

echo $failures === 0 ? "All onion vector checks passed.\n" : "{$failures} onion vector checks failed.\n";
exit($failures === 0 ? 0 : 1);
