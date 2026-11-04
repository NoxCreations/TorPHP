<?php

declare(strict_types=1);

/**
 * Consensus cache test: writes a verified consensus, certificates and
 * microdescriptors through the cache, then proves that a load re-verifies the
 * signatures, rebuilds the relay keys, and rejects a tampered cache.
 *
 * Run: php tests/cache_test.php
 */

require __DIR__ . '/../autoload.php';

use Torv3\Directory\AuthorityCert;
use Torv3\Directory\DirectoryFetcher;

$failures = 0;

function check(string $name, bool $ok, string $detail = ''): void
{
    global $failures;
    if ($ok) {
        echo "  PASS  {$name}\n";
    } else {
        $failures++;
        echo "  FAIL  {$name}" . ($detail !== '' ? " ({$detail})" : '') . "\n";
    }
}

/**
 * Sign like Tor: RSA over the raw SHA digest, without DigestInfo.
 */
function rawSign(string $data, string $privatePem, string $algorithm): string
{
    if (openssl_private_encrypt(hash($algorithm, $data, true), $signature, $privatePem, OPENSSL_PKCS1_PADDING) !== true) {
        throw new RuntimeException('Cannot sign test data: ' . openssl_error_string());
    }

    return $signature;
}

function rsaKeypair(): array
{
    $key = openssl_pkey_new(['private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA]);
    if ($key === false) {
        throw new RuntimeException('Cannot generate RSA key: ' . openssl_error_string());
    }
    openssl_pkey_export($key, $privatePem);
    $details = openssl_pkey_get_details($key);

    return [$privatePem, $details['key']];
}

function makeCertificate(string $identityPriv, string $identityPub, string $signingPub, string $identityFp): string
{
    $cert = "dir-key-certificate-version 3\n"
        . "dir-address 127.0.0.1:9030\n"
        . "fingerprint {$identityFp}\n"
        . "dir-identity-key\n{$identityPub}\n"
        . "dir-key-published 2026-01-01 00:00:00\n"
        . "dir-key-expires 2030-01-01 00:00:00\n"
        . "dir-signing-key\n{$signingPub}\n"
        . "dir-key-certification\n";

    $signature = rawSign($cert, $identityPriv, 'sha1');

    return $cert . "-----BEGIN SIGNATURE-----\n"
        . chunk_split(base64_encode($signature), 64, "\n")
        . "-----END SIGNATURE-----\n";
}

$authorities = [];
$certs = [];
$documents = [];
for ($i = 0; $i < 5; $i++) {
    [$identityPriv, $identityPub] = rsaKeypair();
    [$signingPriv, $signingPub] = rsaKeypair();
    $identityFp = AuthorityCert::fingerprintOf($identityPub);
    $document = makeCertificate($identityPriv, $identityPub, $signingPub, $identityFp);
    $authorities[] = [
        'identityFp' => $identityFp,
        'signingFp' => AuthorityCert::fingerprintOf($signingPub),
        'signingPriv' => $signingPriv,
    ];
    $certs[$identityFp] = AuthorityCert::parse($document, [$identityFp]);
    $documents[$identityFp] = $document;
}

$now = time();
$validAfter = $now - 600;
$freshUntil = $now + 1800;
$srv = random_bytes(32);
$previousSrv = random_bytes(32);
$ed25519 = random_bytes(32);
$ntor = random_bytes(32);

$microdescriptor = 'ntor-onion-key ' . rtrim(base64_encode($ntor), '=')
    . "\nid ed25519 " . rtrim(base64_encode($ed25519), '=') . "\n";
$digest = rtrim(base64_encode(hash('sha256', $microdescriptor, true)), '=');
$identity = rtrim(base64_encode(random_bytes(20)), '=');

$body = "network-status-version 3 microdesc\n"
    . "vote-status consensus\n"
    . "consensus-method 32\n"
    . 'valid-after ' . gmdate('Y-m-d H:i:s', $validAfter) . "\n"
    . 'fresh-until ' . gmdate('Y-m-d H:i:s', $freshUntil) . "\n"
    . 'valid-until ' . gmdate('Y-m-d H:i:s', $now + 3600) . "\n"
    . "r CacheRelay {$identity} {$digest} " . gmdate('Y-m-d', $now) . ' ' . gmdate('H:i:s', $now) . " 127.0.0.1 9001 0\n"
    . "m {$digest}\n"
    . "s Fast Running Valid\n"
    . "v Tor 0.4.9.15\n"
    . "w Bandwidth=1000\n"
    . "params hsdir-interval=1440 hsdir_n_replicas=2 hsdir_spread_fetch=3\n"
    . 'shared-rand-current-value 1 ' . base64_encode($srv) . "\n"
    . 'shared-rand-previous-value 1 ' . base64_encode($previousSrv) . "\n"
    . "directory-footer\n";

$signed = $body . 'directory-signature ';
$consensus = $body;
foreach ($authorities as $authority) {
    $signature = rawSign($signed, $authority['signingPriv'], 'sha256');
    $consensus .= 'directory-signature sha256 ' . $authority['identityFp'] . ' ' . $authority['signingFp'] . "\n"
        . "-----BEGIN SIGNATURE-----\n"
        . chunk_split(base64_encode($signature), 64, "\n")
        . "-----END SIGNATURE-----\n";
}

check('fixture consensus verifies before caching', DirectoryFetcher::verifyConsensus($consensus, $certs));

$cacheFile = sys_get_temp_dir() . '/torv3-cache-test-' . bin2hex(random_bytes(6)) . '.json';
$fetcher = new DirectoryFetcher($cacheFile, array_keys($certs));
$write = new ReflectionMethod($fetcher, 'writeCache');
$read = new ReflectionMethod($fetcher, 'readCache');

$write->invoke($fetcher, [
    'relays' => [],
    'validAfter' => $validAfter,
    'freshUntil' => $freshUntil,
    'params' => ['hsdir-interval' => '1440'],
    'sharedRandom' => $srv,
    'sharedRandomPrevious' => $previousSrv,
    'consensusRaw' => $consensus,
    'certs' => $documents,
    'microdescsRaw' => $microdescriptor,
]);

$cached = $read->invoke($fetcher, 3600);
check('valid cached consensus is re-verified and reloaded', is_array($cached) && count($cached['relays']) === 1);
if (is_array($cached)) {
    $relay = reset($cached['relays']);
    check('cached relay address is parsed from the r-line', $relay->address === '127.0.0.1' && $relay->orPort === 9001);
    check('cached microdescriptor keys are restored', $relay->ntorOnionKey !== null && $relay->ed25519Id !== null);
    check('cached shared random values survive the round trip', $cached['sharedRandom'] === $srv && $cached['sharedRandomPrevious'] === $previousSrv);
}

$magic = "TORV3CACHE\n";
$storedBlob = (string) file_get_contents($cacheFile);
check('cache payload is compressed', str_starts_with($storedBlob, $magic));

$stored = json_decode((string) gzdecode(substr($storedBlob, strlen($magic))), true);
check('cache payload decodes to a document map', is_array($stored));

if (is_array($stored)) {
    $tamperedConsensus = str_replace('CacheRelay', 'EvilRelay', (string) base64_decode((string) $stored['consensus'], true));
    $stored['consensus'] = base64_encode($tamperedConsensus);
    file_put_contents($cacheFile, $magic . gzencode((string) json_encode($stored), 6));
    check('tampered cached consensus is rejected', $read->invoke($fetcher, 3600) === null);

    $stored['consensus'] = base64_encode($consensus);
    $stored['certs'] = [base64_encode($documents[array_key_first($documents)])];
    file_put_contents($cacheFile, $magic . gzencode((string) json_encode($stored), 6));
    check('cached consensus without a certificate majority is rejected', $read->invoke($fetcher, 3600) === null);
}

@unlink($cacheFile);

echo $failures === 0 ? "\nAll cache checks passed.\n" : "\n{$failures} cache check(s) failed.\n";
exit($failures === 0 ? 0 : 1);
