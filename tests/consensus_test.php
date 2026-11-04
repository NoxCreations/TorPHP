<?php

declare(strict_types=1);

/**
 * Consensus authentication test: builds five pinned authority certificates and
 * a consensus signed by them, then checks the majority rule and tamper
 * rejection. No network access required.
 *
 * Run: php tests/consensus_test.php
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
for ($i = 0; $i < 5; $i++) {
    [$identityPriv, $identityPub] = rsaKeypair();
    [$signingPriv, $signingPub] = rsaKeypair();
    $identityFp = AuthorityCert::fingerprintOf($identityPub);
    $signingFp = AuthorityCert::fingerprintOf($signingPub);

    $document = makeCertificate($identityPriv, $identityPub, $signingPub, $identityFp);

    $authorities[] = [
        'identityFp' => $identityFp,
        'signingFp' => $signingFp,
        'signingPriv' => $signingPriv,
        'document' => $document,
        'cert' => AuthorityCert::parse($document, [$identityFp]),
    ];
}

check('certificate parses with the pinned fingerprint', $authorities[0]['cert']->fingerprint === $authorities[0]['identityFp']);
check(
    'certificate exposes the signing-key digest',
    hash_equals($authorities[0]['signingFp'], $authorities[0]['cert']->signingKeyDigest)
);

$rejectedPin = false;
try {
    AuthorityCert::parse($authorities[0]['document'], [str_repeat('A', 40)]);
} catch (Throwable $e) {
    $rejectedPin = true;
}
check('certificate from an unpinned authority is rejected', $rejectedPin);

$body = "network-status-version 3 microdesc\n"
    . "vote-status consensus\n"
    . "consensus-method 32\n"
    . "valid-after 2026-11-01 00:00:00\n"
    . "fresh-until 2026-11-01 01:00:00\n"
    . "valid-until 2026-11-01 03:00:00\n"
    . "directory-footer\n";
$signed = $body . 'directory-signature ';

$certs = [];
$consensus = $body;
foreach ($authorities as $authority) {
    $signature = rawSign($signed, $authority['signingPriv'], 'sha256');
    $consensus .= 'directory-signature sha256 ' . $authority['identityFp'] . ' ' . $authority['signingFp'] . "\n"
        . "-----BEGIN SIGNATURE-----\n"
        . chunk_split(base64_encode($signature), 64, "\n")
        . "-----END SIGNATURE-----\n";
    $certs[$authority['identityFp']] = $authority['cert'];
}

check('consensus with a majority of signatures is accepted', DirectoryFetcher::verifyConsensus($consensus, $certs));

// A signature produced by openssl_sign() carries an ASN.1 DigestInfo wrapper
// that Tor never emits; accepting one would mean the wrong scheme is checked.
$digestInfoConsensus = $body;
foreach ($authorities as $authority) {
    openssl_sign($signed, $digestInfoSignature, $authority['signingPriv'], OPENSSL_ALGO_SHA256);
    $digestInfoConsensus .= 'directory-signature sha256 ' . $authority['identityFp'] . ' ' . $authority['signingFp'] . "\n"
        . "-----BEGIN SIGNATURE-----\n"
        . chunk_split(base64_encode($digestInfoSignature), 64, "\n")
        . "-----END SIGNATURE-----\n";
}
check('OpenSSL DigestInfo signatures are rejected', !DirectoryFetcher::verifyConsensus($digestInfoConsensus, $certs));

// Only one signature is below Tor's n_required (9/2 + 1 = 5).
openssl_sign($signed, $singleSig, $authorities[0]['signingPriv'], OPENSSL_ALGO_SHA256);
$single = $body . 'directory-signature sha256 ' . $authorities[0]['identityFp'] . ' ' . $authorities[0]['signingFp'] . "\n"
    . "-----BEGIN SIGNATURE-----\n"
    . chunk_split(base64_encode($singleSig), 64, "\n")
    . "-----END SIGNATURE-----\n";
check('a single signature is not a majority', !DirectoryFetcher::verifyConsensus($single, $certs));

$tampered = str_replace('consensus-method 32', 'consensus-method 33', $consensus);
check('tampered consensus is rejected', !DirectoryFetcher::verifyConsensus($tampered, $certs));

check('unknown authority certificates are rejected', !DirectoryFetcher::verifyConsensus($consensus, []));

$bad = str_replace(
    chunk_split(base64_encode($singleSig), 64, "\n"),
    chunk_split(base64_encode(random_bytes(strlen($singleSig))), 64, "\n"),
    $single
);
check('invalid signature bytes are rejected', !DirectoryFetcher::verifyConsensus($bad, $certs));

/* --------------------------------------------------------------------------
 * ns-flavor consensus: no m-lines, ed25519 identity in the status entry
 * -------------------------------------------------------------------------- */

$nsBody = "network-status-version 3\n"
    . "vote-status consensus\n"
    . "consensus-method 32\n"
    . "valid-after 2026-11-01 00:00:00\n"
    . "fresh-until 2026-11-01 01:00:00\n"
    . "directory-footer\n";
$nsSigned = $nsBody . 'directory-signature ';
$nsConsensus = $nsBody;
foreach ($authorities as $authority) {
    $nsSignature = rawSign($nsSigned, $authority['signingPriv'], 'sha256');
    $nsConsensus .= 'directory-signature sha256 ' . $authority['identityFp'] . ' ' . $authority['signingFp'] . "\n"
        . "-----BEGIN SIGNATURE-----\n"
        . chunk_split(base64_encode($nsSignature), 64, "\n")
        . "-----END SIGNATURE-----\n";
}
check('ns-flavor consensus with a majority of signatures is accepted', DirectoryFetcher::verifyConsensus($nsConsensus, $certs));

$identity = random_bytes(20);
$ed25519 = random_bytes(32);
$statusLine = 'r NSRelay ' . rtrim(strtr(base64_encode($identity), '+/', '-_'), '=') . ' '
    . rtrim(strtr(base64_encode(random_bytes(20)), '+/', '-_'), '=')
    . ' 2026-11-01 00:00:00 192.0.2.10 9001 9030';
$nsDocument = "network-status-version 3\n" . $statusLine . "\n"
    . "s Guard Fast Running\n"
    . "v Tor 0.4.9.15\n"
    . 'id ed25519 ' . base64_encode($ed25519) . "\n"
    . "w Bandwidth=4200\n";

$fetcher = new DirectoryFetcher();
$nsParsed = $fetcher->parseConsensus($nsDocument);
$nsRelay = $nsParsed['relays'][strtoupper(bin2hex($identity))] ?? null;

check('ns consensus is detected as the ns flavor', ($nsParsed['flavor'] ?? '') === 'ns');
check(
    'ns status entry parses address and ports',
    $nsRelay !== null
        && $nsRelay->address === '192.0.2.10'
        && $nsRelay->orPort === 9001
        && $nsRelay->dirPort === 9030
);
check('ns status entry keeps its flags', $nsRelay !== null && $nsRelay->hasFlag('Guard') && $nsRelay->hasFlag('Running'));
check('ns status entry parses the ed25519 identity', $nsRelay !== null && $nsRelay->ed25519Id === $ed25519);
check('ns status entry has no microdescriptor digest', $nsRelay !== null && $nsRelay->microdescDigest === null);

$microDocument = "network-status-version 3 microdesc\n" . $statusLine . "\n"
    . 'm sha256=' . rtrim(base64_encode(hash('sha256', 'm', true)), '=') . "\n"
    . "s Fast Running\n";
$microParsed = $fetcher->parseConsensus($microDocument);
check('microdesc consensus keeps its flavor', ($microParsed['flavor'] ?? '') === 'microdesc');
check(
    'microdesc status entry keeps its digest',
    ($microParsed['relays'][strtoupper(bin2hex($identity))]->microdescDigest ?? null) !== null
);

check(
    'a document without a network-status-version is rejected',
    !DirectoryFetcher::verifyConsensus(str_replace('network-status-version 3', 'network-status-version 9', $nsConsensus), $certs)
);

/* --------------------------------------------------------------------------
 * Consensus method 33+: microdesc "r" lines carry no descriptor digest
 * -------------------------------------------------------------------------- */

$mdIdentity = random_bytes(20);
$mdDigest = rtrim(base64_encode(hash('sha256', 'method37', true)), '=');
$method37Doc = "network-status-version 3 microdesc\n"
    . 'r Method37Relay ' . rtrim(strtr(base64_encode($mdIdentity), '+/', '-_'), '=')
    . " 2038-01-01 00:00:00 192.0.2.20 443 0\n"
    . 'm ' . $mdDigest . "\n"
    . "s Fast Guard HSDir\n"
    . "v Tor 0.4.9.15\n"
    . "w Bandwidth=100\n";
$method37 = $fetcher->parseConsensus($method37Doc);
$method37Relay = $method37['relays'][strtoupper(bin2hex($mdIdentity))] ?? null;

check('method-37 r lines without a descriptor digest are parsed', $method37Relay !== null);
check(
    'method-37 entries keep address, ORPort and DirPort',
    $method37Relay !== null
        && $method37Relay->address === '192.0.2.20'
        && $method37Relay->orPort === 443
        && $method37Relay->dirPort === 0
);
check(
    'the m line supplies the microdesc digest',
    $method37Relay !== null && $method37Relay->microdescDigest === $mdDigest
);

$truncatedEntry = $fetcher->parseConsensus(
    "network-status-version 3 microdesc\nr Broken " . rtrim(strtr(base64_encode(random_bytes(20)), '+/', '-_'), '=') . " 192.0.2.21\ns Fast\n"
);
check('an r line with too few fields is ignored', $truncatedEntry['relays'] === []);

$docA = "onion-key\nntor-onion-key " . rtrim(base64_encode(random_bytes(32)), '=') . "\nid ed25519 " . base64_encode(random_bytes(32)) . "\n";
$docB = "onion-key\nntor-onion-key " . rtrim(base64_encode(random_bytes(32)), '=') . "\nid ed25519 " . base64_encode(random_bytes(32)) . "\n";
$concatenated = $fetcher->parseMicrodescriptors($docA . $docB);
$digestOf = static fn (string $doc): string => rtrim(base64_encode(hash('sha256', $doc, true)), '=');
check(
    'concatenated microdescriptor documents are split without blank lines',
    count($concatenated) === 2
        && isset($concatenated[$digestOf($docA)], $concatenated[$digestOf($docB)])
);


echo $failures === 0 ? "\nAll consensus checks passed.\n" : "\n{$failures} consensus check(s) failed.\n";
exit($failures === 0 ? 0 : 1);
