<?php

declare(strict_types=1);

/**
 * Relay link authentication test: builds a router descriptor signed with an
 * RSA identity key and an ed25519 identity key, then checks both the
 * descriptor chain and the CERTS link certificate.
 *
 * Run: php tests/link_auth_test.php
 */

require __DIR__ . '/../autoload.php';

use Torv3\Directory\AuthorityCert;
use Torv3\Directory\RelayIdentity;

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

function edKeypair(): array
{
    $pair = sodium_crypto_sign_seed_keypair(random_bytes(SODIUM_CRYPTO_SIGN_SEEDBYTES));
    if (is_array($pair)) {
        return [$pair['publickey'], $pair['secretkey']];
    }
    if (strlen($pair) >= 96) {
        return [substr($pair, 64), substr($pair, 0, 64)];
    }

    return [substr($pair, 32), $pair];
}

function edCert(int $type, int $expiry, string $certifiedKey, string $signingKey, string $signingSecret, bool $includeSigner): string
{
    $body = chr(1) . chr($type) . pack('N', $expiry) . chr(1) . $certifiedKey;
    if ($includeSigner) {
        $body .= chr(1) . pack('n', 32) . chr(4) . chr(0) . $signingKey;
    } else {
        $body .= chr(0);
    }

    return $body . sodium_crypto_sign_detached($body, $signingSecret);
}

function rsaKeypair(): array
{
    $key = openssl_pkey_new(['private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA]);
    openssl_pkey_export($key, $privatePem);
    $details = openssl_pkey_get_details($key);

    return [$privatePem, $details['key']];
}

[$masterPub, $masterPriv] = edKeypair();
[$linkPub, $linkPriv] = edKeypair();
[$rsaPriv, $rsaPub] = rsaKeypair();
$ntorKey = random_bytes(32);
$fingerprint = AuthorityCert::fingerprintOf($rsaPub);

$expiry = intdiv(time(), 3600) + 1;
$identityCert = edCert(4, $expiry, $linkPub, $masterPub, $masterPriv, true);
$identityPem = "-----BEGIN ED25519 CERT-----\n"
    . chunk_split(base64_encode($identityCert), 64, "\n")
    . "-----END ED25519 CERT-----\n";

$body = "router TestRelay 127.0.0.1 9001 0 0\n"
    . "identity-ed25519\n" . $identityPem
    . 'master-key-ed25519 ' . base64_encode($masterPub) . "\n"
    . "signing-key\n" . $rsaPub . "\n"
    . 'ntor-onion-key ' . rtrim(base64_encode($ntorKey), '=') . "\n";

$edSigned = 'Tor router descriptor signature v1' . $body . 'router-sig-ed25519 ';
$edSignature = sodium_crypto_sign_detached(hash('sha256', $edSigned, true), $linkPriv);
$descriptor = $body . 'router-sig-ed25519 ' . base64_encode($edSignature) . "\n";

$rsaSigned = $descriptor . "router-signature\n";
// Tor signs the raw SHA-1 digest of the descriptor with RSA (no DigestInfo).
if (openssl_private_encrypt(hash('sha1', $rsaSigned, true), $rsaSignature, $rsaPriv, OPENSSL_PKCS1_PADDING) !== true) {
    throw new RuntimeException('Cannot sign test descriptor: ' . openssl_error_string());
}
$descriptor = $rsaSigned
    . "-----BEGIN SIGNATURE-----\n"
    . chunk_split(base64_encode($rsaSignature), 64, "\n")
    . "-----END SIGNATURE-----\n";

$identity = RelayIdentity::fromDescriptor($descriptor, $fingerprint, $masterPub);
check('valid router descriptor is authenticated', $identity['ed25519'] === $masterPub);
check('descriptor returns the RSA identity key', str_contains($identity['rsa'], 'BEGIN'));
check('descriptor exposes the ntor onion key', ($identity['ntor'] ?? null) === $ntorKey);

$tampered = str_replace('router TestRelay', 'router EvilRelay', $descriptor);
$rejected = false;
try {
    RelayIdentity::fromDescriptor($tampered, $fingerprint, $masterPub);
} catch (Throwable $e) {
    $rejected = true;
}
check('tampered router descriptor is rejected', $rejected);

$wrongId = false;
try {
    RelayIdentity::fromDescriptor($descriptor, $fingerprint, random_bytes(32));
} catch (Throwable $e) {
    $wrongId = true;
}
check('descriptor for a different ed25519 identity is rejected', $wrongId);

$wrongFp = false;
try {
    RelayIdentity::fromDescriptor($descriptor, str_repeat('A', 40), $masterPub);
} catch (Throwable $e) {
    $wrongFp = true;
}
check('descriptor for a different RSA fingerprint is rejected', $wrongFp);

// CERTS cell: one type-4 certificate signed by the master identity.
$linkCert = edCert(4, $expiry, $linkPub, $masterPub, $masterPriv, false);
$certsPayload = chr(1) . chr(4) . pack('n', strlen($linkCert)) . $linkCert;
check('link certificate from the authenticated identity is accepted', RelayIdentity::verifyLinkCerts($certsPayload, $masterPub));
check('link certificate from another identity is rejected', !RelayIdentity::verifyLinkCerts($certsPayload, random_bytes(32)));

$badPayload = chr(1) . chr(4) . pack('n', strlen($linkCert)) . strrev($linkCert);
check('tampered link certificate is rejected', !RelayIdentity::verifyLinkCerts($badPayload, $masterPub));

echo $failures === 0 ? "\nAll link authentication checks passed.\n" : "\n{$failures} link check(s) failed.\n";
exit($failures === 0 ? 0 : 1);
