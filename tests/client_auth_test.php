<?php

declare(strict_types=1);

/**
 * Client authorization test: builds the first descriptor layer an authorized
 * service would serve, derives the descriptor cookie the way rend-spec-v3
 * §2.5.1.2 prescribes, and checks parsing, selection and rejection paths.
 *
 * Run: php tests/client_auth_test.php
 */

require __DIR__ . '/../autoload.php';

use Torv3\Crypto\Keccak;
use Torv3\Onion\OnionV3;
use Torv3\TorOnionException;

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

function randomOnion(): OnionV3
{
    for ($attempt = 0; $attempt < 20; $attempt++) {
        $pair = sodium_crypto_sign_seed_keypair(random_bytes(32));
        foreach ([substr($pair, 0, 32), substr($pair, 32, 32)] as $publicKey) {
            try {
                return new OnionV3(OnionV3::encodeAddress($publicKey));
            } catch (TorOnionException) {
                continue;
            }
        }
    }

    throw new RuntimeException('Cannot generate a valid onion address');
}

$onion = randomOnion();

$clientSecret = random_bytes(32);
$clientPublic = sodium_crypto_scalarmult_base($clientSecret);
$ephemeralSecret = random_bytes(32);
$ephemeralPublic = sodium_crypto_scalarmult_base($ephemeralSecret);

$shared = sodium_crypto_scalarmult($ephemeralSecret, $clientPublic);
$keys = Keccak::shake256($onion->subcredential() . $shared, 40);
$clientId = substr($keys, 0, 8);
$cookieKey = substr($keys, 8, 32);

$cookie = random_bytes(16);
$iv = random_bytes(16);
$encryptedCookie = openssl_encrypt($cookie, 'aes-256-ctr', $cookieKey, OPENSSL_RAW_DATA, $iv);
if ($encryptedCookie === false) {
    fwrite(STDERR, "cookie encryption failed\n");
    exit(1);
}

$firstLayer = "desc-auth-type x25519\n"
    . 'desc-auth-ephemeral-key ' . base64_encode($ephemeralPublic) . "\n"
    . 'auth-client ' . base64_encode(str_repeat("\x00", 8)) . ' ' . base64_encode(random_bytes(16)) . ' '
    . base64_encode(random_bytes(16)) . "\n"
    . 'auth-client ' . base64_encode($clientId) . ' ' . base64_encode($iv) . ' ' . base64_encode($encryptedCookie) . "\n"
    . "encrypted\n";

$onion->setClientAuthKey($clientSecret);
check('an authorized client derives its descriptor cookie', $onion->clientDescriptorCookie($firstLayer) === $cookie);

$onion->setClientAuthKey(base64_encode($clientSecret));
check('base64 client keys are accepted', $onion->clientDescriptorCookie($firstLayer) === $cookie);

$wrong = randomOnion();
$wrong->setClientAuthKey(random_bytes(32));
check('an unrelated key finds no matching auth-client entry', $wrong->clientDescriptorCookie($firstLayer) === null);

$plaintext = randomOnion();
$plaintext->setClientAuthKey(random_bytes(32));
check('a service without auth fields yields no cookie', $plaintext->clientDescriptorCookie("encrypted\n") === null);

$badType = false;
try {
    $onion->clientDescriptorCookie("desc-auth-type ed25519\n");
} catch (TorOnionException) {
    $badType = true;
}
check('an unsupported auth type is rejected', $badType);

$badKey = false;
try {
    $onion->setClientAuthKey('too-short');
} catch (TorOnionException) {
    $badKey = true;
}
check('malformed client keys are rejected', $badKey);

$required = true;
try {
    $onion->clientDescriptorCookie("desc-auth-type x25519\n");
} catch (TorOnionException) {
    $required = false;
}
check('a missing ephemeral key is rejected', !$required);

echo $failures === 0 ? "\nAll client authorization checks passed.\n" : "\n{$failures} client authorization check(s) failed.\n";
exit($failures === 0 ? 0 : 1);
