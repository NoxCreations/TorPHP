<?php

declare(strict_types=1);

namespace Torv3\Crypto;

/**
 * Tor-style RSA signature verification.
 *
 * Tor hashes the signed bytes itself and RSA-encrypts that raw digest
 * (crypto_pk_private_sign_digest -> crypto_pk_private_sign in
 * lib/crypt_ops/crypto_rsa.c). There is no ASN.1 DigestInfo wrapper, so
 * openssl_verify() rejects every genuine authority, consensus and router
 * descriptor signature. Verify by decrypting with the public key and comparing
 * the recovered block to our own digest instead.
 */
final class RsaSignature
{
    /** @var string[] Digest lengths accepted by Tor's signature formats. */
    private const ALGORITHMS = ['sha1', 'sha256'];

    public static function verify(
        string $data,
        string $signature,
        string $publicKeyPem,
        string $hashAlgorithm
    ): bool {
        if (!in_array($hashAlgorithm, self::ALGORITHMS, true)) {
            return false;
        }

        $key = openssl_pkey_get_public($publicKeyPem);
        if ($key === false) {
            return false;
        }

        $recovered = '';
        if (openssl_public_decrypt($signature, $recovered, $key, OPENSSL_PKCS1_PADDING) !== true) {
            return false;
        }

        return hash_equals(hash($hashAlgorithm, $data, true), $recovered);
    }
}
