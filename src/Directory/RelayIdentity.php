<?php

declare(strict_types=1);

namespace Torv3\Directory;

use Torv3\Crypto\RsaSignature;
use Torv3\Onion\OnionV3;
use Torv3\TorNetworkException;

/**
 * Authentication of a relay's identity material.
 *
 * A router descriptor is signed twice: with the relay's RSA identity key
 * ("router-signature") and with its ed25519 identity key
 * ("router-sig-ed25519"). Verifying both against the fingerprint and ed25519
 * identity from the authenticated consensus binds the two keys together.
 *
 * The link's CERTS cell is then checked for a certificate signed by that
 * ed25519 identity, which authenticates the ORPort connection.
 */
final class RelayIdentity
{
    public const CERT_TYPE_ID_SIGNING = 0x04;

    private const ED_DESC_PREFIX = 'Tor router descriptor signature v1';

    /**
     * Verify a router descriptor and return its authenticated keys.
     *
     * The ntor onion key is returned here because ns-flavor consensuses do not
     * carry one; it is covered by both descriptor signatures above.
     *
     * @return array{rsa: string, ed25519: string, ntor: ?string}
     */
    public static function fromDescriptor(
        string $descriptor,
        string $expectedFingerprint,
        ?string $expectedEd25519Id
    ): array {
        if (preg_match('/^router \S+ \S+ \d+/', $descriptor) !== 1) {
            throw new TorNetworkException('Not a router descriptor');
        }

        if (preg_match('/\nsigning-key\s*\r?\n(-----BEGIN [A-Z0-9 ]+-----.*?-----END [A-Z0-9 ]+-----)/s', $descriptor, $keyMatch) !== 1) {
            throw new TorNetworkException('Router descriptor has no signing key');
        }
        $rsaPem = $keyMatch[1];

        if (!hash_equals(strtoupper($expectedFingerprint), AuthorityCert::fingerprintOf($rsaPem))) {
            throw new TorNetworkException('Router descriptor identity key does not match the consensus fingerprint');
        }

        if (preg_match('/\nrouter-signature\s*\r?\n-----BEGIN SIGNATURE-----\s*(.*?)-----END SIGNATURE-----/s', $descriptor, $sigMatch) !== 1) {
            throw new TorNetworkException('Router descriptor has no signature');
        }
        $rsaSignature = base64_decode(preg_replace('/\s+/', '', $sigMatch[1]) ?? '', true);
        if ($rsaSignature === false || $rsaSignature === '') {
            throw new TorNetworkException('Malformed router descriptor signature');
        }

        $rsaMarker = "\nrouter-signature\n";
        $rsaEnd = strpos($descriptor, $rsaMarker);
        if ($rsaEnd === false) {
            throw new TorNetworkException('Malformed router descriptor signature marker');
        }
        $rsaSigned = substr($descriptor, 0, $rsaEnd + strlen($rsaMarker));

        if (!RsaSignature::verify($rsaSigned, $rsaSignature, $rsaPem, 'sha1')) {
            throw new TorNetworkException('Router descriptor RSA signature is invalid');
        }

        if (preg_match('/\nidentity-ed25519\s*\r?\n(-----BEGIN ED25519 CERT-----.*?-----END ED25519 CERT-----)/s', $descriptor, $certMatch) !== 1) {
            throw new TorNetworkException('Router descriptor has no ed25519 identity certificate');
        }
        $identityCert = OnionV3::parseEd25519Cert($certMatch[1]);
        if ($identityCert['expires'] < time()) {
            throw new TorNetworkException('Router descriptor ed25519 certificate has expired');
        }

        $signer = $identityCert['extensions'][self::CERT_TYPE_ID_SIGNING] ?? $identityCert['key'];
        if (!self::ed25519Verify($identityCert['signature'], substr($identityCert['raw'], 0, -64), $signer)) {
            throw new TorNetworkException('Router descriptor ed25519 certificate signature is invalid');
        }

        // The certificate's own key is the descriptor signing key; the
        // master identity key is the type-4 signer extension (tor's
        // ed25519 identity cert layout for router descriptors).
        $masterKey = $identityCert['extensions'][self::CERT_TYPE_ID_SIGNING] ?? $identityCert['key'];
        if ($expectedEd25519Id !== null && !hash_equals($expectedEd25519Id, $masterKey)) {
            throw new TorNetworkException('Router descriptor ed25519 identity does not match the consensus');
        }

        if (preg_match('/^master-key-ed25519 ([A-Za-z0-9+\/=]+)$/m', $descriptor, $masterMatch) === 1) {
            $declared = base64_decode($masterMatch[1] . str_repeat('=', (4 - strlen($masterMatch[1]) % 4) % 4), true);
            if ($declared === false || !hash_equals($masterKey, $declared)) {
                throw new TorNetworkException('Router descriptor master-key-ed25519 does not match its certificate');
            }
        }

        if (preg_match('/\nrouter-sig-ed25519 ([A-Za-z0-9+\/=]+)/', $descriptor, $edSigMatch) !== 1) {
            throw new TorNetworkException('Router descriptor has no ed25519 signature');
        }
        $edSignature = base64_decode($edSigMatch[1] . str_repeat('=', (4 - strlen($edSigMatch[1]) % 4) % 4), true);
        if ($edSignature === false || strlen($edSignature) !== 64) {
            throw new TorNetworkException('Malformed router descriptor ed25519 signature');
        }

        $edMarker = "\nrouter-sig-ed25519 ";
        $edEnd = strpos($descriptor, $edMarker);
        if ($edEnd === false) {
            throw new TorNetworkException('Malformed router descriptor ed25519 signature marker');
        }
        $edSigned = self::ED_DESC_PREFIX . substr($descriptor, 0, $edEnd + strlen($edMarker));
        $edDigest = hash('sha256', $edSigned, true);

        // The signature is over the 32-byte SHA-256 digest, made with the
        // signing key certified by identity-ed25519 (tor's router.c signs the
        // digest with signing_keypair; routerparse verifies with signed_key).
        if (!self::ed25519Verify($edSignature, $edDigest, $identityCert['key'])) {
            throw new TorNetworkException('Router descriptor ed25519 signature is invalid');
        }

        $ntor = null;
        if (preg_match('/^ntor-onion-key ([A-Za-z0-9+\/=]+)\s*$/m', $descriptor, $ntorMatch) === 1) {
            $encoded = $ntorMatch[1];
            $raw = base64_decode($encoded . str_repeat('=', (4 - strlen($encoded) % 4) % 4), true);
            if ($raw !== false && strlen($raw) === 32) {
                $ntor = $raw;
            }
        }

        return ['rsa' => $rsaPem, 'ed25519' => $masterKey, 'ntor' => $ntor];
    }

    /**
     * Verify a CERTS cell payload: at least one valid certificate signed by
     * the relay's authenticated ed25519 identity.
     */
    public static function verifyLinkCerts(string $certsPayload, string $expectedEd25519Id): bool
    {
        // tor-spec §4.2: the body starts with a one-byte certificate count,
        // followed by that many [type:1][length:2][body] records.
        if ($certsPayload === '') {
            return false;
        }

        $count = ord($certsPayload[0]);
        $offset = 1;
        $length = strlen($certsPayload);
        $valid = 0;

        for ($index = 0; $index < $count; $index++) {
            if ($offset + 3 > $length) {
                return false;
            }
            $type = ord($certsPayload[$offset]);
            $certLength = unpack('n', $certsPayload, $offset + 1)[1];
            $offset += 3;
            if ($certLength <= 0 || $offset + $certLength > $length) {
                return false;
            }

            $raw = substr($certsPayload, $offset, $certLength);
            $offset += $certLength;

            if ($type !== self::CERT_TYPE_ID_SIGNING) {
                continue;
            }

            try {
                $cert = OnionV3::parseEd25519Cert(
                    "-----BEGIN ED25519 CERT-----\n" . chunk_split(base64_encode($raw), 64, "\n")
                    . "-----END ED25519 CERT-----\n"
                );
            } catch (\Throwable) {
                continue;
            }

            if ($cert['type'] !== self::CERT_TYPE_ID_SIGNING || $cert['expires'] < time()) {
                continue;
            }

            if (self::ed25519Verify($cert['signature'], substr($cert['raw'], 0, -64), $expectedEd25519Id)) {
                $valid++;
            }
        }

        return $valid > 0;
    }

    private static function ed25519Verify(string $signature, string $message, string $publicKey): bool
    {
        try {
            return sodium_crypto_sign_verify_detached($signature, $message, $publicKey);
        } catch (\SodiumException) {
            return false;
        }
    }
}
