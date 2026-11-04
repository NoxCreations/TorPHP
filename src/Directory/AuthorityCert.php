<?php

declare(strict_types=1);

namespace Torv3\Directory;

use Torv3\Crypto\RsaSignature;
use Torv3\TorDirectoryException;

/**
 * A directory authority's key certificate (dir-spec.txt §3.1): a self-signed
 * document binding a pinned RSA identity key to a shorter-lived RSA signing
 * key and its ed25519 cross-certificate.
 *
 * The trust anchor is the SHA-1 fingerprint of the identity key, which is
 * hard-coded from tor's auth_dirs.inc. Because the certificate is
 * self-contained, verifying it needs no additional data from the network.
 */
final class AuthorityCert
{
    private function __construct(
        public readonly string $fingerprint,
        public readonly string $identityPem,
        public readonly string $signingPem,
        public readonly string $signingKeyDigest,
        public readonly int $expires
    ) {
    }

    /**
     * Parse and verify one key certificate.
     *
     * @param string[] $pinnedFingerprints uppercase hex SHA-1 fingerprints
     */
    public static function parse(string $document, array $pinnedFingerprints): self
    {
        if (preg_match('/^dir-key-certificate-version 3\r?\n/', $document) !== 1) {
            throw new TorDirectoryException('Not a version 3 authority key certificate');
        }

        if (preg_match('/^fingerprint ([0-9A-Fa-f]{40})$/m', $document, $fpMatch) !== 1) {
            throw new TorDirectoryException('Authority certificate has no fingerprint');
        }
        $declared = strtoupper($fpMatch[1]);
        if (!in_array($declared, $pinnedFingerprints, true)) {
            throw new TorDirectoryException('Authority certificate is not from a pinned authority');
        }

        $identityPem = self::pemBlock($document, 'dir-identity-key');
        $signingPem = self::pemBlock($document, 'dir-signing-key');

        if (!hash_equals($declared, self::fingerprintOf($identityPem))) {
            throw new TorDirectoryException('Authority certificate fingerprint does not match its identity key');
        }

        if (preg_match('/^dir-key-expires (.+)$/m', $document, $expMatch) !== 1) {
            throw new TorDirectoryException('Authority certificate has no expiry');
        }
        $expires = strtotime(trim($expMatch[1]) . ' UTC');
        if ($expires === false || $expires < time()) {
            throw new TorDirectoryException('Authority certificate has expired');
        }

        // The certificate signature covers everything through the newline
        // after the "dir-key-certification" keyword.
        $certPos = strpos($document, "\ndir-key-certification");
        if ($certPos === false) {
            throw new TorDirectoryException('Authority certificate is unsigned');
        }
        $lineEnd = strpos($document, "\n", $certPos + 1);
        if ($lineEnd === false) {
            throw new TorDirectoryException('Malformed authority certificate signature line');
        }
        $signed = substr($document, 0, $lineEnd + 1);

        if (preg_match('/dir-key-certification.*?-----BEGIN (?:ID )?SIGNATURE-----\s*(.*?)-----END (?:ID )?SIGNATURE-----/s', $document, $sigMatch) !== 1) {
            throw new TorDirectoryException('Authority certificate signature is missing');
        }
        $signature = base64_decode(preg_replace('/\s+/', '', $sigMatch[1]) ?? '', true);
        if ($signature === false || $signature === '') {
            throw new TorDirectoryException('Malformed authority certificate signature');
        }

        if (!RsaSignature::verify($signed, $signature, $identityPem, 'sha1')) {
            throw new TorDirectoryException('Authority certificate self-signature is invalid');
        }

        return new self(
            $declared,
            $identityPem,
            $signingPem,
            self::fingerprintOf($signingPem),
            $expires
        );
    }

    /**
     * Verify a consensus signature made by this certificate's signing key.
     */
    public function verifyConsensusSignature(string $signedData, string $signature, string $hashAlgorithm): bool
    {
        return RsaSignature::verify($signedData, $signature, $this->signingPem, $hashAlgorithm);
    }

    /**
     * SHA-1 of the PKCS#1 DER encoding of an RSA public key, uppercase hex.
     */
    public static function fingerprintOf(string $pem): string
    {
        return strtoupper(sha1(self::pkcs1Der($pem)));
    }

    private static function pemBlock(string $text, string $field): string
    {
        $pattern = '/\n' . preg_quote($field, '/') . '\s*\r?\n(-----BEGIN [A-Z0-9 ]+-----.*?-----END [A-Z0-9 ]+-----)/s';
        if (preg_match($pattern, $text, $match) !== 1) {
            throw new TorDirectoryException('Authority certificate is missing ' . $field);
        }

        return $match[1];
    }

    /**
     * Encode an RSA public key as PKCS#1 RSAPublicKey DER, which is what
     * Tor hashes for identity and signing-key digests.
     */
    private static function pkcs1Der(string $pem): string
    {
        $key = openssl_pkey_get_public($pem);
        if ($key === false) {
            throw new TorDirectoryException('Authority certificate contains an invalid public key');
        }
        $details = openssl_pkey_get_details($key);
        if (!is_array($details) || !isset($details['rsa']['n'], $details['rsa']['e'])) {
            throw new TorDirectoryException('Authority public key is not RSA');
        }

        $integer = static function (string $bytes): string {
            $bytes = ltrim($bytes, "\x00");
            if ($bytes === '' || (ord($bytes[0]) & 0x80) !== 0) {
                $bytes = "\x00" . $bytes;
            }

            return "\x02" . self::derLength(strlen($bytes)) . $bytes;
        };

        $body = $integer($details['rsa']['n']) . $integer($details['rsa']['e']);

        return "\x30" . self::derLength(strlen($body)) . $body;
    }

    private static function derLength(int $length): string
    {
        if ($length < 0x80) {
            return chr($length);
        }

        $bytes = ltrim(pack('N', $length), "\x00");

        return chr(0x80 | strlen($bytes)) . $bytes;
    }

}
