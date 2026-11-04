<?php

declare(strict_types=1);

namespace Torv3\Crypto;

use Torv3\TorProtocolException;

/**
 * ntor handshake (proposal 216, tor-spec.txt §5.1.4) plus the
 * HKDF-SHA256 (RFC 5869) key expansion used throughout Tor.
 */
final class NtorHandshake
{
    public const PROTOID = 'ntor-curve25519-sha256-1';
    public const T_MAC = self::PROTOID . ':mac';
    public const T_KEY = self::PROTOID . ':key_extract';
    public const T_VERIFY = self::PROTOID . ':verify';
    public const M_EXPAND = self::PROTOID . ':key_expand';

    public const H_LENGTH = 32;
    public const KEY_LENGTH = 16;
    public const ID_LENGTH = 20;

    /**
     * RFC 5869 HKDF-Expand with SHA-256.
     */
    public static function kdf(string $prk, string $info, int $length): string
    {
        if ($length < 0) {
            throw new TorProtocolException('HKDF length must not be negative');
        }

        $output = '';
        $previous = '';
        $counter = 1;

        while (strlen($output) < $length) {
            if ($counter > 255) {
                throw new TorProtocolException('HKDF output too long');
            }
            $previous = hash_hmac('sha256', $previous . $info . chr($counter), $prk, true);
            $output .= $previous;
            $counter++;
        }

        return substr($output, 0, $length);
    }

    /**
     * RFC 5869 HKDF (Extract then Expand).
     */
    public static function hkdf(string $ikm, string $salt, string $info, int $length): string
    {
        $prk = hash_hmac('sha256', $ikm, $salt, true);

        return self::kdf($prk, $info, $length);
    }

    /**
     * Generate a single-use X25519 keypair.
     *
     * @return array{private: string, public: string}
     */
    public static function generateKeypair(?string $private = null): array
    {
        $sk = $private ?? random_bytes(32);
        if (strlen($sk) !== 32) {
            throw new TorProtocolException('X25519 private key must be 32 bytes');
        }

        return [
            'private' => $sk,
            'public' => sodium_crypto_scalarmult_base($sk),
        ];
    }

    /**
     * Build the client's ntor onionskin: NODEID | B | X (84 bytes).
     */
    public static function clientOnionSkin(string $nodeId, string $onionKey, string $clientPublic): string
    {
        if (strlen($nodeId) !== self::ID_LENGTH) {
            throw new TorProtocolException('Node ID must be 20 bytes');
        }
        if (strlen($onionKey) !== 32 || strlen($clientPublic) !== 32) {
            throw new TorProtocolException('ntor keys must be 32 bytes');
        }

        return $nodeId . $onionKey . $clientPublic;
    }

    /**
     * Derive relay keys from a CREATED2/EXTENDED2 reply.
     *
     * Verifies the server AUTH value and returns
     * Df[20] | Db[20] | Kf[16] | Kb[16] (tor-spec.txt §5.2.2).
     *
     * @return array{df: string, db: string, kf: string, kb: string}
     */
    public static function clientComputeKeys(
        string $nodeId,
        string $onionKey,
        string $clientPrivate,
        string $clientPublic,
        string $serverPublic,
        string $auth
    ): array {
        if (strlen($auth) !== self::H_LENGTH) {
            throw new TorProtocolException('ntor AUTH must be 32 bytes');
        }

        $expY = sodium_crypto_scalarmult($clientPrivate, $serverPublic);
        $expB = sodium_crypto_scalarmult($clientPrivate, $onionKey);

        $secretInput = $expY . $expB . $nodeId . $onionKey . $clientPublic . $serverPublic . self::PROTOID;

        $verify = hash_hmac('sha256', $secretInput, self::T_VERIFY, true);

        $authInput = $verify . $nodeId . $onionKey . $serverPublic . $clientPublic . self::PROTOID . 'Server';
        $expected = hash_hmac('sha256', $authInput, self::T_MAC, true);

        if (!hash_equals($expected, $auth)) {
            throw new TorProtocolException('ntor handshake AUTH verification failed');
        }

        $keySeed = hash_hmac('sha256', $secretInput, self::T_KEY, true);
        $keys = self::kdf($keySeed, self::M_EXPAND, 72);

        // K is Df[20] | Db[20] | Kf[16] | Kb[16] (tor-spec.txt §5.2.2).
        return [
            'df' => substr($keys, 0, 20),
            'db' => substr($keys, 20, 20),
            'kf' => substr($keys, 40, self::KEY_LENGTH),
            'kb' => substr($keys, 56, self::KEY_LENGTH),
        ];
    }

    /**
     * Server-side derivation, used by the test-suite to exercise the
     * handshake symmetrically.
     *
     * @return array{reply: string, df: string, db: string, kf: string, kb: string}
     */
    public static function serverRespond(
        string $nodeId,
        string $onionPrivate,
        string $onionKey,
        string $clientPublic
    ): array {
        $ephemeral = self::generateKeypair();
        $serverPublic = $ephemeral['public'];

        $expX = sodium_crypto_scalarmult($ephemeral['private'], $clientPublic);
        $expB = sodium_crypto_scalarmult($onionPrivate, $clientPublic);

        $secretInput = $expX . $expB . $nodeId . $onionKey . $clientPublic . $serverPublic . self::PROTOID;

        $verify = hash_hmac('sha256', $secretInput, self::T_VERIFY, true);
        $authInput = $verify . $nodeId . $onionKey . $serverPublic . $clientPublic . self::PROTOID . 'Server';
        $auth = hash_hmac('sha256', $authInput, self::T_MAC, true);

        $keySeed = hash_hmac('sha256', $secretInput, self::T_KEY, true);
        $keys = self::kdf($keySeed, self::M_EXPAND, 72);

        return [
            'reply' => $serverPublic . $auth,
            'df' => substr($keys, 0, 20),
            'db' => substr($keys, 20, 20),
            'kf' => substr($keys, 40, self::KEY_LENGTH),
            'kb' => substr($keys, 56, self::KEY_LENGTH),
        ];
    }

    /**
     * Raw X25519 for hs-ntor (client ephemeral secret against a service key).
     */
    public static function exchange(string $privateKey, string $publicKey): string
    {
        if (strlen($privateKey) !== 32 || strlen($publicKey) !== 32) {
            throw new TorProtocolException('X25519 keys must be 32 bytes');
        }

        return sodium_crypto_scalarmult($privateKey, $publicKey);
    }
}
