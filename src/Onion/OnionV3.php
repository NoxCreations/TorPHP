<?php

declare(strict_types=1);

namespace Torv3\Onion;

use Torv3\Cell\Commands;
use Torv3\Circuit\Circuit;
use Torv3\Crypto\Ed25519;
use Torv3\Crypto\Keccak;
use Torv3\Directory\DirectoryFetcher;
use Torv3\TorException;
use Torv3\TorOnionException;
use Torv3\TorStreamException;

/**
 * Next-generation (v3) onion service client:
 * address parsing, key blinding, descriptor fetching/decryption, the
 * introduction handshake and the rendezvous handshake.
 *
 * rend-spec-v3.txt §2 (descriptors), §3 (introduction), §4 (rendezvous),
 * §6 (addresses).
 */
final class OnionV3
{
    public const PROTOID = 'tor-hs-ntor-curve25519-sha3-256-1';
    public const T_HSENC = self::PROTOID . ':hs_key_extract';
    public const T_HSVERIFY = self::PROTOID . ':hs_verify';
    public const T_HSMAC = self::PROTOID . ':hs_mac';
    public const M_HSEXPAND = self::PROTOID . ':hs_key_expand';

    public const PERIOD_LENGTH_MINUTES = 1440;

    /** HSDirs accept descriptors up to 50k; allow framing overhead only. */
    public const MAX_DESCRIPTOR_BYTES = 65536;

    private const BLIND_STRING = "Derive temporary signing key\x00";

    private const ED25519_BASEPOINT =
        '(15112221349535400772501151409588531511454012693041857206046113283949847762202, '
        . '46316835694926478169428394003475163141307993866256225615783033603165251855960)';

    private const BASE32_ALPHABET = 'abcdefghijklmnopqrstuvwxyz234567';

    private string $address;
    private string $publicKey;
    private int $periodNum;
    private string $blindedPublicKey;
    private string $subcredential;
    private int $periodLengthMinutes;
    private ?string $clientAuthKey = null;

    public function __construct(string $address, ?int $timestamp = null, ?int $periodLengthMinutes = null)
    {
        $parsed = self::parseAddress($address);

        $this->address = $parsed['hostname'];
        $this->publicKey = $parsed['publicKey'];
        $this->periodLengthMinutes = $periodLengthMinutes ?? self::PERIOD_LENGTH_MINUTES;
        if ($this->periodLengthMinutes <= 0) {
            throw new TorOnionException('Descriptor period length must be positive');
        }
        $this->periodNum = self::timePeriod($timestamp ?? time(), $this->periodLengthMinutes);
        $this->blindedPublicKey = self::blindedPublicKey(
            $this->publicKey,
            $this->periodNum,
            $this->periodLengthMinutes
        );
        $this->subcredential = self::subcredentialFor($this->publicKey, $this->blindedPublicKey);
    }

    /* ------------------------------------------------------------------
     * Address handling
     * ------------------------------------------------------------------ */

    /**
     * @return array{hostname: string, publicKey: string, checksum: string, version: int}
     */
    public static function parseAddress(string $address): array
    {
        $hostname = strtolower(trim($address));
        if (str_ends_with($hostname, '.onion')) {
            $hostname = substr($hostname, 0, -6);
        }

        if (strlen($hostname) !== 56) {
            throw new TorOnionException('v3 onion addresses must be 56 base32 characters');
        }

        $raw = self::base32Decode($hostname);
        if ($raw === null || strlen($raw) !== 35) {
            throw new TorOnionException('Malformed v3 onion address');
        }

        $publicKey = substr($raw, 0, 32);
        $checksum = substr($raw, 32, 2);
        $version = ord($raw[34]);

        if ($version !== 3) {
            throw new TorOnionException('Unsupported onion address version ' . $version);
        }

        $expected = substr(Keccak::sha3_256('.onion checksum' . $publicKey . chr($version)), 0, 2);
        if (!hash_equals($expected, $checksum)) {
            throw new TorOnionException('Onion address checksum mismatch');
        }

        return [
            'hostname' => $hostname . '.onion',
            'publicKey' => $publicKey,
            'checksum' => $checksum,
            'version' => $version,
        ];
    }

    /**
     * Encode a 32-byte ed25519 public key as a v3 onion address.
     */
    public static function encodeAddress(string $publicKey, int $version = 3): string
    {
        if (strlen($publicKey) !== 32) {
            throw new TorOnionException('Onion public key must be 32 bytes');
        }

        $checksum = substr(Keccak::sha3_256('.onion checksum' . $publicKey . chr($version)), 0, 2);

        return self::base32Encode($publicKey . $checksum . chr($version)) . '.onion';
    }

    /**
     * Time period number: minutes since the epoch minus 12 hours, divided by
     * the period length in minutes (rend-spec-v3 §2.2.1).
     */
    public static function timePeriod(int $timestamp, int $periodLengthMinutes = self::PERIOD_LENGTH_MINUTES): int
    {
        $minutes = intdiv($timestamp, 60);
        $rotation = 12 * 60;

        return intdiv($minutes - $rotation, $periodLengthMinutes);
    }

    /**
     * blinded_pk = h * identity_pk, where
     * h = SHA3-256("Derive temporary signing key"|0x00|pk|B|"key-blind"|tp|period_length)
     * (rend-spec-v3 Appendix A / [KEYBLIND], as implemented by hs_common.c).
     */
    public static function blindedPublicKey(string $publicKey, int $periodNum, int $periodLengthMinutes = self::PERIOD_LENGTH_MINUTES): string
    {
        if (strlen($publicKey) !== 32) {
            throw new TorOnionException('Identity public key must be 32 bytes');
        }

        $nonce = 'key-blind' . pack('J', $periodNum) . pack('J', $periodLengthMinutes);

        $factor = Keccak::sha3_256(
            self::BLIND_STRING . $publicKey . self::ED25519_BASEPOINT . $nonce
        );

        // tor ed25519_donna_gettweak(): the blinding factor is a little-endian
        // scalar and must be clamped before the scalar multiplication.
        $factor[0] = chr(ord($factor[0]) & 248);
        $factor[31] = chr((ord($factor[31]) & 63) | 64);

        try {
            return Ed25519::scalarMultiply($factor, $publicKey);
        } catch (\Torv3\TorProtocolException $e) {
            throw new TorOnionException(
                'Onion service identity key is not a valid Ed25519 point: ' . $e->getMessage()
            );
        }
    }

    /**
     * N_hs_subcred = H("subcredential" | N_hs_cred | blinded_pk) with
     * N_hs_cred = H("credential" | identity_pk).
     */
    public static function subcredentialFor(string $publicKey, string $blindedPublicKey): string
    {
        $credential = Keccak::sha3_256('credential' . $publicKey);

        return Keccak::sha3_256('subcredential' . $credential . $blindedPublicKey);
    }

    /**
     * HSDir ring index for one descriptor replica (tor hs_build_hs_index):
     * H("store-at-idx" | blinded_pk | replica | period_length | period_num).
     *
     * This selects the responsible HSDirs; it is *not* the descriptor path.
     */
    public function hsIndex(int $replica = 1): string
    {
        return self::storeAtIndex(
            $this->blindedPublicKey,
            $replica,
            $this->periodNum,
            $this->periodLengthMinutes
        );
    }

    /**
     * H("store-at-idx" | blinded_pk | INT_8(replica) | INT_8(period_length)
     *   | INT_8(period_num)), with 8-byte integers (hs_build_hs_index()).
     */
    public static function storeAtIndex(
        string $blindedPublicKey,
        int $replica,
        int $periodNum,
        int $periodLengthMinutes
    ): string {
        return Keccak::sha3_256(
            'store-at-idx'
            . $blindedPublicKey
            . pack('J', $replica)
            . pack('J', $periodLengthMinutes)
            . pack('J', $periodNum)
        );
    }

    /**
     * GET path for the descriptor.
     *
     * The HSDir keys descriptors by the base64 (unpadded) blinded public key,
     * not by the ring index: tor's directory_launch_v3_desc_fetch() sets the
     * request resource to ed25519_public_to_base64(blinded_pubkey), and
     * handle_get_hs_descriptor_v3() hands everything after "/tor/hs/3/" to
     * hs_cache_lookup_as_dir(), which base64-decodes it back to that key.
     * The blinded key is the same for both replicas.
     */
    public function descriptorPath(): string
    {
        return '/tor/hs/3/' . rtrim(base64_encode($this->blindedPublicKey), '=');
    }

    public function hostname(): string
    {
        return $this->address;
    }

    public function publicKey(): string
    {
        return $this->publicKey;
    }

    public function blindedPublicKeyValue(): string
    {
        return $this->blindedPublicKey;
    }

    public function subcredential(): string
    {
        return $this->subcredential;
    }

    public function periodNum(): int
    {
        return $this->periodNum;
    }

    public function periodLengthMinutes(): int
    {
        return $this->periodLengthMinutes;
    }

    /* ------------------------------------------------------------------
     * Descriptor download
     * ------------------------------------------------------------------ */

    /**
     * Download the descriptor through an existing circuit ending at an HSDir
     * using RELAY_BEGIN_DIR (rend-spec-v3 §2.5, dir-spec.txt §5.2).
     */
    public function fetchDescriptor(Circuit $hsdirCircuit, float $timeout = 45.0): string
    {
        $path = $this->descriptorPath();

        $streamId = $hsdirCircuit->beginStream('', 0, true, $timeout);
        $hsdirCircuit->sendData(
            $streamId,
            'GET ' . $path . " HTTP/1.0\r\n"
            . "Host: hsdir\r\n"
            . "User-Agent: TorPHP/1.0\r\n"
            . "Connection: close\r\n\r\n"
        );

        $raw = '';
        $deadline = microtime(true) + $timeout;

        while (microtime(true) < $deadline) {
            try {
                $chunk = $hsdirCircuit->readStreamData($streamId, max(0.5, $deadline - microtime(true)));
            } catch (TorStreamException $e) {
                if (str_contains(strtolower($e->getMessage()), 'timed out')) {
                    // Never parse a half-read descriptor: the signature and
                    // encrypted block would be missing or truncated.
                    throw new TorOnionException('Timed out reading the descriptor from the HSDir');
                }

                break;
            }

            if ($chunk === '') {
                continue;
            }

            $raw .= $chunk;
            if (strlen($raw) > self::MAX_DESCRIPTOR_BYTES) {
                throw new TorOnionException('HSDir response exceeds the descriptor size limit');
            }

            $response = DirectoryFetcher::parseHttpResponse($raw);
            $length = isset($response['headers']['content-length'][0])
                ? (int) $response['headers']['content-length'][0]
                : null;
            if ($length !== null && strlen($response['body']) >= $length) {
                break;
            }
        }

        $hsdirCircuit->closeStream($streamId);

        if (microtime(true) >= $deadline) {
            throw new TorOnionException('Timed out reading the descriptor from the HSDir');
        }

        $response = DirectoryFetcher::parseHttpResponse($raw);
        if ($response['status'] !== 200) {
            throw new TorOnionException(
                'HSDir returned HTTP ' . $response['status'] . ' for descriptor ' . $path
            );
        }
        if (trim($response['body']) === '') {
            throw new TorOnionException('HSDir returned an empty descriptor');
        }

        return $response['body'];
    }

    /* ------------------------------------------------------------------
     * Descriptor decryption
     * ------------------------------------------------------------------ */

    /**
     * Configure the x25519 private key used to decrypt an authorized
     * descriptor's cookie. Accepts 32 raw bytes or base64.
     */
    public function setClientAuthKey(string $key): void
    {
        if (strlen($key) === 32) {
            $this->clientAuthKey = $key;

            return;
        }

        $decoded = self::decodeBase64Value($key);
        if ($decoded === null || strlen($decoded) !== 32) {
            throw new TorOnionException('Client authorization key must be 32 raw bytes or base64');
        }

        $this->clientAuthKey = $decoded;
    }

    public function hasClientAuthKey(): bool
    {
        return $this->clientAuthKey !== null;
    }

    /**
     * Derive the descriptor cookie for an authorized client from the first
     * descriptor layer (rend-spec-v3 §2.5.1.2):
     *
     *   SECRET_SEED = x25519(client_secret, ephemeral_public)
     *   KEYS        = SHAKE256(subcredential | SECRET_SEED, 40)
     *   CLIENT-ID   = KEYS[0..8]
     *   COOKIE-KEY  = KEYS[8..40]
     *   cookie      = AES-256-CTR(COOKIE-KEY, iv) XOR encrypted-cookie
     *
     * Returns null when the service advertises no matching auth-client entry,
     * which is the normal case for a service without client authorization.
     */
    public function clientDescriptorCookie(string $firstLayerPlaintext): ?string
    {
        if ($this->clientAuthKey === null) {
            throw new TorOnionException('No client authorization key is configured');
        }

        if (preg_match('/^desc-auth-type\s+(\S+)\s*$/m', $firstLayerPlaintext, $typeMatch) !== 1) {
            return null;
        }
        if (strtolower($typeMatch[1]) !== 'x25519') {
            throw new TorOnionException('Unsupported descriptor client-auth type: ' . $typeMatch[1]);
        }

        if (preg_match('/^desc-auth-ephemeral-key\s+(\S+)\s*$/m', $firstLayerPlaintext, $keyMatch) !== 1) {
            throw new TorOnionException('Descriptor has no client-auth ephemeral key');
        }

        $ephemeral = self::decodeBase64Value($keyMatch[1]);
        if ($ephemeral === null || strlen($ephemeral) !== 32) {
            throw new TorOnionException('Descriptor client-auth ephemeral key is invalid');
        }

        try {
            $secret = sodium_crypto_scalarmult($this->clientAuthKey, $ephemeral);
        } catch (\SodiumException) {
            throw new TorOnionException('Client authorization key agreement failed');
        }

        $keys = Keccak::shake256($this->subcredential . $secret, 40);
        $clientId = substr($keys, 0, 8);
        $cookieKey = substr($keys, 8, 32);

        foreach (preg_split('/\r?\n/', $firstLayerPlaintext) as $line) {
            if (!str_starts_with($line, 'auth-client ')) {
                continue;
            }

            $parts = preg_split('/\s+/', trim($line));
            if (count($parts) !== 4) {
                continue;
            }

            $id = self::decodeBase64Value($parts[1]);
            $iv = self::decodeBase64Value($parts[2]);
            $encrypted = self::decodeBase64Value($parts[3]);
            if ($id === null || $iv === null || $encrypted === null) {
                continue;
            }
            if (strlen($iv) !== 16 || strlen($encrypted) !== 16 || !hash_equals($clientId, $id)) {
                continue;
            }

            $cookie = openssl_decrypt($encrypted, 'aes-256-ctr', $cookieKey, OPENSSL_RAW_DATA, $iv);
            if ($cookie === false || strlen($cookie) !== 16) {
                throw new TorOnionException('Descriptor cookie decryption failed');
            }

            return $cookie;
        }

        return null;
    }

    private static function decodeBase64Value(string $value): ?string
    {
        $normalized = strtr(trim($value), '-_', '+/');
        $normalized .= str_repeat('=', (4 - strlen($normalized) % 4) % 4);
        $raw = base64_decode($normalized, true);

        return $raw === false ? null : $raw;
    }

    /**
     * Decrypt both descriptor layers and return the introduction points.
     *
     * @return array{revision: int, plaintext: string, introductionPoints: array<int, array<string, mixed>>, descriptor: string}
     */
    public function decryptDescriptor(string $descriptor, string $descriptorCookie = ''): array
    {
        if (!str_contains($descriptor, 'hs-descriptor 3')) {
            throw new TorOnionException('Not a version 3 hidden service descriptor');
        }

        $this->verifyDescriptorSignature($descriptor);

        $revision = 0;
        foreach (preg_split('/\r?\n/', $descriptor) as $line) {
            if (str_starts_with($line, 'revision-counter ')) {
                $revision = (int) trim(substr($line, 17));
                break;
            }
        }

        $superencrypted = self::extractPemBlock($descriptor, 'superencrypted');
        if ($superencrypted === null) {
            throw new TorOnionException('Descriptor has no superencrypted block');
        }

        $outerPlaintext = $this->decryptLayer(
            $superencrypted,
            $this->blindedPublicKey,
            'hsdir-superencrypted-data',
            $revision
        );

        if (preg_match('/^descriptor-lifetime (\d+)$/m', $outerPlaintext, $lifeMatch) === 1) {
            $lifetime = (int) $lifeMatch[1];
            if ($lifetime < 30 || $lifetime > 720) {
                throw new TorOnionException('Descriptor lifetime is outside the permitted 30..720 minutes');
            }
        }

        if ($descriptorCookie === '' && $this->clientAuthKey !== null) {
            $descriptorCookie = $this->clientDescriptorCookie($outerPlaintext) ?? '';
        }

        $innerBlob = self::extractPemBlock($outerPlaintext, 'encrypted');
        if ($innerBlob === null) {
            throw new TorOnionException('Descriptor has no encrypted block');
        }

        $innerPlaintext = $this->decryptLayer(
            $innerBlob,
            $this->blindedPublicKey . $descriptorCookie,
            'hsdir-encrypted-data',
            $revision
        );

        $plaintext = rtrim($innerPlaintext, "\x00");

        if (self::introAuthRequired($plaintext) && $descriptorCookie === '') {
            throw new TorOnionException(
                'This onion service requires client authorization; no matching client key is configured'
            );
        }

        return [
            'revision' => $revision,
            'plaintext' => $plaintext,
            'introductionPoints' => self::parseIntroPoints($plaintext),
            'descriptor' => $descriptor,
        ];
    }

    /**
     * Derive the layer keys and decrypt one descriptor layer.
     */
    public function decryptLayer(string $blob, string $secretData, string $stringConstant, int $revision): string
    {
        if (strlen($blob) < 16 + 32 + 16) {
            throw new TorOnionException('Descriptor layer is too short');
        }

        $salt = substr($blob, 0, 16);
        $mac = substr($blob, -32);
        $ciphertext = substr($blob, 16, -32);

        $secretInput = $secretData . $this->subcredential . pack('J', $revision);

        // KDF: SHAKE-256(secret_input | salt | string_constant, 80)
        //      KEY[32] | IV[16] | MAC_KEY[32]
        $keys = Keccak::shake256($secretInput . $salt . $stringConstant, 80);

        $key = substr($keys, 0, 32);
        $iv = substr($keys, 32, 16);
        $macKey = substr($keys, 48, 32);

        // MAC: SHA3-256(htonll(32) | MAC_KEY | htonll(16) | salt | ciphertext)
        $expected = Keccak::sha3_256(pack('J', 32) . $macKey . pack('J', 16) . $salt . $ciphertext);
        if (!hash_equals($expected, $mac)) {
            throw new TorOnionException('Descriptor MAC verification failed');
        }

        $plaintext = openssl_decrypt($ciphertext, 'aes-256-ctr', $key, OPENSSL_RAW_DATA, $iv);
        if ($plaintext === false) {
            throw new TorOnionException('Descriptor decryption failed');
        }

        return $plaintext;
    }

    /**
     * Extract and base64-decode a "-----BEGIN X-----" block.
     */
    public static function extractPemBlock(string $text, string $field): ?string
    {
        $keyword = $field === 'superencrypted' ? 'superencrypted' : '(?<!super)encrypted';
        $pattern = '/' . $keyword
            . '\s*\r?\n\s*-----BEGIN MESSAGE-----\s*(.*?)-----END MESSAGE-----/s';

        if (!preg_match($pattern, $text, $matches)) {
            return null;
        }

        $decoded = base64_decode(preg_replace('/\s+/', '', $matches[1]) ?? '', true);
        if ($decoded === false || $decoded === '') {
            return null;
        }

        return $decoded;
    }

    /**
     * True when the service advertises client authorization in its descriptor.
     */
    public static function introAuthRequired(string $plaintext): bool
    {
        return preg_match('/^intro-auth-required\s+\S+/m', $plaintext) === 1;
    }

    /**
     * Parse the second-layer plaintext into introduction point entries.
     *
     * @return array<int, array<string, mixed>>
     */
    public static function parseIntroPoints(string $plaintext): array
    {
        $lines = preg_split('/\r?\n/', $plaintext);
        $points = [];
        $current = null;

        /** Field whose multi-line PEM certificate is being collected. */
        $certField = null;
        $certBuffer = '';

        foreach ($lines as $line) {
            $line = rtrim($line, "\r\n");

            if ($certField !== null) {
                $certBuffer .= $line . "\n";
                if (str_starts_with($line, '-----END ED25519 CERT-----')) {
                    if ($certField === 'auth-key' && $current !== null) {
                        $current['authKey'] = self::certKey($certBuffer);
                    }
                    $certField = null;
                    $certBuffer = '';
                }
                continue;
            }

            if (str_starts_with($line, 'introduction-point ')) {
                if ($current !== null) {
                    $points[] = $current;
                }
                $current = [
                    'linkSpecifiers' => self::parseLspecs(trim(substr($line, 19))),
                    'authKey' => null,
                    'encKey' => null,
                    'onionKey' => null,
                ];
                continue;
            }

            if ($current === null) {
                continue;
            }

            if ($line === 'auth-key' || $line === 'enc-key-cert') {
                $certField = $line;
                $certBuffer = '';
                continue;
            }

            if (str_starts_with($line, 'auth-key ')) {
                $current['authKey'] = self::certKey(substr($line, 9));
                continue;
            }

            if (str_starts_with($line, 'onion-key ntor ')) {
                $current['onionKey'] = self::base64DecodeKey(trim(substr($line, 15)));
                continue;
            }

            if (str_starts_with($line, 'enc-key ntor ')) {
                $current['encKey'] = self::base64DecodeKey(trim(substr($line, 13)));
            }
        }

        if ($current !== null) {
            $points[] = $current;
        }

        return array_values(array_filter(
            $points,
            static fn (array $p): bool => $p['authKey'] !== null && $p['encKey'] !== null
        ));
    }

    /**
     * Verify the descriptor-signing-key-cert and the descriptor signature
     * (rend-spec-v3 §2.4). Without this an HSDir could substitute arbitrary
     * introduction points for any service.
     */
    public function verifyDescriptorSignature(string $descriptor): void
    {
        self::verifyDescriptorForBlindedKey($descriptor, $this->blindedPublicKey);
    }

    public static function verifyDescriptorForBlindedKey(string $descriptor, string $blindedPublicKey): void
    {
        $pattern = '/descriptor-signing-key-cert\\s*\\r?\\n(-----BEGIN ED25519 CERT-----.*?-----END ED25519 CERT-----)/s';
        if (preg_match($pattern, $descriptor, $match) !== 1) {
            throw new TorOnionException('Descriptor has no signing-key certificate');
        }

        $cert = self::parseEd25519Cert($match[1]);
        if ($cert['type'] !== 8) {
            throw new TorOnionException('Descriptor signing certificate has type ' . $cert['type'] . ', expected 8');
        }
        if ($cert['expires'] < time()) {
            throw new TorOnionException('Descriptor signing certificate has expired');
        }

        // The certificate is signed by the blinded signing key, which we can
        // derive from the onion address and the current time period.
        if (!self::ed25519Verify($cert['signature'], substr($cert['raw'], 0, -64), $blindedPublicKey)) {
            throw new TorOnionException('Descriptor signing certificate is not signed by the service blinded key');
        }

        $signingKey = $cert['extensions'][4] ?? null;
        if ($signingKey === null || !hash_equals($blindedPublicKey, $signingKey)) {
            throw new TorOnionException('Descriptor signing certificate does not certify the blinded key');
        }

        $signaturePos = strpos($descriptor, "\nsignature ");
        if ($signaturePos === false) {
            throw new TorOnionException('Descriptor has no signature line');
        }
        $signatureLine = substr($descriptor, $signaturePos + 1);
        if (preg_match('/^signature ([A-Za-z0-9+\\/=]+)/', $signatureLine, $sig) !== 1) {
            throw new TorOnionException('Malformed descriptor signature line');
        }

        $signature = base64_decode($sig[1], true);
        if ($signature === false || strlen($signature) !== 64) {
            throw new TorOnionException('Malformed descriptor signature');
        }

        $signed = substr($descriptor, 0, $signaturePos + 1);
        if (!self::ed25519Verify($signature, 'Tor onion service descriptor sig v3' . $signed, $cert['key'])) {
            throw new TorOnionException('Descriptor signature verification failed');
        }
    }

    /**
     * Parse a prop220 ed25519 certificate.
     *
     * VERSION(1) | TYPE(1) | EXPIRY(4) | KEY_TYPE(1) | KEY(32) | N_EXT(1)
     *   | [ LEN(2) | TYPE(1) | FLAGS(1) | DATA ]... | SIGNATURE(64)
     * The signature covers every preceding byte.
     *
     * @return array{type: int, expires: int, key: string, extensions: array<int, string>, signature: string, raw: string}
     */
    public static function parseEd25519Cert(string $pem): array
    {
        if (preg_match('/-----BEGIN ED25519 CERT-----\\s*(.*?)-----END ED25519 CERT-----/s', $pem, $match) !== 1) {
            throw new TorOnionException('Malformed ed25519 certificate wrapper');
        }

        $raw = base64_decode(preg_replace('/\\s+/', '', $match[1]) ?? '', true);
        if ($raw === false || strlen($raw) < 40 + 64) {
            throw new TorOnionException('Malformed ed25519 certificate');
        }

        $version = ord($raw[0]);
        $type = ord($raw[1]);
        // Ed25519 certificates store expiry as hours since the epoch
        // (tor's ed25519_cert_t.exp_hours), not as a unix timestamp.
        $expires = 3600 * unpack('N', $raw, 2)[1];
        $keyType = ord($raw[6]);
        if ($version !== 1 || $keyType !== 1) {
            throw new TorOnionException('Unsupported ed25519 certificate version or key type');
        }

        $key = substr($raw, 7, 32);
        $extensions = [];
        $count = ord($raw[39]);
        $offset = 40;
        $limit = strlen($raw) - 64;

        for ($i = 0; $i < $count; $i++) {
            if ($offset + 4 > $limit) {
                throw new TorOnionException('Truncated ed25519 certificate extension');
            }
            // trunnel: ext_length counts the extension payload only; type
            // and flags are separate bytes before it.
            $length = unpack('n', $raw, $offset)[1];
            if ($offset + 4 + $length > $limit) {
                throw new TorOnionException('Malformed ed25519 certificate extension length');
            }
            $extensionType = ord($raw[$offset + 2]);
            $extensions[$extensionType] = substr($raw, $offset + 4, $length);
            $offset += 4 + $length;
        }

        return [
            'type' => $type,
            'expires' => $expires,
            'key' => $key,
            'extensions' => $extensions,
            'signature' => substr($raw, -64),
            'raw' => $raw,
        ];
    }

    private static function ed25519Verify(string $signature, string $message, string $publicKey): bool
    {
        try {
            return sodium_crypto_sign_verify_detached($signature, $message, $publicKey);
        } catch (\SodiumException $e) {
            return false;
        }
    }

    /**
     * Read the 32-byte certified key out of an ed25519 certificate.
     *
     * Layout: VERSION(1) | CERT_TYPE(1) | EXPIRY(4) | KEY_TYPE(1) | KEY(32) ...
     */
    public static function certKey(string $certificate): string
    {
        $base64 = $certificate;
        if (preg_match('/-----BEGIN ED25519 CERT-----\s*(.*?)-----END ED25519 CERT-----/s', $certificate, $m)) {
            $base64 = $m[1];
        }

        $raw = base64_decode(preg_replace('/\s+/', '', $base64) ?? '', true);
        if ($raw === false || strlen($raw) < 39) {
            throw new TorOnionException('Malformed ed25519 certificate');
        }

        $version = ord($raw[0]);
        $keyType = ord($raw[6]);
        if ($version !== 1) {
            throw new TorOnionException('Unsupported ed25519 certificate version ' . $version);
        }
        if ($keyType !== 1) {
            throw new TorOnionException('Unexpected ed25519 certificate key type ' . $keyType);
        }

        return substr($raw, 7, 32);
    }

    /**
     * Decode a base64 list of link specifiers.
     *
     * @return array<int, array{type: int, data: string}>
     */
    public static function parseLspecs(string $encoded): array
    {
        $normalised = strtr(preg_replace('/\s+/', '', $encoded) ?? '', '-_', '+/');
        $raw = base64_decode($normalised, true);
        if ($raw === false || $raw === '') {
            throw new TorOnionException('Malformed link specifier blob');
        }

        // Descriptor link-specifier lists start with NSPEC (rend-spec-v3
        // §2.5): NSPEC | [LSTYPE | LSLEN | LSPEC]*. The NSPEC byte is part
        // of the serialized list, even though INTRODUCE1 writes the count
        // itself before calling encodeLspecs().
        $count = ord($raw[0]);
        $specs = [];
        $offset = 1;
        $length = strlen($raw);

        for ($i = 0; $i < $count; $i++) {
            if ($offset + 2 > $length) {
                throw new TorOnionException('Truncated link specifier list');
            }
            $type = ord($raw[$offset]);
            $len = ord($raw[$offset + 1]);
            $offset += 2;
            if ($offset + $len > $length) {
                throw new TorOnionException('Truncated link specifier');
            }
            $specs[] = ['type' => $type, 'data' => substr($raw, $offset, $len)];
            $offset += $len;
        }

        return $specs;
    }

    /**
     * Build the link-specifier bytes for the rendezvous point.
     *
     * @param array<int, array{type: int, data: string}> $specs
     */
    public static function encodeLspecs(array $specs): string
    {
        $raw = '';
        foreach ($specs as $spec) {
            $raw .= chr($spec['type']) . chr(strlen($spec['data'])) . $spec['data'];
        }

        return $raw;
    }

    /* ------------------------------------------------------------------
     * hs-ntor: INTRODUCE1
     * ------------------------------------------------------------------ */

    /**
     * Build the INTRODUCE1 body for an introduction point.
     *
     * @param array{authKey: string, encKey: string} $introPoint
     * @param string $rendezvousPublicKey  ntor onion key of the rendezvous point
     * @param array<int, array{type: int, data: string}> $rendezvousLspecs
     * @param string $cookie 20-byte rendezvous cookie
     * @return array{body: string, clientPrivate: string, clientPublic: string, encKey: string, authKey: string, macKey: string, plaintext: string}
     */
    public function buildIntroduce1(
        array $introPoint,
        string $rendezvousPublicKey,
        array $rendezvousLspecs,
        string $cookie
    ): array {
        if (strlen($cookie) !== 20) {
            throw new TorOnionException('Rendezvous cookie must be 20 bytes');
        }
        if (strlen($rendezvousPublicKey) !== 32) {
            throw new TorOnionException('Rendezvous ntor key must be 32 bytes');
        }

        $authKey = $introPoint['authKey'];
        $encKey = $introPoint['encKey'];

        $keypair = \Torv3\Crypto\NtorHandshake::generateKeypair();
        $clientPrivate = $keypair['private'];
        $clientPublic = $keypair['public'];

        // intro_secret_hs_input = EXP(B,x) | AUTH_KEY | X | B | PROTOID
        $exp = sodium_crypto_scalarmult($clientPrivate, $encKey);
        $secret = $exp . $authKey . $clientPublic . $encKey . self::PROTOID;

        $info = self::M_HSEXPAND . $this->subcredential;
        $keys = Keccak::shake256($secret . self::T_HSENC . $info, 64);
        $hsEncKey = substr($keys, 0, 32);
        $hsMacKey = substr($keys, 32, 32);

        // Body header: LEGACY_KEY_ID(20) | AUTH_KEY_TYPE(1)=2 | AUTH_KEY_LEN(2)
        //              | AUTH_KEY(32) | N_EXTENSIONS(1)=0
        $header = str_repeat("\x00", 20)
            . chr(2)
            . pack('n', 32)
            . $authKey
            . chr(0);

        // Decrypted plaintext:
        //   RENDEZVOUS_COOKIE(20) | N_EXTENSIONS(1) | ONION_KEY_TYPE(1)
        //   ONION_KEY_LEN(2) | ONION_KEY | NSPEC(1) | specs | PAD
        $plaintext = $cookie
            . chr(0)
            . chr(1)
            . pack('n', 32)
            . $rendezvousPublicKey
            . chr(count($rendezvousLspecs))
            . self::encodeLspecs($rendezvousLspecs);

        $paddingLength = (16 - (strlen($plaintext) % 16)) % 16;
        $plaintext .= random_bytes($paddingLength);

        $ciphertext = openssl_encrypt(
            $plaintext,
            'aes-256-ctr',
            $hsEncKey,
            OPENSSL_RAW_DATA,
            str_repeat("\x00", 16)
        );
        if ($ciphertext === false) {
            throw new TorOnionException('Failed to encrypt INTRODUCE1 payload');
        }

        // MAC = SHA3-256(htonll(32) | MAC_KEY | H | X | C)
        $mac = Keccak::sha3_256(pack('J', 32) . $hsMacKey . $header . $clientPublic . $ciphertext);

        return [
            'body' => $header . $clientPublic . $ciphertext . $mac,
            'clientPrivate' => $clientPrivate,
            'clientPublic' => $clientPublic,
            'encKey' => $encKey,
            'authKey' => $authKey,
            'macKey' => $hsMacKey,
            'plaintext' => $plaintext,
        ];
    }

    /* ------------------------------------------------------------------
     * hs-ntor: RENDEZVOUS2
     * ------------------------------------------------------------------ */

    /**
     * Complete the handshake with the service's RENDEZVOUS2 payload
     * (SERVER_PK | AUTH) and return the relay key material.
     *
     * @param array{clientPrivate: string, clientPublic: string, encKey: string, authKey: string} $context
     * @return array{df: string, db: string, kf: string, kb: string, seed: string}
     */
    public function processRend2(array $context, string $payload): array
    {
        if (strlen($payload) < 64) {
            throw new TorOnionException('RENDEZVOUS2 payload is too short');
        }

        $serverPublic = substr($payload, 0, 32);
        $auth = substr($payload, 32, 32);

        // rend_secret_hs_input = EXP(X,y) | EXP(X,b) | AUTH_KEY | B | X | Y | PROTOID
        // Both DH values use the same single-use client ephemeral key.
        $expWithService = sodium_crypto_scalarmult($context['clientPrivate'], $serverPublic);
        $expWithIntro = sodium_crypto_scalarmult($context['clientPrivate'], $context['encKey']);

        $secret = $expWithService
            . $expWithIntro
            . $context['authKey']
            . $context['encKey']
            . $context['clientPublic']
            . $serverPublic
            . self::PROTOID;

        // MAC(key, msg) = SHA3-256(htonll(len(key)) | key | msg): here the
        // secret input is the key and the tweak string is the message.
        $seed = self::macSha3($secret, self::T_HSENC);
        $verify = self::macSha3($secret, self::T_HSVERIFY);

        $authInput = $verify
            . $context['authKey']
            . $context['encKey']
            . $serverPublic
            . $context['clientPublic']
            . self::PROTOID
            . 'Server';

        $expected = self::macSha3($authInput, self::T_HSMAC);
        if (!hash_equals($expected, $auth)) {
            throw new TorOnionException('RENDEZVOUS2 handshake authentication failed');
        }

        // Key expansion: SHAKE-256(NTOR_KEY_SEED | m_hsexpand, 128)
        //   Df[32] | Db[32] | Kf[32] | Kb[32]
        $keys = Keccak::shake256($seed . self::M_HSEXPAND, 128);

        return [
            'df' => substr($keys, 0, 32),
            'db' => substr($keys, 32, 32),
            'kf' => substr($keys, 64, 32),
            'kb' => substr($keys, 96, 32),
            'seed' => $seed,
        ];
    }

    /**
     * MAC(key, msg) = SHA3-256(htonll(len(key)) | key | msg) — tor's
     * crypto_mac_sha3_256().
     */
    public static function macSha3(string $key, string $message): string
    {
        return Keccak::sha3_256(pack('J', strlen($key)) . $key . $message);
    }

    /* ------------------------------------------------------------------
     * Helpers
     * ------------------------------------------------------------------ */

    public static function base32Encode(string $data): string
    {
        $bits = '';
        foreach (str_split($data) as $byte) {
            $bits .= str_pad(decbin(ord($byte)), 8, '0', STR_PAD_LEFT);
        }

        $output = '';
        foreach (str_split($bits, 5) as $chunk) {
            $chunk = str_pad($chunk, 5, '0', STR_PAD_RIGHT);
            $output .= self::BASE32_ALPHABET[bindec($chunk)];
        }

        return $output;
    }

    public static function base32Decode(string $encoded): ?string
    {
        $encoded = strtolower(rtrim($encoded, '='));
        $bits = '';

        foreach (str_split($encoded) as $char) {
            $value = strpos(self::BASE32_ALPHABET, $char);
            if ($value === false) {
                return null;
            }
            $bits .= str_pad(decbin($value), 5, '0', STR_PAD_LEFT);
        }

        $output = '';
        foreach (str_split($bits, 8) as $chunk) {
            if (strlen($chunk) < 8) {
                break;
            }
            $output .= chr(bindec($chunk));
        }

        return $output;
    }

    private static function base64DecodeKey(string $base64): string
    {
        $normalised = strtr($base64, '-_', '+/');
        $padded = $normalised . str_repeat('=', (4 - strlen($normalised) % 4) % 4);
        $raw = base64_decode($padded, true);
        if ($raw === false || strlen($raw) !== 32) {
            throw new TorOnionException('Malformed base64 key in descriptor');
        }

        return $raw;
    }
}
