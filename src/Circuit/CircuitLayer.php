<?php

declare(strict_types=1);

namespace Torv3\Circuit;

use Torv3\Cell\Commands;
use Torv3\Cell\RelayCell;
use Torv3\Crypto\Aes128Ctr;
use Torv3\TorProtocolException;

/**
 * One hop's relay-cell crypto state:
 *
 *   - AES-128-CTR forward/backward ciphers (Kf/Kb)
 *   - SHA-1 (ntor hops) or SHA3-256 (hs_ntor rendezvous layer) digests
 *     seeded with Df/Db
 *
 * tor-spec.txt §5.2.2 and §6.1.
 */
final class CircuitLayer
{
    /**
     * Length of a SENDME v1 tag (proposal 289). Tor always uses 20 bytes for
     * the tor1 crypto protocol, even on the SHA3-256 hidden-service layer.
     */
    public const SENDME_TAG_LEN = 20;

    private Aes128Ctr $forwardCipher;
    private Aes128Ctr $backwardCipher;

    /** @var \HashContext */
    private $forwardDigest;

    /** @var \HashContext */
    private $backwardDigest;

    private string $algorithm;
    private int $digestFieldLen;

    /** Full rolling digest of the most recent cell sent toward this hop. */
    private string $lastForwardDigest = '';

    /** Full rolling digest of the most recent cell received from this hop. */
    private string $lastBackwardDigest = '';

    /**
     * @param string $df  digest seed, forward direction
     * @param string $db  digest seed, backward direction
     * @param string $kf  AES-128 key, forward direction
     * @param string $kb  AES-128 key, backward direction
     * @param string $digestAlgorithm 'sha1' for ntor hops, 'sha3-256' for hs layers
     */
    public function __construct(
        string $df,
        string $db,
        string $kf,
        string $kb,
        string $digestAlgorithm = 'sha1'
    ) {
        if (strlen($kf) !== strlen($kb) || !in_array(strlen($kf), [16, 32], true)) {
            throw new TorProtocolException('Relay keys must both be 16 bytes (AES-128) or 32 bytes (AES-256)');
        }
        if ($df === '' || $db === '') {
            throw new TorProtocolException('Relay digest seeds must not be empty');
        }

        $this->algorithm = $digestAlgorithm;
        $this->digestFieldLen = RelayCell::DIGEST_LEN;

        $this->forwardCipher = new Aes128Ctr($kf);
        $this->backwardCipher = new Aes128Ctr($kb);

        $this->forwardDigest = hash_init($digestAlgorithm);
        hash_update($this->forwardDigest, $df);

        $this->backwardDigest = hash_init($digestAlgorithm);
        hash_update($this->backwardDigest, $db);
    }

    /**
     * Hash the payload (digest field zeroed) with the forward digest and write
     * the truncated digest into the payload.
     */
    public function setDigest(string $payload): string
    {
        $zeroed = RelayCell::zeroDigest($payload);
        $context = hash_copy($this->forwardDigest);
        hash_update($context, $zeroed);
        $digest = substr(hash_final($context, true), 0, $this->digestFieldLen);

        // Advance the real digest state: this cell is part of the stream.
        hash_update($this->forwardDigest, $zeroed);
        $this->lastForwardDigest = hash_final(hash_copy($this->forwardDigest), true);

        return RelayCell::insertDigest($payload, $digest);
    }

    /**
     * Encrypt a 509-byte payload with this layer's forward cipher.
     */
    public function encrypt(string $payload): string
    {
        return $this->forwardCipher->encrypt($payload);
    }

    /**
     * Decrypt a 509-byte payload with this layer's backward cipher.
     */
    public function decrypt(string $payload): string
    {
        return $this->backwardCipher->decrypt($payload);
    }

    /**
     * Verify the relay digest of an already-decrypted 509-byte payload and
     * advance the backward digest state (every layer the cell passes through
     * consumes one digest step).
     */
    public function verifyDigest(string $payload): bool
    {
        $received = RelayCell::digest($payload);
        $zeroed = RelayCell::zeroDigest($payload);

        $context = hash_copy($this->backwardDigest);
        hash_update($context, $zeroed);
        $calculated = substr(hash_final($context, true), 0, $this->digestFieldLen);

        hash_update($this->backwardDigest, $zeroed);
        $this->lastBackwardDigest = hash_final(hash_copy($this->backwardDigest), true);

        return hash_equals($calculated, $received);
    }

    public function digestAlgorithm(): string
    {
        return $this->algorithm;
    }

    /**
     * SENDME v1 tag for the last cell received from this hop (proposal 289):
     * the truncated rolling backward digest, computed over the payload with
     * the relay digest field zeroed.
     */
    public function inboundSendmeTag(): string
    {
        return substr($this->lastBackwardDigest, 0, self::SENDME_TAG_LEN);
    }

    /**
     * SENDME v1 tag the relay is expected to return for the last cell we sent
     * toward this hop.
     */
    public function outboundSendmeTag(): string
    {
        return substr($this->lastForwardDigest, 0, self::SENDME_TAG_LEN);
    }
}
