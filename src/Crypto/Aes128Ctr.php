<?php

declare(strict_types=1);

namespace Torv3\Crypto;

use Torv3\TorProtocolException;

/**
 * Stateful AES-CTR stream cipher as used by Tor relay cells.
 *
 * tor-spec.txt §5.2.2 / §6.1: the counter is a 128-bit big-endian integer
 * starting at zero, and keystream blocks are AES-ECB encryptions of the
 * counter block.  Keystream bytes left over from a partial block are kept so
 * that successive cells continue the same stream.
 *
 * Ordinary ntor hops use 128-bit keys; the end-to-end hidden service layer
 * created by hs-ntor uses AES-256 (rend-spec-v3 §3.3.2).  The key length is
 * therefore detected from the key itself.
 */
final class Aes128Ctr
{
    private const BLOCK = 16;

    /** @var string 16- or 32-byte AES key */
    private string $key;

    /** @var string openssl cipher name matching the key length */
    private string $cipher;

    /** @var string unconsumed keystream bytes */
    private string $keystream = '';

    /** @var int current 32-bit block counter (low half of the 128-bit counter) */
    private int $counter = 0;

    public function __construct(string $key)
    {
        if (strlen($key) !== 16 && strlen($key) !== 32) {
            throw new TorProtocolException('AES key must be 16 or 32 bytes, got ' . strlen($key));
        }
        $this->key = $key;
        $this->cipher = strlen($key) === 32 ? 'aes-256-ecb' : 'aes-128-ecb';
    }

    /**
     * XOR $data against the keystream (encrypt == decrypt).
     */
    public function process(string $data): string
    {
        $len = strlen($data);
        if ($len === 0) {
            return '';
        }

        while (strlen($this->keystream) < $len) {
            $this->keystream .= $this->nextBlock();
        }

        $out = $data ^ substr($this->keystream, 0, $len);
        $this->keystream = substr($this->keystream, $len);

        return $out;
    }

    /**
     * Encrypt (same operation as decrypt for CTR).
     */
    public function encrypt(string $data): string
    {
        return $this->process($data);
    }

    /**
     * Decrypt (same operation as encrypt for CTR).
     */
    public function decrypt(string $data): string
    {
        return $this->process($data);
    }

    /**
     * Produce the next 16 bytes of keystream.
     */
    private function nextBlock(): string
    {
        // 128-bit big-endian counter: 96 zero bits then the block index.
        $counterBlock = str_repeat("\x00", 12) . pack('N', $this->counter);
        $this->counter = ($this->counter + 1) & 0xFFFFFFFF;

        $block = openssl_encrypt(
            $counterBlock,
            $this->cipher,
            $this->key,
            OPENSSL_RAW_DATA | OPENSSL_ZERO_PADDING
        );

        if ($block === false || strlen($block) !== self::BLOCK) {
            throw new TorProtocolException('AES-ECB block encryption failed');
        }

        return $block;
    }

    /**
     * Number of keystream bytes already generated for the current counter.
     */
    public function bytePosition(): int
    {
        return $this->counter * self::BLOCK - strlen($this->keystream);
    }
}
