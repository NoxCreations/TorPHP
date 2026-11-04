<?php

declare(strict_types=1);

namespace Torv3\Cell;

use Torv3\TorProtocolException;

/**
 * 509-byte relay cell payload (tor-spec.txt §6.1).
 *
 * Layout:
 *   Relay command  [1]
 *   'Recognized'   [2]   must be zero
 *   Stream ID      [2]
 *   Digest         [4]   running SHA-1 digest, zeroed while hashing
 *   Length         [2]
 *   Data           [Length]
 *   Padding        [up to 509 bytes]
 */
final class RelayCell
{
    public const HEADER_LEN = 11;
    public const DIGEST_OFFSET = 5;
    public const DIGEST_LEN = 4;
    public const MAX_DATA = Commands::PAYLOAD_LEN - self::HEADER_LEN; // 498

    /**
     * Build a 509-byte relay payload with a zeroed digest field.
     */
    public static function build(int $command, int $streamId, string $data): string
    {
        $length = strlen($data);
        if ($length > self::MAX_DATA) {
            throw new TorProtocolException(
                'Relay cell data too long: ' . $length . ' > ' . self::MAX_DATA
            );
        }

        $header = chr($command & 0xFF)
            . pack('n', 0)            // Recognized
            . pack('n', $streamId & 0xFFFF)
            . str_repeat("\x00", self::DIGEST_LEN)
            . pack('n', $length);

        $payload = $header . $data;

        return str_pad($payload, Commands::PAYLOAD_LEN, "\x00");
    }

    public static function command(string $payload): int
    {
        return ord($payload[0]);
    }

    public static function recognized(string $payload): int
    {
        return unpack('n', $payload, 1)[1];
    }

    public static function streamId(string $payload): int
    {
        return unpack('n', $payload, 3)[1];
    }

    public static function digest(string $payload): string
    {
        return substr($payload, self::DIGEST_OFFSET, self::DIGEST_LEN);
    }

    public static function length(string $payload): int
    {
        return unpack('n', $payload, 9)[1];
    }

    public static function data(string $payload): string
    {
        $length = self::length($payload);
        if ($length > self::MAX_DATA) {
            throw new TorProtocolException('Relay cell claims invalid length ' . $length);
        }

        return substr($payload, self::HEADER_LEN, $length);
    }

    /**
     * Return the payload with the digest field zeroed (as hashed on the wire).
     */
    public static function zeroDigest(string $payload): string
    {
        return substr_replace($payload, str_repeat("\x00", self::DIGEST_LEN), self::DIGEST_OFFSET, self::DIGEST_LEN);
    }

    /**
     * Return the payload with $digest written into the digest field.
     */
    public static function insertDigest(string $payload, string $digest): string
    {
        if (strlen($digest) !== self::DIGEST_LEN) {
            throw new TorProtocolException('Relay digest must be 4 bytes');
        }

        return substr_replace($payload, $digest, self::DIGEST_OFFSET, self::DIGEST_LEN);
    }
}
