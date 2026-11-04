<?php

declare(strict_types=1);

namespace Torv3\Crypto;

/**
 * Keccak / FIPS-202 primitives in pure PHP.
 *
 * Tor uses SHA3-256 for hidden-service descriptor MACs and SHAKE-256 as the
 * descriptor and hs-ntor KDF.  They are not guaranteed to be present in
 * ext-hash (and were absent from the PHP build this library was verified
 * against), so the sponge is implemented here on signed 64-bit lanes.
 *
 * The Keccak permutation only uses XOR/AND/NOT and rotations, so PHP's
 * 64-bit wrapping bitwise operators are exact; no 64-bit addition is needed.
 */
final class Keccak
{
    private const ROUNDS = 24;

    /** Rotation offsets, indexed by lane x + 5*y. */
    private const ROTATION = [
        0, 1, 62, 28, 27,
        36, 44, 6, 55, 20,
        3, 10, 43, 25, 39,
        41, 45, 15, 21, 8,
        18, 2, 61, 56, 14,
    ];

    /** Round constants for Keccak-f[1600], as raw 64-bit little-endian hex. */
    private const ROUND_CONSTANTS = [
        '0000000000000001', '0000000000008082', '800000000000808a', '8000000080008000',
        '000000000000808b', '0000000080000001', '8000000080008081', '8000000000008009',
        '000000000000008a', '0000000000000088', '0000000080008009', '000000008000000a',
        '000000008000808b', '800000000000008b', '8000000000008089', '8000000000008003',
        '8000000000008002', '8000000000000080', '000000000000800a', '800000008000000a',
        '8000000080008081', '8000000000008080', '0000000080000001', '8000000080008008',
    ];

    /**
     * SHA3-256 (rate 136 bytes, domain padding 0x06).
     */
    public static function sha3_256(string $data): string
    {
        return self::sponge($data, 136, "\x06", 32);
    }

    /**
     * SHAKE-256 with a chosen output length (rate 136 bytes, padding 0x1F).
     */
    public static function shake256(string $data, int $length): string
    {
        if ($length < 0) {
            throw new \InvalidArgumentException('SHAKE output length must not be negative');
        }

        return self::sponge($data, 136, "\x1F", $length);
    }

    private static function sponge(string $data, int $rate, string $suffix, int $outputLength): string
    {
        $state = array_fill(0, 25, 0);

        $padded = $data . $suffix;
        $padLen = $rate - (strlen($padded) % $rate);
        if ($padLen === 0) {
            $padLen = $rate;
        }
        // Final bit of the padding block.
        $padded .= str_repeat("\x00", $padLen - 1) . "\x80";

        $blocks = strlen($padded) / $rate;
        for ($b = 0; $b < $blocks; $b++) {
            $block = substr($padded, $b * $rate, $rate);
            for ($i = 0; $i < intdiv($rate, 8); $i++) {
                $state[$i] ^= self::laneFromBytes(substr($block, $i * 8, 8));
            }
            self::permute($state);
        }

        $output = '';
        while (strlen($output) < $outputLength) {
            for ($i = 0; $i < intdiv($rate, 8) && strlen($output) < $outputLength; $i++) {
                $output .= self::laneToBytes($state[$i]);
            }
            if (strlen($output) < $outputLength) {
                self::permute($state);
            }
        }

        return substr($output, 0, $outputLength);
    }

    /**
     * Read 8 little-endian bytes as a signed 64-bit lane.
     */
    private static function laneFromBytes(string $bytes): int
    {
        $parts = unpack('Vlo/Vhi', $bytes);

        return ($parts['hi'] << 32) | $parts['lo'];
    }

    /**
     * Write a lane as 8 little-endian bytes.
     */
    private static function laneToBytes(int $lane): string
    {
        return pack('V2', $lane & 0xFFFFFFFF, ($lane >> 32) & 0xFFFFFFFF);
    }

    /**
     * Rotate a 64-bit lane left by $n bits.
     */
    private static function rotl(int $lane, int $n): int
    {
        $n &= 63;
        if ($n === 0) {
            return $lane;
        }

        // Low $n bits of the arithmetic right shift give the wrapped bits.
        $mask = $n === 63 ? PHP_INT_MAX : ((1 << $n) - 1);

        return ($lane << $n) | (($lane >> (64 - $n)) & $mask);
    }

    /**
     * Keccak-f[1600] permutation, in place.
     *
     * @param int[] $a 25 lanes
     */
    private static function permute(array &$a): void
    {
        $c = array_fill(0, 5, 0);
        $b = array_fill(0, 25, 0);

        for ($round = 0; $round < self::ROUNDS; $round++) {
            /* Theta */
            for ($x = 0; $x < 5; $x++) {
                $c[$x] = $a[$x] ^ $a[$x + 5] ^ $a[$x + 10] ^ $a[$x + 15] ^ $a[$x + 20];
            }
            for ($x = 0; $x < 5; $x++) {
                $d = $c[($x + 4) % 5] ^ self::rotl($c[($x + 1) % 5], 1);
                for ($y = 0; $y < 25; $y += 5) {
                    $a[$y + $x] ^= $d;
                }
            }

            /* Rho and Pi */
            for ($x = 0; $x < 5; $x++) {
                for ($y = 0; $y < 5; $y++) {
                    $index = $x + 5 * $y;
                    $newX = $y;
                    $newY = (2 * $x + 3 * $y) % 5;
                    $b[$newX + 5 * $newY] = self::rotl($a[$index], self::ROTATION[$index]);
                }
            }

            /* Chi */
            for ($y = 0; $y < 25; $y += 5) {
                for ($x = 0; $x < 5; $x++) {
                    $a[$y + $x] = $b[$y + $x] ^ ((~$b[$y + (($x + 1) % 5)]) & $b[$y + (($x + 2) % 5)]);
                }
            }

            /* Iota: round constants are stored as big-endian 64-bit numbers. */
            $a[0] ^= unpack('J', hex2bin(self::ROUND_CONSTANTS[$round]))[1];
        }
    }
}
