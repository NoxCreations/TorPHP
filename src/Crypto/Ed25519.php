<?php

declare(strict_types=1);

namespace Torv3\Crypto;

use Torv3\TorProtocolException;

/**
 * Ed25519 group arithmetic on top of ext-gmp.
 *
 * PHP (and libsodium) expose Ed25519 signing but not point-scalar
 * multiplication, which HSv3 key blinding requires
 * (rend-spec-v3 §2.2, Appendix A):
 *
 *     blinded_pk = blind_factor * identity_pk
 *
 * Curve: -x^2 + y^2 = 1 + d*x^2*y^2 over GF(2^255-19), d = -121665/121666.
 * Points use extended homogeneous coordinates (X:Y:Z:T) with x = X/Z,
 * y = Y/Z, T = XY/Z, and the complete Hisil-Wong-Carter-Dawson addition
 * formula so there are no exceptional cases.
 */
final class Ed25519
{
    /** Little-endian encoding of the Ed25519 base point B (y = 4/5). */
    public const BASE_POINT =
        '5866666666666666666666666666666666666666666666666666666666666666';

    private const P_HEX = '7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed';

    /** Group order l = 2^252 + 27742317777372353535851937790883648493 */
    private const L_HEX = '1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ed';

    private static ?\GMP $p = null;
    private static ?\GMP $d = null;
    private static ?\GMP $twoD = null;
    private static ?\GMP $sqrtM1 = null;
    private static ?\GMP $l = null;

    /**
     * Decode a 32-byte compressed point into extended coordinates.
     *
     * @return array{X: \GMP, Y: \GMP, Z: \GMP, T: \GMP}
     */
    public static function decode(string $encoded): array
    {
        if (strlen($encoded) !== 32) {
            throw new TorProtocolException('Ed25519 point must be 32 bytes, got ' . strlen($encoded));
        }

        $p = self::p();

        $sign = (ord($encoded[31]) >> 7) & 1;
        $bytes = $encoded;
        $bytes[31] = chr(ord($bytes[31]) & 0x7F);

        $y = gmp_import($bytes, 1, GMP_LSW_FIRST);
        if (gmp_cmp($y, $p) >= 0) {
            throw new TorProtocolException('Ed25519 point has non-canonical y coordinate');
        }

        $y2 = gmp_mod(gmp_mul($y, $y), $p);

        // u = y^2 - 1, v = d*y^2 + 1
        $u = gmp_mod(gmp_sub($y2, gmp_init(1)), $p);
        $v = gmp_mod(gmp_add(gmp_mul(self::d(), $y2), gmp_init(1)), $p);

        // x = u*v^3 * (u*v^7)^((p-5)/8)
        $v3 = gmp_mod(gmp_mul(gmp_mul($v, $v), $v), $p);
        $v7 = gmp_mod(gmp_mul(gmp_mul($v3, $v3), $v), $p);
        $pow = gmp_powm(gmp_mod(gmp_mul($u, $v7), $p), gmp_div_q(gmp_sub($p, gmp_init(5)), gmp_init(8)), $p);
        $x = gmp_mod(gmp_mul(gmp_mul($u, $v3), $pow), $p);

        $check = gmp_mod(gmp_mul($v, gmp_mul($x, $x)), $p);
        if (gmp_cmp($check, $u) !== 0) {
            if (gmp_cmp($check, gmp_mod(gmp_neg($u), $p)) !== 0) {
                throw new TorProtocolException('Ed25519 point is not on the curve');
            }
            $x = gmp_mod(gmp_mul($x, self::sqrtMinusOne()), $p);
        }

        if (gmp_cmp($x, gmp_init(0)) === 0 && $sign === 1) {
            throw new TorProtocolException('Ed25519 point has invalid sign bit');
        }

        if (gmp_intval(gmp_mod($x, gmp_init(2))) !== $sign) {
            $x = gmp_sub($p, $x);
        }

        return [
            'X' => $x,
            'Y' => $y,
            'Z' => gmp_init(1),
            'T' => gmp_mod(gmp_mul($x, $y), $p),
        ];
    }

    /**
     * Encode an extended-coordinate point back to 32 bytes.
     *
     * @param array{X: \GMP, Y: \GMP, Z: \GMP, T: \GMP} $point
     */
    public static function encode(array $point): string
    {
        $p = self::p();
        $zInv = gmp_invert($point['Z'], $p);
        if ($zInv === false) {
            throw new TorProtocolException('Ed25519 point has zero Z coordinate');
        }

        $x = gmp_mod(gmp_mul($point['X'], $zInv), $p);
        $y = gmp_mod(gmp_mul($point['Y'], $zInv), $p);

        $bytes = gmp_export($y, 1, GMP_LSW_FIRST);
        $bytes = str_pad($bytes, 32, "\x00", STR_PAD_RIGHT);

        if (gmp_intval(gmp_mod($x, gmp_init(2))) === 1) {
            $bytes[31] = chr(ord($bytes[31]) | 0x80);
        } else {
            $bytes[31] = chr(ord($bytes[31]) & 0x7F);
        }

        return $bytes;
    }

    /**
     * Multiply an encoded point by a scalar (little-endian byte string,
     * GMP integer, or int) and return the encoded result.
     *
     * @param \GMP|string|int $scalar
     */
    public static function scalarMultiply($scalar, string $encodedPoint): string
    {
        $point = self::decode($encodedPoint);
        $result = self::identity();

        $addend = $point;
        foreach (self::scalarBits($scalar) as $bit) {
            if ($bit === 1) {
                $result = self::add($result, $addend);
            }
            $addend = self::double($addend);
        }

        return self::encode($result);
    }

    /**
     * Reduce a 32-byte little-endian value modulo the group order l.
     */
    public static function reduceScalar(string $bytes): \GMP
    {
        return gmp_mod(gmp_import($bytes, 1, GMP_LSW_FIRST), self::order());
    }

    /**
     * Group order l.
     */
    public static function order(): \GMP
    {
        return self::$l ??= gmp_init(self::L_HEX, 16);
    }

    /**
     * Identity element (0:1:1:0).
     *
     * @return array{X: \GMP, Y: \GMP, Z: \GMP, T: \GMP}
     */
    public static function identity(): array
    {
        return [
            'X' => gmp_init(0),
            'Y' => gmp_init(1),
            'Z' => gmp_init(1),
            'T' => gmp_init(0),
        ];
    }

    /**
     * Complete (unified) point addition, HWCD formulas.
     *
     * @param array{X: \GMP, Y: \GMP, Z: \GMP, T: \GMP} $p1
     * @param array{X: \GMP, Y: \GMP, Z: \GMP, T: \GMP} $p2
     * @return array{X: \GMP, Y: \GMP, Z: \GMP, T: \GMP}
     */
    public static function add(array $p1, array $p2): array
    {
        $p = self::p();

        $a = gmp_mod(gmp_mul(gmp_sub($p1['Y'], $p1['X']), gmp_sub($p2['Y'], $p2['X'])), $p);
        $b = gmp_mod(gmp_mul(gmp_add($p1['Y'], $p1['X']), gmp_add($p2['Y'], $p2['X'])), $p);
        $c = gmp_mod(gmp_mul(gmp_mul($p1['T'], self::twoD()), $p2['T']), $p);
        $e = gmp_sub($b, $a);
        $f = gmp_sub(gmp_mod(gmp_mul(gmp_mul(gmp_init(2), $p1['Z']), $p2['Z']), $p), $c);
        $g = gmp_add(gmp_mod(gmp_mul(gmp_mul(gmp_init(2), $p1['Z']), $p2['Z']), $p), $c);
        $h = gmp_add($b, $a);

        return [
            'X' => gmp_mod(gmp_mul($e, $f), $p),
            'Y' => gmp_mod(gmp_mul($g, $h), $p),
            'Z' => gmp_mod(gmp_mul($f, $g), $p),
            'T' => gmp_mod(gmp_mul($e, $h), $p),
        ];
    }

    /**
     * Point doubling in extended coordinates.
     *
     * @param array{X: \GMP, Y: \GMP, Z: \GMP, T: \GMP} $p1
     * @return array{X: \GMP, Y: \GMP, Z: \GMP, T: \GMP}
     */
    public static function double(array $p1): array
    {
        $p = self::p();

        $a = gmp_mod(gmp_mul($p1['X'], $p1['X']), $p);
        $b = gmp_mod(gmp_mul($p1['Y'], $p1['Y']), $p);
        $c = gmp_mod(gmp_mul(gmp_init(2), gmp_mul($p1['Z'], $p1['Z'])), $p);
        $h = gmp_mod(gmp_add($a, $b), $p);
        $e = gmp_mod(gmp_sub($h, gmp_mul(gmp_add($p1['X'], $p1['Y']), gmp_add($p1['X'], $p1['Y']))), $p);
        $g = gmp_mod(gmp_sub($a, $b), $p);
        $f = gmp_mod(gmp_add($c, $g), $p);

        return [
            'X' => gmp_mod(gmp_mul($e, $f), $p),
            'Y' => gmp_mod(gmp_mul($g, $h), $p),
            'Z' => gmp_mod(gmp_mul($f, $g), $p),
            'T' => gmp_mod(gmp_mul($e, $h), $p),
        ];
    }

    /**
     * Yield the low 256 bits of a scalar, LSB first.
     *
     * @param \GMP|string|int $scalar
     * @return int[]
     */
    private static function scalarBits($scalar): array
    {
        if (is_string($scalar)) {
            $scalar = gmp_import($scalar, 1, GMP_LSW_FIRST);
        } elseif (is_int($scalar)) {
            $scalar = gmp_init($scalar);
        }

        $mask = gmp_init(1);
        $zero = gmp_init(0);
        $bits = [];
        for ($i = 0; $i < 256; $i++) {
            // gmp_intval() truncates values above PHP_INT_MAX, so compare
            // with GMP instead of converting the masked bit to an int.
            $bits[] = gmp_cmp(gmp_and($scalar, $mask), $zero) === 0 ? 0 : 1;
            $mask = gmp_mul($mask, gmp_init(2));
        }

        return $bits;
    }

    private static function p(): \GMP
    {
        return self::$p ??= gmp_init(self::P_HEX, 16);
    }

    private static function d(): \GMP
    {
        if (self::$d === null) {
            $p = self::p();
            // d = -121665 / 121666 mod p
            $inv = gmp_invert(gmp_init(121666), $p);
            if ($inv === false) {
                throw new TorProtocolException('Unable to invert 121666 modulo p');
            }
            self::$d = gmp_mod(gmp_mul(gmp_init(-121665), $inv), $p);
        }

        return self::$d;
    }

    private static function twoD(): \GMP
    {
        return self::$twoD ??= gmp_mod(gmp_mul(gmp_init(2), self::d()), self::p());
    }

    private static function sqrtMinusOne(): \GMP
    {
        if (self::$sqrtM1 === null) {
            $p = self::p();
            self::$sqrtM1 = gmp_powm(gmp_init(2), gmp_div_q(gmp_sub($p, gmp_init(1)), gmp_init(4)), $p);
        }

        return self::$sqrtM1;
    }
}
