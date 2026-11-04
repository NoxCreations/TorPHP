<?php

declare(strict_types=1);

namespace Torv3\Cell;

/**
 * Link-level cell commands and relay-level relay commands.
 *
 * tor-spec.txt §3 (cell format) and §6 (relay cells).
 */
final class Commands
{
    /* ------------------------------------------------------------------
     * Circuit / link cell commands (cell header command byte)
     * ------------------------------------------------------------------ */

    public const PADDING = 0;
    public const CREATE = 1;
    public const CREATED = 2;
    public const RELAY = 3;
    public const DESTROY = 4;
    public const CREATE_FAST = 5;
    public const CREATED_FAST = 6;
    public const VERSIONS = 7;
    public const NETINFO = 8;
    public const RELAY_EARLY = 9;
    public const CREATE2 = 10;
    public const CREATED2 = 11;
    public const PADDING_NEGOTIATE = 12;

    /* Variable-length commands (>= 128). */
    public const VPADDING = 128;
    public const CERTS = 129;
    public const AUTH_CHALLENGE = 130;
    public const AUTHENTICATE = 131;
    public const AUTHORIZE = 132;

    /* ------------------------------------------------------------------
     * Relay commands (first byte of a 509-byte relay payload)
     * ------------------------------------------------------------------ */

    public const RELAY_BEGIN = 1;
    public const RELAY_DATA = 2;
    public const RELAY_END = 3;
    public const RELAY_CONNECTED = 4;
    public const RELAY_SENDME = 5;
    public const RELAY_EXTEND = 6;
    public const RELAY_EXTENDED = 7;
    public const RELAY_TRUNCATE = 8;
    public const RELAY_TRUNCATED = 9;
    public const RELAY_DROP = 10;
    public const RELAY_RESOLVE = 11;
    public const RELAY_RESOLVED = 12;
    public const RELAY_BEGIN_DIR = 13;
    public const RELAY_EXTEND2 = 14;
    public const RELAY_EXTENDED2 = 15;

    /* Hidden service relay commands */
    public const RELAY_ESTABLISH_INTRO = 32;
    public const RELAY_ESTABLISH_RENDEZVOUS = 33;
    public const RELAY_INTRODUCE1 = 34;
    public const RELAY_INTRODUCE2 = 35;
    public const RELAY_RENDEZVOUS1 = 36;
    public const RELAY_RENDEZVOUS2 = 37;
    public const RELAY_INTRO_ESTABLISHED = 38;
    public const RELAY_RENDEZVOUS_ESTABLISHED = 39;
    public const RELAY_INTRODUCE_ACK = 40;

    /* ------------------------------------------------------------------
     * Protocol constants
     * ------------------------------------------------------------------ */

    /** CREATE2 / EXTEND2 handshake type for ntor (proposal 216). */
    public const NTOR_HTYPE = 0x0002;

    /** Tor link protocol versions we implement (v4 => 4-byte circuit IDs). */
    public const LINK_VERSIONS = [3, 4];

    /** A fixed-length cell payload is 509 bytes. */
    public const PAYLOAD_LEN = 509;

    /** Default circuit window sizes (FLOWCTRL spec / tor-spec §7.4). */
    public const CIRCWINDOW_START = 1000;
    public const CIRCWINDOW_INCREMENT = 100;
    public const STREAMWINDOW_START = 500;
    public const STREAMWINDOW_INCREMENT = 50;

    /** RELAY_EARLY cells allowed per circuit. */
    public const MAX_RELAY_EARLY = 8;

    /**
     * True for commands whose bodies use the variable-length cell encoding
     * (2-byte length prefix instead of 509 bytes of payload).
     */
    public static function isVariableLength(int $command): bool
    {
        return $command === self::VERSIONS
            || $command === self::VPADDING
            || $command === self::CERTS
            || $command === self::AUTH_CHALLENGE
            || $command === self::AUTHENTICATE
            || $command === self::AUTHORIZE;
    }
}
