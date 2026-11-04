<?php

declare(strict_types=1);

namespace Torv3\Cell;

use Torv3\TorConnectionException;
use Torv3\TorProtocolException;

/**
 * A single Tor link-protocol cell (tor-spec.txt §3).
 *
 * Fixed-length cell (link protocol v4+):
 *   CircID [4] | Command [1] | Payload [509]
 * Variable-length cell:
 *   CircID [4] | Command [1] | Length [2] | Body [Length]
 *
 * Before the VERSIONS negotiation the circuit ID field is 2 bytes wide.
 */
final class Cell
{
    public function __construct(
        public int $circuitId,
        public int $command,
        public string $payload,
        public bool $variable = false
    ) {
    }

    public static function fixed(int $circuitId, int $command, string $payload): self
    {
        if (strlen($payload) > Commands::PAYLOAD_LEN) {
            throw new TorProtocolException('Fixed cell payload too long: ' . strlen($payload));
        }

        return new self($circuitId, $command, str_pad($payload, Commands::PAYLOAD_LEN, "\x00"), false);
    }

    public static function variable(int $circuitId, int $command, string $body): self
    {
        return new self($circuitId, $command, $body, true);
    }

    /**
     * Serialise for the wire. $circIdWidth is 2 before the VERSIONS exchange,
     * 4 afterwards (link protocol >= 4).
     */
    public function encode(int $circIdWidth = 4): string
    {
        if ($circIdWidth === 2) {
            if ($this->circuitId > 0xFFFF) {
                throw new TorProtocolException('Circuit ID does not fit in 2 bytes');
            }
            $header = pack('n', $this->circuitId) . chr($this->command);
        } else {
            $header = pack('N', $this->circuitId) . chr($this->command);
        }

        if ($this->variable) {
            return $header . pack('n', strlen($this->payload)) . $this->payload;
        }

        return $header . $this->payload;
    }

    /**
     * Read one complete cell from a stream.
     *
     * @param resource $stream
     */
    public static function read($stream, int $circIdWidth = 4): self
    {
        $headerLen = $circIdWidth + 1;
        $header = self::readExact($stream, $headerLen);

        if ($circIdWidth === 2) {
            $circuitId = unpack('n', $header, 0)[1];
            $command = ord($header[2]);
        } else {
            $circuitId = unpack('N', $header, 0)[1];
            $command = ord($header[4]);
        }

        if (!Commands::isVariableLength($command)) {
            return new self($circuitId, $command, self::readExact($stream, Commands::PAYLOAD_LEN), false);
        }

        $lenBytes = self::readExact($stream, 2);
        $length = unpack('n', $lenBytes, 0)[1];
        $body = $length === 0 ? '' : self::readExact($stream, $length);

        return new self($circuitId, $command, $body, true);
    }

    /**
     * Read exactly $n bytes or fail.
     *
     * @param resource $stream
     */
    public static function readExact($stream, int $n): string
    {
        $buffer = '';
        while (strlen($buffer) < $n) {
            $chunk = fread($stream, $n - strlen($buffer));
            if ($chunk === false || $chunk === '') {
                if (feof($stream)) {
                    throw new TorConnectionException('Connection closed while reading cell data');
                }
                $meta = stream_get_meta_data($stream);
                if (!empty($meta['timed_out'])) {
                    throw new TorConnectionException('Timed out while reading cell data');
                }
                throw new TorConnectionException('Failed to read from stream');
            }
            $buffer .= $chunk;
        }

        return $buffer;
    }
}
