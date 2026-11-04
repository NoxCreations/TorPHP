<?php

declare(strict_types=1);

namespace Torv3\Link;

use Torv3\Cell\Cell;
use Torv3\Cell\Commands;
use Torv3\Directory\RelayIdentity;
use Torv3\TorConnectionException;
use Torv3\TorProtocolException;

/**
 * A TLS connection to a Tor relay speaking the link protocol.
 *
 * tor-spec.txt §4: VERSIONS negotiation, then CERTS/AUTH_CHALLENGE/NETINFO.
 * Relays present ephemeral self-signed certificates, so certificate
 * verification is intentionally disabled.
 */
final class LinkSession
{
    private const CONNECT_TIMEOUT = 15.0;

    /** @var resource */
    private $stream;

    private int $linkVersion = 0;

    /** Circuit-ID width: 2 bytes until the VERSIONS exchange completes. */
    private int $circIdWidth = 2;

    private string $peerAddress;
    private int $peerPort;

    /**
     * @param resource $stream
     */
    private function __construct($stream, string $address, int $port)
    {
        $this->stream = $stream;
        $this->peerAddress = $address;
        $this->peerPort = $port;
    }

    public static function connect(string $address, int $port, float $timeout = self::CONNECT_TIMEOUT): self
    {
        $context = stream_context_create([
            'ssl' => [
                'verify_peer' => false,
                'verify_peer_name' => false,
                'allow_self_signed' => true,
                'SNI_enabled' => false,
                'disable_compression' => true,
                'crypto_method' => STREAM_CRYPTO_METHOD_TLSv1_2_CLIENT | STREAM_CRYPTO_METHOD_TLSv1_3_CLIENT,
            ],
        ]);

        $errno = 0;
        $errstr = '';
        $stream = @stream_socket_client(
            'ssl://' . $address . ':' . $port,
            $errno,
            $errstr,
            $timeout,
            STREAM_CLIENT_CONNECT,
            $context
        );

        if ($stream === false) {
            throw new TorConnectionException(
                'Unable to open TLS connection to ' . $address . ':' . $port . ' (' . $errno . ': ' . $errstr . ')'
            );
        }

        stream_set_timeout($stream, (int) max(1, (int) $timeout));
        stream_set_blocking($stream, true);
        stream_set_read_buffer($stream, 0);
        stream_set_write_buffer($stream, 0);

        return new self($stream, $address, $port);
    }

    /**
     * Perform the in-protocol handshake and finish with our own NETINFO.
     */
    public function negotiate(?string $expectedRelayEd25519Id = null, float $timeout = 30.0): void
    {
        $versions = Commands::LINK_VERSIONS;
        $payload = '';
        foreach ($versions as $version) {
            $payload .= pack('n', $version);
        }

        // Pre-negotiation VERSIONS cells always use a 2-byte circuit ID of 0.
        $this->sendRaw((new Cell(0, Commands::VERSIONS, $payload, true))->encode(2));

        $peerVersions = null;
        $sawNetinfo = false;
        $certsPayload = '';
        $this->setTimeout(max(0.5, $timeout));
        $deadline = microtime(true) + $timeout;

        while (microtime(true) < $deadline) {
            $cell = Cell::read($this->stream, $this->circIdWidth);

            if ($cell->command === Commands::VERSIONS) {
                if ($peerVersions === null) {
                    $peerVersions = $this->parseVersions($cell->payload);
                    $common = array_values(array_intersect($versions, $peerVersions));
                    if ($common === []) {
                        throw new TorProtocolException('No common link protocol version with relay');
                    }
                    $this->linkVersion = max($common);
                    $this->circIdWidth = $this->linkVersion >= 4 ? 4 : 2;

                    // After negotiation every cell uses the negotiated width.
                    continue;
                }
                // Any later VERSIONS cell must be ignored.
                continue;
            }

            if ($cell->command === Commands::NETINFO) {
                $sawNetinfo = true;
                break;
            }

            if ($cell->command === Commands::CERTS) {
                $certsPayload .= $cell->payload;
                continue;
            }

            // AUTH_CHALLENGE, VPADDING and PADDING are safe to ignore:
            // clients are allowed to remain unauthenticated.
            if ($cell->command === Commands::DESTROY) {
                throw new TorConnectionException('Relay sent DESTROY during handshake');
            }
        }

        if ($this->linkVersion === 0) {
            throw new TorProtocolException('Relay did not send VERSIONS');
        }
        if (!$sawNetinfo) {
            throw new TorProtocolException('Relay did not send NETINFO');
        }

        if ($expectedRelayEd25519Id !== null) {
            if ($certsPayload === '') {
                throw new TorProtocolException('Relay did not present link certificates');
            }
            if (!RelayIdentity::verifyLinkCerts($certsPayload, $expectedRelayEd25519Id)) {
                throw new TorProtocolException('Relay link certificate is not signed by the expected identity');
            }
        }

        $this->sendNetinfo();
    }

    /**
     * Send our NETINFO cell: timestamp, our address, and no known peers.
     */
    private function sendNetinfo(): void
    {
        $timestamp = pack('N', time() & 0xFFFFFFFF);
        // tor-spec §4.5: OTHERADDR is ATYPE (0x04 IPv4, 0x06 IPv6), then
        // ALEN, then the address in network byte order.
        $ipv6 = $this->isIpv6($this->peerAddress);
        $type = $ipv6 ? "\x06" : "\x04";
        $length = $ipv6 ? 16 : 4;
        $ourAddress = inet_pton($ipv6 ? '::' : '0.0.0.0');
        $payload = $timestamp . $type . chr($length)
            . ($ourAddress === false ? str_repeat("\x00", $length) : $ourAddress)
            . chr(0);

        $this->sendCell(Cell::fixed(0, Commands::NETINFO, $payload));
    }

    /**
     * @return int[]
     */
    private function parseVersions(string $payload): array
    {
        if (strlen($payload) % 2 !== 0) {
            throw new TorProtocolException('Malformed VERSIONS cell (odd length)');
        }

        $versions = [];
        for ($i = 0; $i < strlen($payload); $i += 2) {
            $versions[] = unpack('n', $payload, $i)[1];
        }

        return $versions;
    }

    private function isIpv6(string $address): bool
    {
        return strpos($address, ':') !== false;
    }

    public function sendCell(Cell $cell): void
    {
        $this->sendRaw($cell->encode($this->circIdWidth));
    }

    public function sendRaw(string $bytes): void
    {
        $total = strlen($bytes);
        $written = 0;

        while ($written < $total) {
            $chunk = fwrite($this->stream, substr($bytes, $written));
            if ($chunk === false || $chunk === 0) {
                throw new TorConnectionException('Failed to write to relay connection');
            }
            $written += $chunk;
        }

        fflush($this->stream);
    }

    public function readCell(): Cell
    {
        return Cell::read($this->stream, $this->circIdWidth);
    }

    public function linkVersion(): int
    {
        return $this->linkVersion;
    }

    public function circIdWidth(): int
    {
        return $this->circIdWidth;
    }

    public function peerAddress(): string
    {
        return $this->peerAddress;
    }

    public function peerPort(): int
    {
        return $this->peerPort;
    }

    public function setTimeout(float $seconds): void
    {
        stream_set_timeout($this->stream, (int) floor($seconds), (int) (($seconds - floor($seconds)) * 1_000_000));
    }

    public function isAlive(): bool
    {
        return is_resource($this->stream) && !feof($this->stream);
    }

    public function close(): void
    {
        if (is_resource($this->stream)) {
            @fclose($this->stream);
        }
    }

    public function __destruct()
    {
        $this->close();
    }
}
