<?php

declare(strict_types=1);

namespace Torv3\Circuit;

use Torv3\Cell\Cell;
use Torv3\Cell\Commands;
use Torv3\Cell\RelayCell;
use Torv3\Crypto\NtorHandshake;
use Torv3\Directory\RelayInfo;
use Torv3\Link\LinkSession;
use Torv3\TorException;
use Torv3\TorProtocolException;
use Torv3\TorStreamException;

/**
 * An origin circuit: a chain of hops with one relay-crypto layer each,
 * plus (for hidden services) an extra end-to-end layer created by hs-ntor.
 *
 * tor-spec.txt §5 (circuits), §6 (relay cells), §7 (flow control).
 */
final class Circuit
{
    private LinkSession $link;
    private int $circuitId;

    /** @var CircuitLayer[] outermost (first hop) to innermost */
    private array $layers = [];

    /** @var RelayInfo[] */
    private array $hops = [];

    private int $relayEarlyCount = 0;

    private int $nextStreamId = 1;

    /** @var array<int, bool> */
    private array $connected = [];

    /** @var array<int, string[]> queued payloads per stream */

    /** @var array<int, array{cmd: int, data: string}> queued non-DATA events per stream */
    private array $pendingEvents = [];

    /** @var array<int, int> outbound package window per hop index */
    private array $packageWindow = [];

    /** @var array<int, int> inbound deliver window per hop index */
    private array $deliverWindow = [];

    /** @var array<int, int> DATA cells received per hop index */
    private array $receivedData = [];

    /** @var array<int, int> DATA cells received per stream */
    private array $streamReceivedData = [];

    /** @var array<int, string> SENDME tag of the last inbound DATA cell per stream */
    private array $streamSendmeTag = [];

    /** @var array<int, string[]> per-hop FIFO of SENDME tags for unacknowledged DATA cells */
    private array $sentDataDigests = [];

    /** @var array<int, int> outbound stream package window per stream id */
    private array $streamPackageWindow = [];

    /** @var array<int, string[]> per-stream FIFO of SENDME tags for unacknowledged DATA cells */
    private array $sentStreamDigests = [];

    private bool $closed = false;

    private function __construct(LinkSession $link, int $circuitId)
    {
        $this->link = $link;
        $this->circuitId = $circuitId;
    }

    /**
     * Create a one-hop circuit with CREATE2/ntor and return it.
     */
    public static function create(LinkSession $link, RelayInfo $firstHop, ?int $circuitId = null, float $timeout = 20.0): self
    {
        if (!$firstHop->canExtend() || strlen($firstHop->identityDigest) !== 20) {
            throw new TorProtocolException('First hop is missing an ntor onion key or identity digest');
        }

        $circuitId ??= self::randomCircuitId();
        $circuit = new self($link, $circuitId);

        $keypair = NtorHandshake::generateKeypair();
        $onionSkin = NtorHandshake::clientOnionSkin(
            $firstHop->identityDigest,
            $firstHop->ntorOnionKey,
            $keypair['public']
        );

        $payload = pack('n', Commands::NTOR_HTYPE) . pack('n', strlen($onionSkin)) . $onionSkin;
        $link->sendCell(Cell::fixed($circuitId, Commands::CREATE2, $payload));

        $cell = $circuit->readCircuitCell(Commands::CREATED2, $timeout);

        $hlen = unpack('n', $cell->payload, 0)[1];
        if ($hlen !== 64 || strlen($cell->payload) < 2 + 64) {
            throw new TorProtocolException('Malformed CREATED2 payload');
        }

        $serverPublic = substr($cell->payload, 2, 32);
        $auth = substr($cell->payload, 34, 32);

        $keys = NtorHandshake::clientComputeKeys(
            $firstHop->identityDigest,
            $firstHop->ntorOnionKey,
            $keypair['private'],
            $keypair['public'],
            $serverPublic,
            $auth
        );

        $circuit->layers[] = new CircuitLayer($keys['df'], $keys['db'], $keys['kf'], $keys['kb'], 'sha1');
        $circuit->hops[] = $firstHop;
        $circuit->initWindows();

        return $circuit;
    }

    /**
     * Extend the circuit one hop further using RELAY_EXTEND2 over RELAY_EARLY.
     */
    public function extend(RelayInfo $hop, float $timeout = 20.0): void
    {
        if (!$hop->canExtend() || strlen($hop->identityDigest) !== 20) {
            throw new TorProtocolException('Cannot extend to ' . $hop->nickname . ': missing ntor key');
        }
        if ($this->relayEarlyCount >= Commands::MAX_RELAY_EARLY) {
            throw new TorProtocolException('RELAY_EARLY limit reached on this circuit');
        }

        $keypair = NtorHandshake::generateKeypair();
        $handshake = NtorHandshake::clientOnionSkin($hop->identityDigest, $hop->ntorOnionKey, $keypair['public']);

        // NSPEC(1) | [LSTYPE(1) | LSLEN(1) | LSPEC] | HTYPE(2) | HLEN(2) | HANDSHAKE
        $specs = '';
        $ip = inet_pton($hop->address);
        if ($ip !== false && strlen($ip) === 4) {
            // LSTYPE 0: TLS-over-TCP IPv4 address + ORPort (tor-spec.txt §5.1.2).
            $specs .= chr(0x00) . chr(6) . $ip . pack('n', $hop->orPort);
        } elseif ($ip !== false && strlen($ip) === 16) {
            // LSTYPE 4: IPv6 address + ORPort.
            $specs .= chr(0x04) . chr(18) . $ip . pack('n', $hop->orPort);
        }
        $specs .= chr(0x02) . chr(20) . $hop->identityDigest;             // legacy identity
        if ($hop->ed25519Id !== null) {
            $specs .= chr(0x03) . chr(32) . $hop->ed25519Id;              // ed25519 identity
        }

        $payload = chr($hop->ed25519Id !== null ? 3 : 2) . $specs
            . pack('n', Commands::NTOR_HTYPE)
            . pack('n', strlen($handshake))
            . $handshake;

        $this->sendRelay(Commands::RELAY_EXTEND2, 0, $payload, count($this->layers) - 1, true);

        $reply = $this->waitForRelay(Commands::RELAY_EXTENDED2, $timeout);
        $data = $reply['data'];

        if (strlen($data) < 2) {
            throw new TorProtocolException('Malformed RELAY_EXTENDED2 payload');
        }

        // tor-spec.txt §5.1.2: an EXTENDED2 payload is identical to a CREATED2
        // payload, i.e. HLEN [2 bytes] followed by the handshake reply.
        $hlen = unpack('n', $data, 0)[1];
        if ($hlen !== 64 || strlen($data) < 2 + 64) {
            throw new TorProtocolException(sprintf(
                'Unexpected EXTENDED2 handshake: length=%d payload=%d bytes (%s)',
                $hlen,
                strlen($data),
                bin2hex(substr($data, 0, 12))
            ));
        }

        $serverPublic = substr($data, 2, 32);
        $auth = substr($data, 34, 32);

        $keys = NtorHandshake::clientComputeKeys(
            $hop->identityDigest,
            $hop->ntorOnionKey,
            $keypair['private'],
            $keypair['public'],
            $serverPublic,
            $auth
        );

        $this->layers[] = new CircuitLayer($keys['df'], $keys['db'], $keys['kf'], $keys['kb'], 'sha1');
        $this->hops[] = $hop;
        $this->initWindows();
    }

    /**
     * Append the end-to-end hidden service layer derived by hs-ntor.
     * This layer uses AES-256 and SHA3-256 (rend-spec-v3 §3.3.2, §5).
     */
    public function addRendezvousLayer(string $df, string $db, string $kf, string $kb): void
    {
        $this->layers[] = new CircuitLayer($df, $db, $kf, $kb, 'sha3-256');
        $this->hops[] = $this->hops[count($this->hops) - 1];
        $this->initWindows();
    }

    private function initWindows(): void
    {
        $index = count($this->layers) - 1;
        $this->packageWindow[$index] = Commands::CIRCWINDOW_START;
        $this->deliverWindow[$index] = Commands::CIRCWINDOW_START;
        $this->receivedData[$index] = 0;
    }

    /**
     * Open a stream (RELAY_BEGIN / RELAY_BEGIN_DIR) and wait for CONNECTED.
     */
    public function beginStream(string $host, int $port, bool $beginDir = false, float $timeout = 15.0): int
    {
        $streamId = $this->nextStreamId++;

        if ($beginDir) {
            $this->sendRelay(Commands::RELAY_BEGIN_DIR, $streamId, '', count($this->layers) - 1);
        } else {
            $payload = $host . ':' . $port . "\x00";
            $this->sendRelay(Commands::RELAY_BEGIN, $streamId, $payload, count($this->layers) - 1);
        }

        $deadline = microtime(true) + $timeout;
        while (microtime(true) < $deadline) {
            $event = $this->nextStreamEvent($streamId, $deadline - microtime(true));
            if ($event === null) {
                break;
            }

            if ($event['cmd'] === Commands::RELAY_CONNECTED) {
                $this->connected[$streamId] = true;

                return $streamId;
            }

            if ($event['cmd'] === Commands::RELAY_END) {
                throw new TorStreamException(
                    'Relay refused the stream to ' . $host . ':' . $port,
                    strlen($event['data']) > 0 ? ord($event['data'][0]) : 0
                );
            }
        }

        throw new TorStreamException('Timed out waiting for RELAY_CONNECTED from ' . $host . ':' . $port);
    }

    /**
     * Send stream data, respecting the circuit package window.
     */
    public function sendData(int $streamId, string $data): void
    {
        $offset = 0;
        $length = strlen($data);

        while ($offset < $length) {
            $chunk = substr($data, $offset, RelayCell::MAX_DATA);
            $offset += strlen($chunk);

            $hop = count($this->layers) - 1;
            $this->maybeWaitForPackageWindow($hop);
            $this->maybeWaitForStreamWindow($streamId);
            $this->packageWindow[$hop]--;
            $this->streamPackageWindow[$streamId] = ($this->streamPackageWindow[$streamId]
                ?? Commands::STREAMWINDOW_START) - 1;

            $this->sendRelay(Commands::RELAY_DATA, $streamId, $chunk, $hop);
            $tag = $this->layers[$hop]->outboundSendmeTag();
            $this->sentDataDigests[$hop][] = $tag;
            $this->sentStreamDigests[$streamId][] = $tag;
        }
    }

    /**
     * Block until the hop's package window has room again.
     */
    private function maybeWaitForPackageWindow(int $hop): void
    {
        $deadline = microtime(true) + 30.0;

        while (($this->packageWindow[$hop] ?? Commands::CIRCWINDOW_START) <= 0) {
            $remaining = $deadline - microtime(true);
            if ($remaining <= 0) {
                throw new TorException('Timed out waiting for a circuit SENDME from hop ' . $hop);
            }

            $relay = $this->receiveRelayCell($remaining);
            if ($relay === null) {
                continue;
            }

            $this->dispatch($relay);
        }
    }

    /**
     * Block until the stream package window has room again.
     */
    private function maybeWaitForStreamWindow(int $streamId): void
    {
        $deadline = microtime(true) + 30.0;

        while (($this->streamPackageWindow[$streamId] ?? Commands::STREAMWINDOW_START) <= 0) {
            $remaining = $deadline - microtime(true);
            if ($remaining <= 0) {
                throw new TorException('Timed out waiting for a stream SENDME on stream ' . $streamId);
            }

            $relay = $this->receiveRelayCell($remaining);
            if ($relay === null) {
                continue;
            }

            $this->dispatch($relay);
        }
    }

    /**
     * Read up to one relay cell of stream data.
     *
     * @return array{cmd: int, data: string}
     */
    public function nextStreamEvent(int $streamId, float $timeout = 15.0): ?array
    {
        $deadline = microtime(true) + $timeout;

        while (true) {
            // Events (CONNECTED, DATA, END, ...) are queued in arrival order so
            // a body received before END is never masked by the END.
            if (!empty($this->pendingEvents[$streamId])) {
                /** @var array{cmd: int, data: string} $event */
                $event = array_shift($this->pendingEvents[$streamId]);

                return $event;
            }

            $remaining = $deadline - microtime(true);
            if ($remaining <= 0) {
                return null;
            }

            try {
                $relay = $this->receiveRelayCell($remaining);
            } catch (TorProtocolException $e) {
                throw $e;
            } catch (TorException $e) {
                return null;
            }

            if ($relay === null) {
                return null;
            }

            // CONNECTED/END/other edge cells must be queued for the stream;
            // DATA and SENDME are already consumed by receiveRelayCell().
            $this->dispatch($relay);
        }
    }

    /**
     * Read data for a stream until at least one byte is available.
     */
    public function readStreamData(int $streamId, float $timeout = 15.0): string
    {
        $data = $this->readStreamDataIfAvailable($streamId, $timeout);

        if ($data === null) {
            throw new TorStreamException('Timed out reading stream ' . $streamId);
        }

        return $data;
    }

    /**
     * Read up to one relay cell of stream data, returning null on timeout.
     * A remote END still raises TorStreamException.
     */
    public function readStreamDataIfAvailable(int $streamId, float $timeout = 15.0): ?string
    {
        $event = $this->nextStreamEvent($streamId, $timeout);

        if ($event === null) {
            return null;
        }

        if ($event['cmd'] === Commands::RELAY_END) {
            throw new TorStreamException(
                'Stream closed by the remote host',
                strlen($event['data']) > 0 ? ord($event['data'][0]) : 0
            );
        }

        if ($event['cmd'] !== Commands::RELAY_DATA) {
            return '';
        }

        return $event['data'];
    }

    /**
     * Close a stream gracefully.
     */
    public function closeStream(int $streamId): void
    {
        if (isset($this->connected[$streamId])) {
            try {
                $this->sendRelay(Commands::RELAY_END, $streamId, chr(0), count($this->layers) - 1);
            } catch (TorException) {
                // Circuit likely already gone.
            }
        }
        unset(
            $this->connected[$streamId],
            $this->pendingEvents[$streamId],
            $this->streamPackageWindow[$streamId],
            $this->sentStreamDigests[$streamId],
            $this->streamReceivedData[$streamId],
            $this->streamSendmeTag[$streamId]
        );
    }

    /**
     * Send a relay command to a specific hop, sealing it through that hop's
     * layer and every layer outside it.
     */
    public function sendRelay(int $command, int $streamId, string $data, ?int $hop = null, bool $early = false): void
    {
        if ($this->closed) {
            throw new TorException('Circuit is closed');
        }

        $hop ??= count($this->layers) - 1;
        if (!isset($this->layers[$hop])) {
            throw new TorProtocolException('No such hop ' . $hop . ' on circuit');
        }

        $payload = RelayCell::build($command, $streamId, $data);

        // Seal from the innermost hop outward: the target hop's digest and
        // encryption are applied first, then every layer outside it. This way
        // each relay's decryption reveals the next layer's ciphertext, which
        // is what makes multi-hop cells work (tor-spec.txt §5.5.2).
        for ($i = $hop; $i >= 0; $i--) {
            if ($i === $hop) {
                $payload = $this->layers[$i]->setDigest($payload);
            }
            $payload = $this->layers[$i]->encrypt($payload);
        }

        // tor-spec.txt §5.1.1: RELAY_EARLY is used for EXTEND/EXTEND2 and for
        // every cell not addressed to the first hop, while the 8-cell budget
        // lasts (Tor's relay.c `remaining_relay_early_cells`).
        $isExtend = $command === Commands::RELAY_EXTEND2 || $command === Commands::RELAY_EXTEND;
        $cellCommand = Commands::RELAY;
        // RELAY_EARLY is reserved for circuit extension; stream and control
        // cells must be plain RELAY even when addressed to the last hop.
        if (($early || $isExtend) && $this->relayEarlyCount < Commands::MAX_RELAY_EARLY) {
            $this->relayEarlyCount++;
            $cellCommand = Commands::RELAY_EARLY;
        }

        $this->link->sendCell(Cell::fixed($this->circuitId, $cellCommand, $payload));
    }

    /**
     * Read a specific relay command from the innermost hop, used for circuit
     * setup replies (EXTENDED2) and hidden service control cells.
     *
     * @return array{cmd: int, streamId: int, data: string, hop: int}
     */
    public function waitForRelay(int $expectedCommand, float $timeout = 15.0): array
    {
        $deadline = microtime(true) + $timeout;

        while (microtime(true) < $deadline) {
            $relay = $this->receiveRelayCell($deadline - microtime(true));
            if ($relay === null) {
                break;
            }
            if ($relay['cmd'] === $expectedCommand) {
                return $relay;
            }
            $this->dispatch($relay);
        }

        throw new TorException('Timed out waiting for relay command ' . $expectedCommand);
    }

    /**
     * Read and decrypt one relay cell, handling circuit control cells.
     *
     * @return array{cmd: int, streamId: int, data: string, hop: int}|null
     */
    public function receiveRelayCell(float $timeout = 15.0): ?array
    {
        $deadline = microtime(true) + $timeout;

        while (microtime(true) < $deadline) {
            $this->link->setTimeout(max(0.1, $deadline - microtime(true)));

            try {
                $cell = $this->link->readCell();
            } catch (TorException $e) {
                if (microtime(true) >= $deadline) {
                    return null;
                }
                throw $e;
            }

            if ($cell->circuitId !== $this->circuitId) {
                // Not ours: ignore (a real client multiplexes circuits here).
                continue;
            }

            if ($cell->command === Commands::PADDING || $cell->command === Commands::VPADDING) {
                continue;
            }

            if ($cell->command === Commands::DESTROY) {
                $this->closed = true;
                $reason = $cell->payload === '' ? 0 : ord($cell->payload[0]);
                throw new TorException('Circuit destroyed by the network (reason ' . $reason . ')');
            }

            if ($cell->command !== Commands::RELAY && $cell->command !== Commands::RELAY_EARLY) {
                continue;
            }

            $relay = $this->peelRelayCell($cell->payload);
            if ($relay === null) {
                continue; // not addressed to us / digest mismatch
            }

            if ($relay['cmd'] === Commands::RELAY_SENDME) {
                $this->handleSendme($relay, $cell->payload);
                continue;
            }

            if ($relay['cmd'] === Commands::RELAY_DATA) {
                $this->handleInboundData($relay, $cell->payload);
            }

            if ($relay['cmd'] === Commands::RELAY_DROP) {
                continue;
            }

            return $relay;
        }

        return null;
    }

    /**
     * Apply backward decryption layer by layer until a layer's digest matches.
     *
     * @return array{cmd: int, streamId: int, data: string, hop: int}|null
     */
    private function peelRelayCell(string $payload): ?array
    {
        $raw = $payload;

        foreach ($this->layers as $index => $layer) {
            $raw = $layer->decrypt($raw);

            if (!isset($this->hops[$index])) {
                continue;
            }

            $recognized = RelayCell::recognized($raw);
            $matches = $layer->verifyDigest($raw);

            if ($recognized === 0 && $matches) {
                $length = RelayCell::length($raw);
                if ($length > RelayCell::MAX_DATA) {
                    throw new TorProtocolException('Relay cell announces an oversized payload');
                }

                return [
                    'cmd' => RelayCell::command($raw),
                    'streamId' => RelayCell::streamId($raw),
                    'data' => RelayCell::data($raw),
                    'hop' => $index,
                ];
            }
        }

        return null;
    }

    /**
     * Track inbound DATA cells and emit circuit-level SENDMEs.
     */
    private function handleInboundData(array $relay, string $rawPayload): void
    {
        $hop = $relay['hop'];
        $streamId = $relay['streamId'];

        $this->deliverWindow[$hop] = ($this->deliverWindow[$hop] ?? 0) - 1;
        $this->receivedData[$hop] = ($this->receivedData[$hop] ?? 0) + 1;
        $this->streamReceivedData[$streamId] = ($this->streamReceivedData[$streamId] ?? 0) + 1;
        $this->streamSendmeTag[$streamId] = $this->layers[$hop]->inboundSendmeTag();

        if (($this->streamReceivedData[$streamId] % Commands::STREAMWINDOW_INCREMENT) === 0) {
            $this->sendRelay(
                Commands::RELAY_SENDME,
                $streamId,
                self::sendmePayload($this->streamSendmeTag[$streamId]),
                $hop
            );
        }

        if (($this->receivedData[$hop] % Commands::CIRCWINDOW_INCREMENT) === 0) {
            $this->sendRelay(
                Commands::RELAY_SENDME,
                0,
                self::sendmePayload($this->layers[$hop]->inboundSendmeTag()),
                $hop
            );
            $this->deliverWindow[$hop] += Commands::CIRCWINDOW_INCREMENT;
        }

        $this->pendingEvents[$streamId][] = ['cmd' => $relay['cmd'], 'data' => $relay['data']];
    }

    /**
     * Authenticated SENDME v1 payload (proposal 289):
     * VERSION(1)=0x01 | TAG_LEN(2)=20 | TAG(20).
     *
     * The tag is the hop's rolling relay digest of the cell that triggered the
     * SENDME, truncated to 20 bytes (Tor's SENDME_TAG_LEN_TOR1).
     */
    public static function sendmePayload(string $tag): string
    {
        if (strlen($tag) !== CircuitLayer::SENDME_TAG_LEN) {
            throw new TorProtocolException('SENDME tag must be ' . CircuitLayer::SENDME_TAG_LEN . ' bytes');
        }

        return "\x01" . pack('n', strlen($tag)) . $tag;
    }

    /**
     * A RELAY_SENDME from a hop replenishes our package window for that hop.
     */
    private function handleSendme(array $relay, string $rawPayload): void
    {
        $hop = $relay['hop'];
        $streamId = $relay['streamId'];
        $data = $relay['data'];

        if (strlen($data) < 3 || ord($data[0]) !== 1) {
            throw new TorProtocolException('Malformed SENDME cell from hop ' . $hop);
        }

        $length = unpack('n', $data, 1)[1];
        if ($length !== CircuitLayer::SENDME_TAG_LEN || strlen($data) < 3 + $length) {
            throw new TorProtocolException('Unexpected SENDME tag length from hop ' . $hop);
        }

        $tag = substr($data, 3, $length);

        if ($streamId !== 0) {
            $queue = $this->sentStreamDigests[$streamId] ?? [];
            if ($queue !== []) {
                $index = min(count($queue), Commands::STREAMWINDOW_INCREMENT) - 1;
                if (!hash_equals($queue[$index], $tag)) {
                    throw new TorProtocolException('Stream SENDME tag mismatch on stream ' . $streamId);
                }
                array_splice($this->sentStreamDigests[$streamId], 0, $index + 1);
            }

            $this->streamPackageWindow[$streamId] = ($this->streamPackageWindow[$streamId]
                ?? Commands::STREAMWINDOW_START) + Commands::STREAMWINDOW_INCREMENT;

            return;
        }

        $queue = $this->sentDataDigests[$hop] ?? [];
        if ($queue === []) {
            throw new TorProtocolException('Circuit SENDME from hop ' . $hop . ' acknowledges no data');
        }

        // A circuit SENDME acknowledges CIRCWINDOW_INCREMENT DATA cells; the
        // tag is that of the last of them.
        $index = min(count($queue), Commands::CIRCWINDOW_INCREMENT) - 1;
        if (!hash_equals($queue[$index], $tag)) {
            throw new TorProtocolException('SENDME tag mismatch from hop ' . $hop);
        }

        array_splice($this->sentDataDigests[$hop], 0, $index + 1);
        $this->packageWindow[$hop] = ($this->packageWindow[$hop] ?? Commands::CIRCWINDOW_START)
            + Commands::CIRCWINDOW_INCREMENT;
    }

    /**
     * Route a relay cell that the caller did not ask for.
     */
    private function dispatch(array $relay): void
    {
        // DATA and SENDME cells have already been consumed by the routing
        // helpers; every other edge/control cell is queued for its stream.
        if ($relay['cmd'] === Commands::RELAY_DATA || $relay['cmd'] === Commands::RELAY_SENDME) {
            return;
        }

        $this->pendingEvents[$relay['streamId']][] = ['cmd' => $relay['cmd'], 'data' => $relay['data']];
    }

    /**
     * Read the next link cell addressed to this circuit.
     */
    private function readCircuitCell(int $expectedCommand, float $timeout): Cell
    {
        $deadline = microtime(true) + $timeout;

        while (microtime(true) < $deadline) {
            $this->link->setTimeout(max(0.1, $deadline - microtime(true)));
            $cell = $this->link->readCell();
            if ($cell->circuitId !== $this->circuitId) {
                continue;
            }
            if ($cell->command === $expectedCommand) {
                return $cell;
            }
            if ($cell->command === Commands::DESTROY) {
                throw new TorException('Relay destroyed the circuit during creation');
            }
        }

        throw new TorException('Timed out waiting for cell command ' . $expectedCommand);
    }

    public function circuitId(): int
    {
        return $this->circuitId;
    }

    public function hopCount(): int
    {
        return count($this->layers);
    }

    public function lastHop(): ?RelayInfo
    {
        return $this->hops[count($this->hops) - 1] ?? null;
    }

    public function link(): LinkSession
    {
        return $this->link;
    }

    /**
     * Destroy the circuit. The link is closed only when this circuit owns it,
     * so a future multiplexed link is not torn down by one circuit.
     */
    public function close(bool $closeLink = true): void
    {
        if (!$this->closed) {
            $this->closed = true;
            try {
                $this->link->sendCell(Cell::fixed($this->circuitId, Commands::DESTROY, "\x00"));
            } catch (TorException) {
                // ignore
            }
        }

        if ($closeLink) {
            $this->link->close();
        }
    }

    /**
     * Circuit IDs are 4-byte values with the high bit set.
     */
    public static function randomCircuitId(): int
    {
        return 0x80000000 | random_int(1, 0x7FFFFFFF);
    }
}
