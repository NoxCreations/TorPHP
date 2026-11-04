<?php

declare(strict_types=1);

/**
 * Circuit stream-layer test: drives Circuit through a loopback TCP socket
 * using the real relay-cell crypto, so no relay or network is required.
 *
 * Run: php tests/stream_test.php
 */

require __DIR__ . '/../autoload.php';

use Torv3\Cell\Cell;
use Torv3\Cell\Commands;
use Torv3\Cell\RelayCell;
use Torv3\Circuit\Circuit;
use Torv3\Circuit\CircuitLayer;
use Torv3\Directory\RelayInfo;
use Torv3\Link\LinkSession;
use Torv3\TorStreamException;

$failures = 0;

function expect(string $name, bool $ok, string $detail = ''): void
{
    global $failures;
    if ($ok) {
        echo "  PASS  {$name}\n";
    } else {
        $failures++;
        echo "  FAIL  {$name}" . ($detail !== '' ? " ({$detail})" : '') . "\n";
    }
}

/**
 * @return array{0: resource, 1: resource}
 */
function tcpPair(): array
{
    $server = stream_socket_server('tcp://127.0.0.1:0', $errno, $errstr);
    if ($server === false) {
        throw new RuntimeException('Cannot open loopback listener: ' . $errstr);
    }
    $name = (string) stream_socket_get_name($server, false);
    $client = stream_socket_client('tcp://' . $name, $e2, $m2, 2.0);
    $peer = stream_socket_accept($server, 2.0);
    if ($client === false || $peer === false) {
        throw new RuntimeException('Cannot establish loopback connection');
    }

    return [$client, $peer];
}

/**
 * @param resource $stream
 */
function linkFor($stream): LinkSession
{
    $rc = new ReflectionClass(LinkSession::class);
    $link = $rc->newInstanceWithoutConstructor();
    foreach (['stream' => $stream, 'circIdWidth' => 4, 'linkVersion' => 4,
        'peerAddress' => '127.0.0.1', 'peerPort' => 9001] as $name => $value) {
        $rc->getProperty($name)->setValue($link, $value);
    }

    return $link;
}

/**
 * @param CircuitLayer[] $layers
 * @param RelayInfo[] $hops
 */
function circuitFor(LinkSession $link, int $circId, array $layers, array $hops): Circuit
{
    $rc = new ReflectionClass(Circuit::class);
    $circuit = $rc->newInstanceWithoutConstructor();
    foreach (['link' => $link, 'circuitId' => $circId, 'layers' => $layers, 'hops' => $hops] as $name => $value) {
        $rc->getProperty($name)->setValue($circuit, $value);
    }

    return $circuit;
}

function makeHop(): RelayInfo
{
    return new RelayInfo(
        'mock',
        str_repeat('A', 40),
        random_bytes(20),
        '127.0.0.1',
        9001,
        0,
        ['Fast', 'Running'],
        random_bytes(32),
        random_bytes(32)
    );
}

/**
 * @param array{0: string, 1: string} $keys
 */
function mockPair(): array
{
    $df = random_bytes(20);
    $db = random_bytes(20);
    $kf = random_bytes(16);
    $kb = random_bytes(16);

    return [
        new CircuitLayer($df, $db, $kf, $kb, 'sha1'),
        // Relay-to-client direction uses our Db as its forward digest seed
        // and our Kb as its forward cipher key.
        new CircuitLayer($db, $df, $kb, $kb, 'sha1'),
    ];
}

function relayWire(CircuitLayer $peer, int $circId, int $relayCommand, string $data, int $streamId): string
{
    $payload = $peer->setDigest(RelayCell::build($relayCommand, $streamId, $data));
    $payload = $peer->encrypt($payload);

    return Cell::fixed($circId, Commands::RELAY, $payload)->encode(4);
}

echo "Stream layer\n------------\n";

// 1. beginStream() must observe RELAY_CONNECTED.
[$client, $peerStream] = tcpPair();
[$clientLayer, $peerLayer] = mockPair();
$circuitId = 0x80000101;
$circuit = circuitFor(linkFor($client), $circuitId, [$clientLayer], [makeHop()]);
fwrite($peerStream, relayWire($peerLayer, $circuitId, Commands::RELAY_CONNECTED, '', 1));
$streamId = $circuit->beginStream('example.com', 80, false, 2.0);
expect('beginStream returns the stream id after CONNECTED', $streamId === 1, (string) $streamId);

// 2. RELAY_END must reach readStreamData() with its reason code.
fwrite($peerStream, relayWire($peerLayer, $circuitId, Commands::RELAY_END, chr(6), 1));
$reason = null;
try {
    $circuit->readStreamData(1, 2.0);
} catch (TorStreamException $e) {
    $reason = $e->getReason();
}
expect('readStreamData reports the END reason', $reason === 6, (string) $reason);

// 3. A silent relay must time out, not hang.
[$client2, $peerStream2] = tcpPair();
[$clientLayer2, ] = mockPair();
$circuit2 = circuitFor(linkFor($client2), 0x80000102, [$clientLayer2], [makeHop()]);
$started = microtime(true);
$event = $circuit2->nextStreamEvent(1, 0.5);
$elapsed = microtime(true) - $started;
expect('nextStreamEvent honours its timeout', $event === null && $elapsed < 3.0, sprintf('%.2fs', $elapsed));

// 4. DATA is delivered and the SENDME tag comes from the rolling digest.
[$client3, $peerStream3] = tcpPair();
[$clientLayer3, $peerLayer3] = mockPair();
$circuitId3 = 0x80000103;
$circuit3 = circuitFor(linkFor($client3), $circuitId3, [$clientLayer3], [makeHop()]);
fwrite($peerStream3, relayWire($peerLayer3, $circuitId3, Commands::RELAY_DATA, 'hello', 7));
expect('readStreamData returns payload bytes', $circuit3->readStreamData(7, 2.0) === 'hello');
expect('SENDME tag is the layer rolling digest', strlen($clientLayer3->inboundSendmeTag()) === 20);

// 5. Fifty inbound DATA cells must produce a stream SENDME carrying a
//    20-byte rolling-digest tag, and the tag must verify at the relay.
[$client5, $peer5] = tcpPair();
$df5 = random_bytes(20);
$db5 = random_bytes(20);
$kf5 = random_bytes(16);
$kb5 = random_bytes(16);
$clientLayer5 = new CircuitLayer($df5, $db5, $kf5, $kb5, 'sha1');
$inboundLayer5 = new CircuitLayer($db5, $df5, $kb5, $kb5, 'sha1');
$outboundLayer5 = new CircuitLayer($df5, $df5, $kf5, $kf5, 'sha1');
$circuitId5 = 0x80000104;
$circuit5 = circuitFor(linkFor($client5), $circuitId5, [$clientLayer5], [makeHop()]);

$batch = '';
for ($i = 0; $i < 50; $i++) {
    $batch .= relayWire($inboundLayer5, $circuitId5, Commands::RELAY_DATA, 'x', 9);
}
fwrite($peer5, $batch);

for ($i = 0; $i < 50; $i++) {
    $circuit5->readStreamData(9, 2.0);
}

$sendmeCell = Cell::read($peer5, 4);
$decrypted = $outboundLayer5->decrypt($sendmeCell->payload);
$digestOk = $outboundLayer5->verifyDigest($decrypted);
expect('50 DATA cells trigger a RELAY_SENDME', $sendmeCell->command === Commands::RELAY && ord($decrypted[0]) === Commands::RELAY_SENDME);
expect(
    'stream SENDME carries a 20-byte tag',
    unpack('n', $decrypted, 9)[1] === 23 && unpack('n', $decrypted, 12)[1] === 20
);
expect('stream SENDME tag matches the rolling digest', $digestOk);

echo $failures === 0 ? "\nAll stream checks passed.\n" : "\n{$failures} stream check(s) failed.\n";
exit($failures === 0 ? 0 : 1);
