<?php

declare(strict_types=1);

/**
 * Live smoke test against the public Tor network.
 *
 * Fetches the consensus from a directory authority, opens a TLS link to a
 * relay, creates a circuit with CREATE2/ntor, extends it with RELAY_EXTEND2
 * and makes a BEGIN_DIR request for a nonexistent microdescriptor (the HTTP
 * status proves the end-to-end relay cell path works).
 *
 * Run: php tests/live_smoke.php
 */

require __DIR__ . '/../autoload.php';

use Torv3\Circuit\Circuit;
use Torv3\Directory\DirectoryFetcher;
use Torv3\Directory\RelayInfo;
use Torv3\Link\LinkSession;

$started = microtime(true);

try {
    $directory = new DirectoryFetcher(null);
    $consensus = $directory->relays(true, 60);

    $relays = array_values(array_filter(
        $consensus['relays'],
        static fn (RelayInfo $r): bool => $r->isUsable() && $r->orPort > 0
    ));

    echo 'consensus valid-after: ' . date('c', $consensus['validAfter']) . "\n";
    echo 'relays: ' . count($consensus['relays']) . ' total, ' . count($relays) . ' usable with ntor keys' . "\n";

    if (count($relays) < 2) {
        fwrite(STDERR, "Not enough usable relays to build a circuit\n");
        exit(1);
    }

    shuffle($relays);
    $first = $relays[0];
    $second = $relays[1];

    echo 'first hop:  ' . $first->nickname . ' (' . $first->endpoint() . ')' . "\n";
    echo 'second hop: ' . $second->nickname . ' (' . $second->endpoint() . ')' . "\n";

    $link = LinkSession::connect($first->address, $first->orPort);
    $link->negotiate();
    echo 'link protocol: v' . $link->linkVersion() . ' (' . $link->circIdWidth() . '-byte circIDs)' . "\n";

    $circuit = Circuit::create($link, $first, Circuit::randomCircuitId());
    echo "CREATE2/ntor completed\n";

    $circuit->extend($second);
    echo "RELAY_EXTEND2/ntor completed (" . $circuit->hopCount() . " hops)\n";

    $streamId = $circuit->beginStream('', 0, true, 25.0);
    echo "RELAY_BEGIN_DIR connected (stream {$streamId})\n";

    $circuit->sendData(
        $streamId,
        "GET /tor/micro/d/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA HTTP/1.0\r\n"
        . "Host: relay\r\nConnection: close\r\n\r\n"
    );

    $raw = '';
    $deadline = microtime(true) + 25.0;
    while (microtime(true) < $deadline) {
        try {
            $raw .= $circuit->readStreamData($streamId, max(0.5, $deadline - microtime(true)));
        } catch (\Torv3\TorStreamException) {
            break;
        }
        if (str_contains($raw, "\r\n\r\n")) {
            break;
        }
    }

    $response = DirectoryFetcher::parseHttpResponse($raw);
    echo 'directory response: HTTP ' . $response['status'] . "\n";

    $circuit->close();

    echo 'elapsed: ' . round(microtime(true) - $started, 2) . "s\n";
    exit($response['status'] > 0 ? 0 : 1);
} catch (\Throwable $e) {
    fwrite(STDERR, 'LIVE TEST FAILED: ' . get_class($e) . ': ' . $e->getMessage() . "\n");
    exit(1);
}
