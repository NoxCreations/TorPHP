<?php

declare(strict_types=1);

namespace Torv3\Transport;

use Torv3\Circuit\Circuit;

/**
 * Adapts one Tor stream to the ByteStream interface.
 */
final class CircuitByteStream implements ByteStream
{
    public function __construct(
        private Circuit $circuit,
        private int $streamId
    ) {
    }

    public function write(string $bytes): void
    {
        $this->circuit->sendData($this->streamId, $bytes);
    }

    public function read(float $timeout): string
    {
        $data = $this->circuit->readStreamDataIfAvailable($this->streamId, max(0.01, $timeout));

        return $data ?? '';
    }

    public function close(): void
    {
        $this->circuit->closeStream($this->streamId);
    }
}
