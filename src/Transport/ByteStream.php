<?php

declare(strict_types=1);

namespace Torv3\Transport;

/**
 * A bidirectional byte stream. Reads return an empty string when the timeout
 * expires and throw TorStreamException when the peer closes the connection.
 */
interface ByteStream
{
    public function write(string $bytes): void;

    public function read(float $timeout): string;

    public function close(): void;
}
