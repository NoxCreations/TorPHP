<?php

declare(strict_types=1);

namespace Torv3;

/**
 * Base exception for every error raised by this library.
 */
class TorException extends \RuntimeException
{
}

/**
 * Protocol-level failure: malformed cell, rejected handshake, bad digest, etc.
 */
class TorProtocolException extends TorException
{
}

/**
 * TLS/link failure talking to a relay.
 */
class TorConnectionException extends TorException
{
}

/**
 * Directory (consensus/microdescriptor) failure.
 */
class TorDirectoryException extends TorException
{
}

/**
 * Relay identity or link authentication failure.
 */
class TorNetworkException extends TorException
{
}

/**
 * Hidden service specific failure (descriptor, introduction, rendezvous).
 */
class TorOnionException extends TorException
{
}

/**
 * A stream was closed by the relay or by the remote peer (RELAY_END).
 */
class TorStreamException extends TorException
{
    public function __construct(string $message, private int $reason = 0)
    {
        parent::__construct($message);
    }

    public function getReason(): int
    {
        return $this->reason;
    }
}
