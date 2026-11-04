<?php

declare(strict_types=1);

namespace Torv3\Transport;

use Torv3\TorNetworkException;
use Torv3\TorStreamException;

/**
 * TLS 1.2/1.3 over an arbitrary byte transport.
 *
 * PHP can only run its OpenSSL handshake on a socket stream, so a loopback
 * socket pair is used as the TLS endpoint: OpenSSL reads and writes on one
 * end while every byte is pumped to and from the Tor stream on the other.
 * Certificate and hostname verification always use the requested host, and
 * the system CA store unless a caller supplies an explicit cafile.
 */
final class TlsStream
{
    /** @var resource */
    private $client;

    /** @var resource */
    private $peer;

    /**
     * @param resource $client
     * @param resource $peer
     */
    private function __construct(
        private ByteStream $transport,
        $client,
        $peer,
        private string $host,
        private float $timeout
    ) {
        $this->client = $client;
        $this->peer = $peer;
    }

    /**
     * @param array<string, mixed> $sslOptions Extra SSL context options.
     */
    public static function connect(
        ByteStream $transport,
        string $host,
        array $sslOptions = [],
        float $timeout = 15.0
    ): self {
        // A loopback TCP pair, rather than stream_socket_pair(), because the
        // latter's streams do not expose the OpenSSL set_option handler.
        $errno = 0;
        $errstr = '';
        $listener = @stream_socket_server('tcp://127.0.0.1:0', $errno, $errstr);
        if ($listener === false) {
            throw new TorNetworkException('Cannot create the local TLS endpoint: ' . $errstr);
        }

        $name = (string) stream_socket_get_name($listener, false);
        $port = (int) substr($name, (int) strrpos($name, ':') + 1);
        $client = @stream_socket_client('tcp://127.0.0.1:' . $port, $errno, $errstr, 2.0);
        $peer = $client === false ? false : @stream_socket_accept($listener, 2.0);
        @fclose($listener);

        if ($client === false || $peer === false) {
            if (is_resource($client)) {
                @fclose($client);
            }
            throw new TorNetworkException(
                'Cannot create the local TLS endpoint' . ($errstr !== '' ? ': ' . $errstr : '')
            );
        }
        stream_set_blocking($client, false);
        stream_set_blocking($peer, false);
        @stream_set_write_buffer($client, 0);
        @stream_set_write_buffer($peer, 0);

        $options = array_merge([
            'verify_peer' => true,
            'verify_peer_name' => true,
            'peer_name' => $host,
            'SNI_enabled' => true,
            'allow_self_signed' => false,
            'disable_compression' => true,
        ], $sslOptions);

        foreach ($options as $name => $value) {
            @stream_context_set_option($client, 'ssl', $name, $value);
        }

        $stream = new self($transport, $client, $peer, $host, $timeout);
        $stream->handshake();

        return $stream;
    }

    private function handshake(): void
    {
        $methods = STREAM_CRYPTO_METHOD_TLSv1_2_CLIENT;
        if (defined('STREAM_CRYPTO_METHOD_TLSv1_3_CLIENT')) {
            $methods |= (int) constant('STREAM_CRYPTO_METHOD_TLSv1_3_CLIENT');
        }

        $deadline = microtime(true) + $this->timeout;
        while (openssl_error_string() !== false) {
            // Drain stale errors so a failure below is attributable.
        }

        while (true) {
            $result = @stream_socket_enable_crypto($this->client, true, $methods);
            if ($result === true) {
                return;
            }

            if ($result === false) {
                $detail = self::errorSuffix();
                $this->close();
                throw new TorNetworkException('TLS handshake with ' . $this->host . ' failed' . $detail);
            }

            if (microtime(true) >= $deadline) {
                $this->close();
                throw new TorNetworkException('TLS handshake with ' . $this->host . ' timed out');
            }

            $this->pump($deadline);
        }
    }

    public function write(string $data): void
    {
        $deadline = microtime(true) + $this->timeout;
        $length = strlen($data);
        $offset = 0;

        while ($offset < $length) {
            $written = @fwrite($this->client, substr($data, $offset));
            if ($written === false) {
                throw new TorNetworkException('TLS write to ' . $this->host . ' failed');
            }
            if ($written === 0) {
                if (microtime(true) >= $deadline) {
                    throw new TorNetworkException('TLS write to ' . $this->host . ' timed out');
                }
                $this->flushCiphertext();
                usleep(500);
                continue;
            }

            $offset += $written;
            $this->flushCiphertext();
        }

        $this->flushCiphertext();
    }

    /**
     * Read plaintext, returning an empty string on timeout or at end of stream.
     */
    public function read(float $timeout): string
    {
        $deadline = microtime(true) + max(0.01, $timeout);

        while (true) {
            $chunk = @fread($this->client, 16384);
            if ($chunk === false) {
                throw new TorNetworkException('TLS read from ' . $this->host . ' failed');
            }
            if ($chunk !== '') {
                return $chunk;
            }

            if (microtime(true) >= $deadline) {
                return '';
            }

            try {
                $this->pump($deadline);
            } catch (TorStreamException) {
                return '';
            }
        }
    }

    public function close(): void
    {
        if (is_resource($this->client)) {
            @fclose($this->client);
        }
        if (is_resource($this->peer)) {
            @fclose($this->peer);
        }
    }

    /**
     * Move one batch of bytes in each direction between OpenSSL and Tor.
     */
    private function pump(float $deadline): void
    {
        $this->flushCiphertext();

        $remaining = $deadline - microtime(true);
        $wait = max(0.01, min(0.25, $remaining));
        $incoming = $this->transport->read($wait);

        if ($incoming === '') {
            return;
        }

        $length = strlen($incoming);
        $offset = 0;
        while ($offset < $length) {
            $written = @fwrite($this->peer, substr($incoming, $offset));
            if ($written === false || $written === 0) {
                throw new TorNetworkException('TLS pump failed writing to the local endpoint');
            }
            $offset += $written;
        }
    }

    private function flushCiphertext(): void
    {
        while (true) {
            $chunk = @fread($this->peer, 16384);
            if ($chunk === false) {
                throw new TorNetworkException('TLS pump failed reading the local endpoint');
            }
            if ($chunk === '') {
                return;
            }
            $this->transport->write($chunk);
        }
    }

    private static function errorSuffix(): string
    {
        $errors = [];
        while (($message = openssl_error_string()) !== false) {
            $errors[] = $message;
        }

        if ($errors !== []) {
            return ': ' . implode('; ', array_slice($errors, -3));
        }

        $last = error_get_last();

        return $last !== null && $last['message'] !== '' ? ': ' . $last['message'] : '';
    }
}
