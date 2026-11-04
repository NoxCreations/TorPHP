<?php

declare(strict_types=1);

/**
 * TLS-over-transport test: proves the handshake, certificate verification,
 * hostname checking, data pumping and an HTTP response all work over a
 * non-socket byte stream. No Tor network or external service required.
 *
 * Run: php tests/tls_test.php
 */

require __DIR__ . '/../autoload.php';

use Torv3\TorNetworkException;
use Torv3\TorStreamException;
use Torv3\Transport\ByteStream;
use Torv3\Transport\TlsStream;

$failures = 0;

function check(string $name, bool $ok, string $detail = ''): void
{
    global $failures;
    if ($ok) {
        echo "  PASS  {$name}\n";
    } else {
        $failures++;
        echo "  FAIL  {$name}" . ($detail !== '' ? " ({$detail})" : '') . "\n";
    }
}

final class TcpByteStream implements ByteStream
{
    /** @var resource */
    private $socket;

    public function __construct(string $host, int $port)
    {
        $socket = @stream_socket_client('tcp://' . $host . ':' . $port, $errno, $errstr, 5);
        if ($socket === false) {
            throw new RuntimeException('connect failed: ' . $errstr);
        }
        $this->socket = $socket;
        stream_set_blocking($this->socket, false);
    }

    public function write(string $bytes): void
    {
        $length = strlen($bytes);
        $offset = 0;
        while ($offset < $length) {
            $written = @fwrite($this->socket, substr($bytes, $offset));
            if ($written === false || $written === 0) {
                throw new RuntimeException('tcp write failed');
            }
            $offset += $written;
        }
    }

    public function read(float $timeout): string
    {
        $read = [$this->socket];
        $write = null;
        $except = null;
        $seconds = (int) $timeout;
        $micros = (int) (($timeout - $seconds) * 1000000);
        $ready = @stream_select($read, $write, $except, $seconds, $micros);
        if ($ready === false) {
            throw new RuntimeException('select failed');
        }
        if ($ready === 0) {
            return '';
        }

        $chunk = fread($this->socket, 16384);
        if ($chunk === false) {
            throw new RuntimeException('tcp read failed');
        }
        if ($chunk === '' && feof($this->socket)) {
            throw new TorStreamException('transport closed');
        }

        return $chunk;
    }

    public function close(): void
    {
        if (is_resource($this->socket)) {
            fclose($this->socket);
        }
    }
}

$dir = sys_get_temp_dir() . '/torv3-tls-' . bin2hex(random_bytes(6));
if (!mkdir($dir, 0700)) {
    fwrite(STDERR, "cannot create temp dir\n");
    exit(1);
}

$configPath = $dir . '/openssl.cnf';
file_put_contents(
    $configPath,
    "[req]\nprompt = no\ndistinguished_name = dn\nx509_extensions = v3\n"
    . "[dn]\nCN = localhost\n"
    . "[v3]\nsubjectAltName = DNS:localhost,IP:127.0.0.1\nbasicConstraints = CA:TRUE\n"
);

$key = openssl_pkey_new(['private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA]);
$csr = $key === false ? false : openssl_csr_new(
    ['commonName' => 'localhost'],
    $key,
    ['config' => $configPath, 'digest_alg' => 'sha256']
);
$cert = $csr === false ? false : openssl_csr_sign(
    $csr,
    null,
    $key,
    2,
    ['config' => $configPath, 'digest_alg' => 'sha256', 'x509_extensions' => 'v3'],
    random_int(1, PHP_INT_MAX)
);
if ($key === false || $cert === false) {
    fwrite(STDERR, "certificate generation failed: " . (string) openssl_error_string() . "\n");
    exit(1);
}

openssl_x509_export($cert, $certPem);
openssl_pkey_export($key, $keyPem);
file_put_contents($dir . '/cert.pem', $certPem);
file_put_contents($dir . '/key.pem', $keyPem);

$process = proc_open(
    [PHP_BINARY, __DIR__ . '/tls_echo_server.php', $dir . '/cert.pem', $dir . '/key.pem'],
    [1 => ['pipe', 'w'], 2 => ['pipe', 'w']],
    $pipes
);
if (!is_resource($process)) {
    fwrite(STDERR, "cannot start the TLS server\n");
    exit(1);
}

$portLine = fgets($pipes[1]);
$port = (int) trim((string) $portLine);
check('local TLS server starts', $port > 0, 'port ' . $port);

if ($port > 0) {
    try {
        $stream = TlsStream::connect(new TcpByteStream('127.0.0.1', $port), 'localhost', [
            'cafile' => $dir . '/cert.pem',
        ], 10.0);
        $stream->write("GET / HTTP/1.0\r\nHost: localhost\r\nConnection: close\r\n\r\n");

        $response = '';
        $deadline = microtime(true) + 10.0;
        while (microtime(true) < $deadline) {
            $chunk = $stream->read(1.0);
            if ($chunk === '') {
                if (str_contains($response, 'hello')) {
                    break;
                }
                continue;
            }
            $response .= $chunk;
            if (str_contains($response, "\r\n\r\nhello")) {
                break;
            }
        }
        $stream->close();

        check('TLS handshake and HTTP exchange succeed over a byte stream', str_contains($response, '200 OK') && str_contains($response, 'hello'));
    } catch (Throwable $e) {
        check('TLS handshake and HTTP exchange succeed over a byte stream', false, $e->getMessage());
    }

    $rejected = false;
    try {
        $bad = TlsStream::connect(new TcpByteStream('127.0.0.1', $port), '127.0.0.1', [
            'cafile' => $dir . '/cert.pem',
            'peer_name' => 'wrong.example',
        ], 10.0);
        $bad->write("GET / HTTP/1.0\r\nHost: wrong.example\r\n\r\n");
        $bad->close();
    } catch (TorNetworkException) {
        $rejected = true;
    } catch (Throwable) {
        $rejected = false;
    }
    check('a certificate for the wrong hostname is rejected', $rejected);

    try {
        $selfSigned = TlsStream::connect(new TcpByteStream('127.0.0.1', $port), 'localhost', [
            'allow_self_signed' => true,
        ], 10.0);
        $selfSigned->write("GET / HTTP/1.0\r\nHost: localhost\r\nConnection: close\r\n\r\n");

        $reply = '';
        $deadline = microtime(true) + 10.0;
        while (microtime(true) < $deadline && !str_contains($reply, 'hello')) {
            $chunk = $selfSigned->read(1.0);
            if ($chunk !== '') {
                $reply .= $chunk;
            }
        }
        $selfSigned->close();

        check('self-signed certificates can be accepted explicitly', str_contains($reply, 'hello'));
    } catch (Throwable $e) {
        check('self-signed certificates can be accepted explicitly', false, $e->getMessage());
    }
}

proc_terminate($process);
foreach ($pipes as $pipe) {
    @fclose($pipe);
}
proc_close($process);

foreach (['/cert.pem', '/key.pem', '/openssl.cnf'] as $file) {
    @unlink($dir . $file);
}
@rmdir($dir);

echo $failures === 0 ? "\nAll TLS checks passed.\n" : "\n{$failures} TLS check(s) failed.\n";
exit($failures === 0 ? 0 : 1);
