<?php

declare(strict_types=1);

/**
 * Minimal TLS HTTP server used by tests/tls_test.php.
 *
 * Usage: php tests/tls_echo_server.php <cert.pem> <key.pem>
 * Prints the listening port, then serves up to three sequential connections.
 */

$cert = $argv[1] ?? '';
$key = $argv[2] ?? '';
if ($cert === '' || $key === '') {
    fwrite(STDERR, "usage: tls_echo_server.php cert.pem key.pem\n");
    exit(2);
}

$context = stream_context_create(['ssl' => [
    'local_cert' => $cert,
    'local_pk' => $key,
    'verify_peer' => false,
    'allow_self_signed' => true,
]]);

$server = @stream_socket_server(
    'tcp://127.0.0.1:0',
    $errno,
    $errstr,
    STREAM_SERVER_BIND | STREAM_SERVER_LISTEN,
    $context
);
if ($server === false) {
    fwrite(STDERR, "listen failed: {$errstr}\n");
    exit(1);
}

$name = (string) stream_socket_get_name($server, false);
$port = (int) substr($name, (int) strrpos($name, ':') + 1);
fwrite(STDOUT, $port . "\n");
fflush(STDOUT);

for ($i = 0; $i < 3; $i++) {
    $conn = @stream_socket_accept($server, 10);
    if ($conn === false) {
        break;
    }

    stream_set_timeout($conn, 5);
    if (@stream_socket_enable_crypto($conn, true, STREAM_CRYPTO_METHOD_TLS_SERVER) !== true) {
        fclose($conn);
        continue;
    }

    $request = '';
    while (!str_contains($request, "\r\n\r\n") && !feof($conn)) {
        $chunk = fread($conn, 4096);
        if ($chunk === false || $chunk === '') {
            break;
        }
        $request .= $chunk;
    }

    fwrite($conn, "HTTP/1.0 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\nhello");
    fflush($conn);
    fclose($conn);
}

fclose($server);
