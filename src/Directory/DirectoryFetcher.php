<?php

declare(strict_types=1);

namespace Torv3\Directory;

use Torv3\TorConnectionException;
use Torv3\TorDirectoryException;
use Torv3\TorProtocolException;

/**
 * Fetches and parses the microdescriptor consensus and its microdescriptors
 * directly from the directory authorities (dir-spec.txt §3.4, §3.9, §5.2).
 */
final class DirectoryFetcher
{
    /**
     * Directory authorities taken from tor's auth_dirs.inc.
     * [nickname, IPv4, dirport]
     */
    public const AUTHORITIES = [
        ['moria1', '128.31.0.39', 9231],
        ['tor26', '217.196.147.77', 80],
        ['dizum', '45.66.35.11', 80],
        ['gabelmoo', '131.188.40.189', 80],
        ['dannenberg', '193.23.244.244', 80],
        ['maatuska', '171.25.193.9', 443],
        ['longclaw', '199.58.81.140', 80],
        ['bastet', '204.13.164.118', 80],
        ['faravahar', '216.218.219.41', 80],
    ];

    public const CONSENSUS_PATH = '/tor/status-vote/current/consensus-microdesc';
    public const NS_CONSENSUS_PATH = '/tor/status-vote/current/consensus';
    public const MICRODESC_PATH = '/tor/micro/d/';
    public const AUTHORITY_KEYS_PATH = '/tor/keys/all';

    /**
     * v3 identity fingerprints of the authorities in AUTHORITIES, from tor's
     * auth_dirs.inc. These are the trust anchors for consensus verification.
     */
    public const AUTHORITY_FINGERPRINTS = [
        'moria1' => 'F533C81CEF0BC0267857C99B2F471ADF249FA232',
        'tor26' => '2F3DF9CA0E5D36F2685A2DA67184EB8DCB8CBA8C',
        'dizum' => 'E8A9C45EDE6D711294FADF8E7951F4DE6CA56B58',
        'gabelmoo' => 'ED03BB616EB2F60BEC80151114BB25CEF515B226',
        'dannenberg' => '0232AF901C31A04EE9848595AF9BB7620D4C5B2E',
        'maatuska' => '49015F787433103580E3B66A1707A00E60F2D15B',
        'longclaw' => '23D15D965BC35114467363C165C4F724B64B4F66',
        'bastet' => '27102BC123E7AF1D4741AE047E160C91ADC76B21',
        'faravahar' => '70849B868D606BAECFB6128C5E3D782029AA394F',
    ];

    /** Hard cap on a directory response, to bound memory use. */
    private const MAX_RESPONSE_BYTES = 20 * 1024 * 1024;
    private const CACHE_VERSION = 4;
    private const MAX_MICRODESC_BATCH = 90;

    private const CACHE_MAGIC = "TORV3CACHE\n";

    private ?string $cacheFile;

    /** @var array{0: string, 1: int}|null Last authority that served microdescriptors. */
    private static ?array $microdescAuthority = null;

    /** @var array<string, array{rsa: string, ed25519: string, ntor: ?string}> */
    private array $relayIdentities = [];

    /** @var list<string> Pinned authority identity fingerprints (SHA-1 hex). */
    private array $pinnedFingerprints;

    /**
     * @param list<string>|null $pinnedFingerprints Defaults to Tor's authorities.
     */
    public function __construct(?string $cacheFile = null, ?array $pinnedFingerprints = null)
    {
        $this->cacheFile = $cacheFile;
        $this->pinnedFingerprints = $pinnedFingerprints ?? array_values(self::AUTHORITY_FINGERPRINTS);
    }

    /**
     * Fetch and authenticate a relay's identity material.
     *
     * @return array{rsa: string, ed25519: string, ntor: ?string}
     */
    public function relayIdentity(RelayInfo $relay): array
    {
        if (isset($this->relayIdentities[$relay->fingerprint])) {
            return $this->relayIdentities[$relay->fingerprint];
        }

        $errors = [];
        $path = '/tor/server/fp/' . $relay->fingerprint;

        foreach (self::AUTHORITIES as [$nickname, $address, $port]) {
            try {
                $body = $this->httpGet($address, $port, $path);

                return $this->relayIdentities[$relay->fingerprint] = RelayIdentity::fromDescriptor(
                    $body,
                    $relay->fingerprint,
                    $relay->ed25519Id
                );
            } catch (\Throwable $e) {
                $errors[] = $nickname . ': ' . $e->getMessage();
            }
        }

        throw new TorDirectoryException(
            'Could not authenticate relay ' . $relay->fingerprint . ': '
            . implode('; ', array_slice($errors, 0, 3))
        );
    }

    /**
     * Return the relay list, using the cache when it is still fresh.
     *
     * @return array{relays: array<string, RelayInfo>, validAfter: int, freshUntil: int, params: array<string,string>, sharedRandom: ?string, sharedRandomPrevious: ?string, flavor: string}
     */
    public function relays(bool $force = false, int $ttl = 3600, bool $hsdirOnly = false): array
    {
        if (!$force) {
            $cached = $this->readCache($ttl);
            if ($cached !== null) {
                return $cached;
            }
        }

        $data = $this->fetchFromAuthorities();
        $microdescsRaw = '';
        $relays = $this->attachMicrodescriptors($data['relays'], $microdescsRaw, $hsdirOnly);

        $result = [
            'relays' => $relays,
            'validAfter' => $data['validAfter'],
            'freshUntil' => $data['freshUntil'],
            'params' => $data['params'],
            'sharedRandom' => $data['sharedRandom'],
            'sharedRandomPrevious' => $data['sharedRandomPrevious'],
            'flavor' => $data['flavor'],
            'consensusRaw' => $data['consensusRaw'],
            'certs' => $data['certs'],
            'microdescsRaw' => $microdescsRaw,
        ];

        $this->writeCache($result);

        unset($result['consensusRaw'], $result['certs'], $result['microdescsRaw']);

        return $result;
    }

    /**
     * Try each authority until one serves a parseable consensus.
     *
     * @return array{relays: array<string, RelayInfo>, validAfter: int, freshUntil: int, params: array<string,string>, sharedRandom: ?string, sharedRandomPrevious: ?string, flavor: string, consensusRaw: string, certs: array<string,string>}
     */
    private function fetchFromAuthorities(): array
    {
        $errors = [];
        $required = intdiv(count(self::AUTHORITY_FINGERPRINTS), 2) + 1;
        $certs = [];
        $certPems = [];

        // Authority certificates are self-signed and pinned, so they may be
        // gathered from any authority; merge until a majority is available.
        foreach (self::AUTHORITIES as [$nickname, $address, $port]) {
            if (count($certs) >= $required) {
                break;
            }
            try {
                $certData = $this->authorityCerts($address, $port);
                $certs += $certData['certs'];
                $certPems += $certData['pems'];
            } catch (\Throwable $e) {
                $errors[] = $nickname . ' certs: ' . $e->getMessage();
            }
        }

        if (count($certs) < $required) {
            throw new TorDirectoryException(
                'Could not obtain ' . $required . ' authority certificates: '
                . implode('; ', array_slice($errors, 0, 4))
            );
        }

        foreach (self::AUTHORITIES as [$nickname, $address, $port]) {
            // Microdescriptor consensuses are smaller and carry the onion keys
            // directly. Fall back to the ns flavor for authorities that do not
            // serve it; those relays are completed from router descriptors.
            foreach ([self::CONSENSUS_PATH, self::NS_CONSENSUS_PATH] as $path) {
                try {
                    $body = $this->httpGet($address, $port, $path);

                    if (!self::verifyConsensus($body, $certs)) {
                        throw new TorDirectoryException('Consensus lacks a majority of valid authority signatures');
                    }

                    $parsed = $this->parseConsensus($body);
                    if ($parsed['relays'] === []) {
                        throw new TorDirectoryException('Consensus lists no relays');
                    }
                    if (!self::consensusIsFresh($parsed['validAfter'], $parsed['freshUntil'])) {
                        throw new TorDirectoryException('Consensus is outside its validity window');
                    }

                    return $parsed + [
                        'consensusRaw' => $body,
                        'certs' => $certPems,
                    ];
                } catch (\Throwable $e) {
                    $errors[] = $nickname . ' (' . $path . '): ' . $e->getMessage();
                }
            }
        }

        throw new TorDirectoryException(
            'Could not fetch a consensus from any directory authority: ' . implode('; ', array_slice($errors, 0, 4))
        );
    }

    /**
     * Fetch and verify all authority key certificates from one authority.
     *
     * @return array{certs: array<string, AuthorityCert>, pems: array<string, string>}
     */
    private function authorityCerts(string $address, int $port): array
    {
        $body = $this->httpGet($address, $port, self::AUTHORITY_KEYS_PATH);
        $pinned = $this->pinnedFingerprints;
        $certs = [];
        $pems = [];

        foreach (preg_split('/\n(?=dir-key-certificate-version 3\r?\n)/', $body) as $document) {
            $document = trim($document);
            if ($document === '') {
                continue;
            }
            try {
                $cert = AuthorityCert::parse($document, $pinned);
                $certs[$cert->fingerprint] = $cert;
                $pems[$cert->fingerprint] = $document;
            } catch (TorDirectoryException) {
                continue;
            }
        }

        if ($certs === []) {
            throw new TorDirectoryException('No valid authority key certificate was served');
        }

        return ['certs' => $certs, 'pems' => $pems];
    }

    /**
     * Verify the consensus footer against the verified authority certs.
     *
     * The signed bytes are the document through the space after the first
     * "directory-signature" keyword (dir-spec.txt §3.4.2).
     *
     * A consensus is accepted only with signatures from a majority of the
     * pinned authorities (Tor's n_required = n_authorities/2 + 1).
     *
     * @param array<string, AuthorityCert> $certs
     */
    public static function verifyConsensus(string $text, array $certs): bool
    {
        // Both flavors are accepted: microdesc consensuses carry m-lines,
        // while the ns flavor's onion keys come from router descriptors.
        if (preg_match('/^network-status-version 3(?:[ \t]+microdesc)?\r?$/m', $text) !== 1) {
            return false;
        }

        $marker = "\ndirectory-signature ";
        $position = strpos($text, $marker);
        if ($position === false) {
            return false;
        }
        $signed = substr($text, 0, $position + strlen($marker));

        $pattern = '/directory-signature (?:([a-zA-Z0-9]+) )?([0-9A-Fa-f]{40}) ([0-9A-Fa-f]{40})\s*\r?\n-----BEGIN SIGNATURE-----\s*(.*?)-----END SIGNATURE-----/s';
        if (preg_match_all($pattern, substr($text, $position + 1), $matches, PREG_SET_ORDER) === 0) {
            return false;
        }

        $valid = 0;
        $seen = [];

        foreach ($matches as $match) {
            $algorithm = strtolower($match[1] === '' ? 'sha1' : $match[1]);
            $identity = strtoupper($match[2]);
            $signingDigest = strtoupper($match[3]);

            if ($algorithm !== 'sha1' && $algorithm !== 'sha256') {
                continue;
            }
            if (isset($seen[$identity])) {
                continue;
            }

            $cert = $certs[$identity] ?? null;
            if ($cert === null || !hash_equals($cert->signingKeyDigest, $signingDigest)) {
                continue;
            }

            $signature = base64_decode(preg_replace('/\s+/', '', $match[4]) ?? '', true);
            if ($signature === false || $signature === '') {
                continue;
            }

            if ($cert->verifyConsensusSignature($signed, $signature, $algorithm)) {
                $seen[$identity] = true;
                $valid++;
            }
        }

        $required = intdiv(count(self::AUTHORITY_FINGERPRINTS), 2) + 1;

        return $valid >= $required;
    }

    private static function consensusIsFresh(int $validAfter, int $freshUntil): bool
    {
        $now = time();

        return $validAfter > 0
            && $validAfter <= $now + 3600
            && $freshUntil > $now - 3600
            && ($now - $validAfter) < 7 * 86400;
    }

    /**
     * Authority order for microdescriptor requests, putting the last working
     * authority first so unreachable ones are not retried on every batch.
     *
     * @return array<int, array{0: string, 1: string, 2: int}>
     */
    private static function orderedAuthorities(): array
    {
        if (self::$microdescAuthority === null) {
            return self::AUTHORITIES;
        }
        [$address, $port] = self::$microdescAuthority;
        $ordered = [];
        foreach (self::AUTHORITIES as $entry) {
            if ($entry[1] === $address && $entry[2] === $port) {
                $ordered[] = $entry;
            }
        }
        foreach (self::AUTHORITIES as $entry) {
            if ($entry[1] !== $address || $entry[2] !== $port) {
                $ordered[] = $entry;
            }
        }

        return $ordered;
    }

    /**
     * Fetch microdescriptors for every relay that carries an m-line digest.
     *
     * @param array<string, RelayInfo> $relays
     * @return array<string, RelayInfo>
     */
    private function attachMicrodescriptors(array $relays, ?string &$rawOut = null, bool $hsdirOnly = false): array
    {
        /** @var array<string, string[]> $byDigest digest => fingerprints */
        $byDigest = [];
        /** @var array<string, string> $digestOf */
        $digestOf = [];

        foreach ($relays as $fingerprint => $relay) {
            if (!isset($relay->microdescDigest) || $relay->microdescDigest === '') {
                continue;
            }
            if ($hsdirOnly && !$relay->hasFlag('HSDir')) {
                continue;
            }
            $byDigest[$relay->microdescDigest][] = $fingerprint;
            $digestOf[$fingerprint] = $relay->microdescDigest;
        }

        $hashes = array_keys($byDigest);
        if ($hashes === []) {
            return $relays;
        }

        $parsed = [];
        // A directory cache can return the entire microdescriptor corpus in a
        // single /tor/micro/all document; this replaces ~100 batch requests.
        if (!$hsdirOnly) {
            foreach (self::orderedAuthorities() as [, $address, $port]) {
                try {
                    $all = $this->httpGet($address, $port, '/tor/micro/all');
                    $allBlocks = $this->parseMicrodescriptors($all);
                    if (count($allBlocks) * 2 >= count($hashes)) {
                        $parsed = $allBlocks;
                        self::$microdescAuthority = [$address, $port];
                        if ($rawOut !== null) {
                            $rawOut .= rtrim($all, "\n") . "\n\n";
                        }
                        break;
                    }
                } catch (\Throwable $e) {
                    continue;
                }
            }
        }

        $pending = array_values(array_filter(
            $hashes,
            static fn (string $digest): bool => !isset($parsed[$digest])
        ));
        foreach (array_chunk($pending, self::MAX_MICRODESC_BATCH) as $batch) {
            $body = null;
            foreach (self::orderedAuthorities() as [, $address, $port]) {
                try {
                    $body = $this->httpGet($address, $port, self::MICRODESC_PATH . implode('-', $batch));
                    self::$microdescAuthority = [$address, $port];
                    break;
                } catch (\Throwable $e) {
                    continue;
                }
            }

            if ($body === null) {
                continue;
            }

            if ($rawOut !== null) {
                $rawOut .= rtrim($body, "\n") . "\n\n";
            }

            $blocks = $this->parseMicrodescriptors($body);
            foreach ($blocks as $digest => $fields) {
                $parsed[$digest] = $fields;
            }

            // The relay returns microdescriptors in request order; if the
            // reconstructed block hashes do not line up (they depend on exact
            // line endings), fall back to positional mapping.
            $missing = array_filter($batch, static fn (string $digest): bool => !isset($parsed[$digest]));
            if ($missing !== [] && count($blocks) === count($batch)) {
                $fieldsInOrder = array_values($blocks);
                foreach ($batch as $index => $digest) {
                    if (!isset($parsed[$digest]) && isset($fieldsInOrder[$index])) {
                        $parsed[$digest] = $fieldsInOrder[$index];
                    }
                }
            }
        }

        return $this->applyParsedMicrodescriptors($relays, $parsed);
    }

    /**
     * Attach already-parsed microdescriptor fields to their relays.
     *
     * @param array<string, RelayInfo> $relays
     * @param array<string, array{ntorOnionKey: ?string, ed25519Id: ?string}> $parsed
     * @return array<string, RelayInfo>
     */
    private function applyParsedMicrodescriptors(array $relays, array $parsed): array
    {
        foreach ($relays as $relay) {
            $digest = $relay->microdescDigest;
            if ($digest === null || $digest === '' || !isset($parsed[$digest])) {
                continue;
            }

            $relay->ntorOnionKey = $parsed[$digest]['ntorOnionKey'] ?? null;
            $relay->ed25519Id = $parsed[$digest]['ed25519Id'] ?? null;
        }

        return $relays;
    }

    /**
     * Parse a (microdescriptor) consensus document.
     *
     * @return array{relays: array<string, RelayInfo>, validAfter: int, freshUntil: int, params: array<string,string>, sharedRandom: ?string, sharedRandomPrevious: ?string, flavor: string}
     */
    public function parseConsensus(string $text): array
    {
        $relays = [];
        $params = [];
        $validAfter = 0;
        $freshUntil = 0;
        $sharedRandom = null;
        $sharedRandomPrevious = null;

        $current = null;

        foreach (preg_split('/\r?\n/', $text) as $line) {
            if ($line === '') {
                continue;
            }

            if (str_starts_with($line, 'shared-rand-current-value ')
                || str_starts_with($line, 'shared-rand-previous-value ')
            ) {
                $parts = preg_split('/\s+/', trim($line));
                $encoded = $parts[2] ?? '';
                $decoded = base64_decode($encoded . str_repeat('=', (4 - strlen($encoded) % 4) % 4), true);
                if ($decoded !== false && strlen($decoded) === 32) {
                    if (str_contains($line, 'previous')) {
                        $sharedRandomPrevious = $decoded;
                    } else {
                        $sharedRandom = $decoded;
                    }
                }
                continue;
            }
            if (str_starts_with($line, 'valid-after ')) {
                $validAfter = self::parseConsensusTime(substr($line, 12));
                continue;
            }
            if (str_starts_with($line, 'fresh-until ')) {
                $freshUntil = self::parseConsensusTime(substr($line, 12));
                continue;
            }
            if (str_starts_with($line, 'params ')) {
                foreach (preg_split('/\s+/', trim(substr($line, 7))) as $pair) {
                    $parts = explode('=', $pair, 2);
                    if (count($parts) === 2) {
                        $params[$parts[0]] = $parts[1];
                    }
                }
                continue;
            }

            if (str_starts_with($line, 'r ')) {
                $parts = preg_split('/\s+/', $line) ?: [];

                // Two layouts are valid (fmt_routerstatus.c):
                //   ns/joint:  r nick identity digest DATE TIME ip orport dirport
                //   microdesc: r nick identity DATE TIME ip orport dirport
                // From consensus method 33 on, the microdesc flavor replaces
                // the publication time with 2038-01-01 and moves the digest
                // to the entry's "m" line, leaving eight fields.
                $fields = count($parts);
                if ($fields === 9) {
                    $address = $parts[6];
                    $orPort = (int) $parts[7];
                    $dirPort = (int) $parts[8];
                } elseif ($fields === 8) {
                    $address = $parts[5];
                    $orPort = (int) $parts[6];
                    $dirPort = (int) $parts[7];
                } else {
                    continue;
                }

                $identity = base64_decode(strtr($parts[2], '-_', '+/') . str_repeat('=', (4 - strlen($parts[2]) % 4) % 4), true);
                if ($identity === false || strlen($identity) !== 20) {
                    $current = null;
                    continue;
                }

                $fingerprint = strtoupper(bin2hex($identity));
                $current = new RelayInfo(
                    $parts[1],
                    $fingerprint,
                    $identity,
                    $address,
                    $orPort,
                    $dirPort,
                    []
                );
                $relays[$fingerprint] = $current;
                continue;
            }

            if ($current === null) {
                continue;
            }

            if (str_starts_with($line, 'm ')) {
                $parts = preg_split('/\s+/', trim($line));
                $hash = $parts[1] ?? '';
                $hash = preg_replace('/^sha256=/i', '', $hash) ?? $hash;
                // Microdesc digests are plain base64 with trailing =s
                // omitted (dir-spec §4.8). The "-" is only the request
                // separator, so the base64 alphabet must not be rewritten.
                $hash = rtrim($hash, '=');
                if ($hash !== '') {
                    $current->microdescDigest = $hash;
                }
                continue;
            }

            if (str_starts_with($line, 'id ed25519 ')) {
                $encoded = trim(substr($line, 11));
                $raw = $encoded === 'none' ? false : base64_decode(
                    $encoded . str_repeat('=', (4 - strlen($encoded) % 4) % 4),
                    true
                );
                if ($raw !== false && strlen($raw) === 32) {
                    $current->ed25519Id = $raw;
                }
                continue;
            }

            if (str_starts_with($line, 's ')) {
                $current->flags = array_filter(explode(' ', substr($line, 2)));
                continue;
            }

            if (str_starts_with($line, 'v ')) {
                $current->version = trim(substr($line, 2));
                continue;
            }

            if (str_starts_with($line, 'w ')) {
                foreach (preg_split('/\s+/', trim(substr($line, 2))) as $pair) {
                    if (str_starts_with($pair, 'Bandwidth=')) {
                        $current->bandwidth = (int) substr($pair, 10);
                    }
                }
            }
        }

        $flavor = preg_match('/^network-status-version 3 microdesc\b/m', $text) === 1
            ? 'microdesc'
            : 'ns';

        return [
            'relays' => $relays,
            'validAfter' => $validAfter,
            'freshUntil' => $freshUntil,
            'params' => $params,
            'sharedRandom' => $sharedRandom,
            'sharedRandomPrevious' => $sharedRandomPrevious,
            'flavor' => $flavor,
        ];
    }

    /**
     * Parse microdescriptors keyed by the base64 SHA-256 of the document block.
     *
     * @return array<string, array{ntorOnionKey: ?string, ed25519Id: ?string}>
     */
    public function parseMicrodescriptors(string $text): array
    {
        $result = [];
        $text = str_replace("\r\n", "\n", $text);

        // A response holds one document after another with no blank line
        // between them: each document begins at an "onion-key" line and runs
        // until the next one (dir-spec §4.8). Method 37 leaves the bare
        // "onion-key" keyword even after removing TAP keys.
        $blocks = [];
        foreach (preg_split('/(?=^onion-key\n)/m', $text) ?: [] as $block) {
            $block = trim($block, "\n");
            if ($block !== '' && str_contains($block, "\n")) {
                $blocks[] = $block . "\n";
            }
        }

        foreach ($blocks as $block) {
            $digest = rtrim(base64_encode(hash('sha256', $block, true)), '=');

            $ntor = null;
            $ed = null;
            foreach (preg_split('/\r?\n/', $block) as $line) {
                if (str_starts_with($line, 'ntor-onion-key ')) {
                    $raw = base64_decode(trim(substr($line, 15)) . str_repeat('=', (4 - strlen(trim(substr($line, 15))) % 4) % 4), true);
                    if ($raw !== false && strlen($raw) === 32) {
                        $ntor = $raw;
                    }
                } elseif (str_starts_with($line, 'id ed25519 ')) {
                    $b64 = trim(substr($line, 11));
                    $raw = base64_decode($b64 . str_repeat('=', (4 - strlen($b64) % 4) % 4), true);
                    if ($raw !== false && strlen($raw) === 32) {
                        $ed = $raw;
                    }
                }
            }

            $result[$digest] = ['ntorOnionKey' => $ntor, 'ed25519Id' => $ed];
        }

        return $result;
    }

    /**
     * Minimal HTTP/1.x GET; follows up to three redirects.
     */
    public function httpGet(string $host, int $port, string $path, int $redirects = 3): string
    {
        $errno = 0;
        $errstr = '';
        $stream = @stream_socket_client(
            'tcp://' . $host . ':' . $port,
            $errno,
            $errstr,
            15.0,
            STREAM_CLIENT_CONNECT
        );

        if ($stream === false) {
            throw new TorConnectionException('Cannot connect to ' . $host . ':' . $port . ' (' . $errstr . ')');
        }

        stream_set_timeout($stream, 20);
        $request = 'GET ' . $path . " HTTP/1.0\r\n"
            . 'Host: ' . $host . "\r\n"
            . "User-Agent: TorPHP/1.0\r\n"
            . "Accept-Encoding: identity\r\n"
            . "Connection: close\r\n\r\n";

        if (@fwrite($stream, $request) === false) {
            fclose($stream);
            throw new TorConnectionException('Failed to write directory request');
        }

        $raw = '';
        while (!feof($stream)) {
            $chunk = fread($stream, 65536);
            if ($chunk === false) {
                break;
            }
            if ($chunk === '') {
                $meta = stream_get_meta_data($stream);
                if (!empty($meta['timed_out'])) {
                    break;
                }
                continue;
            }
            $raw .= $chunk;
            if (strlen($raw) > self::MAX_RESPONSE_BYTES) {
                fclose($stream);
                throw new TorDirectoryException('Directory response exceeded the size limit');
            }
        }
        fclose($stream);

        if ($raw === '') {
            throw new TorConnectionException('Empty response from ' . $host . ':' . $port);
        }

        $response = self::parseHttpResponse($raw);

        if ($response['status'] >= 300 && $response['status'] < 400 && $redirects > 0) {
            $location = $response['headers']['location'][0] ?? null;
            if ($location !== null) {
                $target = parse_url($location);
                if (!is_array($target) || strtolower($target['scheme'] ?? 'http') !== 'http') {
                    throw new TorDirectoryException('Directory redirect is not an http URL');
                }

                $newHost = $target['host'] ?? $host;
                $newPort = $target['port'] ?? 80;
                $newPath = ($target['path'] ?? '/') . (isset($target['query']) ? '?' . $target['query'] : '');

                $allowedHosts = array_map(static fn (array $a): string => $a[1], self::AUTHORITIES);
                if ($newHost !== $host && !in_array($newHost, $allowedHosts, true)) {
                    throw new TorDirectoryException('Directory redirect to an unpinned host');
                }
                if (preg_match('/[\x00-\x1f\x7f]/', $newPath) === 1) {
                    throw new TorDirectoryException('Directory redirect contains control characters');
                }

                return $this->httpGet($newHost, $newPort, $newPath, $redirects - 1);
            }
        }

        if ($response['status'] !== 200) {
            throw new TorDirectoryException('Directory returned HTTP ' . $response['status'] . ' for ' . $path);
        }

        return $response['body'];
    }

    /**
     * Split an HTTP response into status, headers and a decoded body.
     *
     * @return array{status: int, headers: array<string, string[]>, body: string}
     */
    public static function parseHttpResponse(string $raw): array
    {
        $headerEnd = strpos($raw, "\r\n\r\n");
        $separatorLength = 4;
        if ($headerEnd === false) {
            $headerEnd = strpos($raw, "\n\n");
            $separatorLength = 2;
        }

        if ($headerEnd === false) {
            return ['status' => 0, 'headers' => [], 'body' => $raw];
        }

        $head = substr($raw, 0, $headerEnd);
        $body = substr($raw, $headerEnd + $separatorLength);

        $lines = preg_split('/\r?\n/', $head);
        $status = 0;
        if (isset($lines[0]) && preg_match('#^HTTP/\d\.\d\s+(\d{3})#', $lines[0], $m) === 1) {
            $status = (int) $m[1];
        }

        $headers = [];
        foreach (array_slice($lines, 1) as $line) {
            $pos = strpos($line, ':');
            if ($pos === false) {
                continue;
            }
            $name = strtolower(trim(substr($line, 0, $pos)));
            $headers[$name][] = trim(substr($line, $pos + 1));
        }

        if (isset($headers['transfer-encoding'][0])
            && stripos($headers['transfer-encoding'][0], 'chunked') !== false) {
            $body = self::decodeChunked($body);
        }

        return ['status' => $status, 'headers' => $headers, 'body' => $body];
    }

    /**
     * Decode a chunked transfer-encoded body.
     */
    public static function decodeChunked(string $body): string
    {
        $output = '';
        $offset = 0;
        $length = strlen($body);

        while ($offset < $length) {
            $lineEnd = strpos($body, "\r\n", $offset);
            if ($lineEnd === false) {
                break;
            }
            $sizeLine = trim(explode(';', substr($body, $offset, $lineEnd - $offset))[0]);
            if (preg_match('/^[0-9a-f]+$/i', $sizeLine) !== 1) {
                break;
            }
            $size = (int) hexdec($sizeLine);
            $offset = $lineEnd + 2;
            if ($size === 0) {
                break;
            }
            $output .= substr($body, $offset, $size);
            $offset += $size + 2;
        }

        return $output;
    }

    private static function parseConsensusTime(string $value): int
    {
        $timestamp = strtotime(trim($value) . ' UTC');

        return $timestamp === false ? 0 : $timestamp;
    }

    /**
     * The cache stores the raw consensus, authority certificates and
     * microdescriptors, and every load re-verifies the signatures and the
     * validity window before rebuilding the relay list. A tampered or
     * unparseable cache is discarded, forcing a refetch.
     *
     * @return array{relays: array<string, RelayInfo>, validAfter: int, freshUntil: int, params: array<string,string>, sharedRandom: ?string, sharedRandomPrevious: ?string, flavor: string}|null
     */
    private function readCache(int $ttl): ?array
    {
        if ($this->cacheFile === null || !is_file($this->cacheFile)) {
            return null;
        }

        $raw = @file_get_contents($this->cacheFile);
        if ($raw === false || $raw === '') {
            return null;
        }

        if (str_starts_with($raw, self::CACHE_MAGIC)) {
            $decoded = @gzdecode(substr($raw, strlen(self::CACHE_MAGIC)));
            if ($decoded === false) {
                return null;
            }
            $raw = $decoded;
        }

        $data = json_decode($raw, true);
        if (!is_array($data) || ($data['version'] ?? 0) !== self::CACHE_VERSION) {
            return null;
        }

        $fetchedAt = (int) ($data['fetched_at'] ?? 0);
        $freshUntil = (int) ($data['fresh_until'] ?? 0);

        $expired = $ttl > 0 && (time() - $fetchedAt) > $ttl;
        if ($expired || ($freshUntil > 0 && time() > $freshUntil + 900)) {
            return null;
        }

        $consensus = base64_decode((string) ($data['consensus'] ?? ''), true);
        $microdescs = base64_decode((string) ($data['microdescs'] ?? ''), true);
        if ($consensus === false || $consensus === '' || $microdescs === false) {
            return null;
        }

        $certs = [];
        foreach ($data['certs'] ?? [] as $encodedDocument) {
            if (!is_string($encodedDocument)) {
                return null;
            }
            $document = base64_decode($encodedDocument, true);
            if ($document === false || $document === '') {
                return null;
            }
            try {
                $cert = AuthorityCert::parse($document, $this->pinnedFingerprints);
            } catch (TorDirectoryException) {
                return null;
            }
            $certs[$cert->fingerprint] = $cert;
        }

        if ($certs === [] || !self::verifyConsensus($consensus, $certs)) {
            return null;
        }

        $parsed = $this->parseConsensus($consensus);
        if ($parsed['relays'] === [] || !self::consensusIsFresh($parsed['validAfter'], $parsed['freshUntil'])) {
            return null;
        }

        $relays = $this->applyParsedMicrodescriptors(
            $parsed['relays'],
            $this->parseMicrodescriptors($microdescs)
        );

        return [
            'relays' => $relays,
            'validAfter' => $parsed['validAfter'],
            'freshUntil' => $parsed['freshUntil'],
            'params' => $parsed['params'],
            'sharedRandom' => $parsed['sharedRandom'],
            'sharedRandomPrevious' => $parsed['sharedRandomPrevious'],
            'flavor' => $parsed['flavor'],
        ];
    }

    private function writeCache(array $result): void
    {
        if ($this->cacheFile === null) {
            return;
        }

        $certs = [];
        foreach ($result['certs'] ?? [] as $document) {
            if (is_string($document) && $document !== '') {
                $certs[] = base64_encode($document);
            }
        }

        $payload = json_encode([
            'version' => self::CACHE_VERSION,
            'fetched_at' => time(),
            'valid_after' => $result['validAfter'],
            'fresh_until' => $result['freshUntil'],
            'params' => $result['params'],
            'shared_random' => base64_encode((string) ($result['sharedRandom'] ?? '')),
            'shared_random_previous' => base64_encode((string) ($result['sharedRandomPrevious'] ?? '')),
            'consensus' => base64_encode((string) ($result['consensusRaw'] ?? '')),
            'certs' => $certs,
            'microdescs' => base64_encode((string) ($result['microdescsRaw'] ?? '')),
        ]);

        if ($payload === false) {
            return;
        }

        $compressed = gzencode($payload, 6);
        if ($compressed === false) {
            return;
        }
        $payload = self::CACHE_MAGIC . $compressed;

        $dir = dirname($this->cacheFile);
        if (!is_dir($dir)) {
            @mkdir($dir, 0770, true);
        }

        $tmp = $this->cacheFile . '.tmp';
        if (@file_put_contents($tmp, $payload) !== false) {
            @rename($tmp, $this->cacheFile);
        }
    }
}
