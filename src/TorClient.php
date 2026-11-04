<?php

declare(strict_types=1);

namespace Torv3;

use Torv3\Cell\Commands;
use Torv3\Circuit\Circuit;
use Torv3\Crypto\Keccak;
use Torv3\Directory\DirectoryFetcher;
use Torv3\Directory\GuardSet;
use Torv3\Directory\RelayInfo;
use Torv3\Link\LinkSession;
use Torv3\Onion\OnionV3;
use Torv3\Transport\CircuitByteStream;
use Torv3\Transport\TlsStream;

/**
 * Public API: bootstrap from the consensus, build circuits and fetch URLs
 * through the Tor network (including v3 onion services) without any local
 * tor process, SOCKS proxy or HTTP proxy.
 */
final class TorClient
{
    private DirectoryFetcher $directory;

    /** @var array<string, RelayInfo> */
    private array $relays = [];

    /** @var array<string, string> */
    private array $params = [];

    private int $pathLength = 3;

    /** Current shared random value from the consensus (32 bytes). */
    private ?string $sharedRandom = null;

    /** Previous shared random value (32 bytes), used early in an SRV run. */
    private ?string $previousSharedRandom = null;

    /** Descriptor time-period length in minutes (consensus hsdir-interval). */
    private int $periodLength = 1440;

    /** Consensus valid-after, used instead of the local clock. */
    private ?int $validAfter = null;

    /** @var array<string, int> Highest descriptor revision accepted per blinded key. */
    private array $descriptorRevisions = [];

    /** False when bootstrapped from an ns-flavor consensus (no onion keys). */
    private bool $microdescFlavor = true;

    /** True when only HSDir microdescriptors were loaded (onion lookups). */
    private bool $hsdirOnlyBootstrap = false;

    /** Absolute wall-clock deadline for the current request, or null. */
    private ?float $requestDeadline = null;

    private ?GuardSet $guards = null;

    private function __construct(?string $cacheFile)
    {
        $this->directory = new DirectoryFetcher($cacheFile);
        $this->guards = GuardSet::forCacheFile($cacheFile);
    }

    public static function create(?string $cacheFile = null): self
    {
        return new self($cacheFile);
    }

    /**
     * Download (or load from cache) the network consensus.
     */
    public function bootstrap(bool $force = false, int $ttl = 3600, bool $hsdirOnly = false): self
    {
        $this->hsdirOnlyBootstrap = $hsdirOnly;
        $data = $this->directory->relays($force, $ttl, $hsdirOnly);

        $this->relays = $data['relays'];
        $this->params = $data['params'];
        $this->sharedRandom = $data['sharedRandom'] ?? null;
        $this->previousSharedRandom = $data['sharedRandomPrevious'] ?? null;
        $this->validAfter = ((int) $data['validAfter']) ?: null;
        $this->periodLength = max(60, (int) ($this->params['hsdir-interval'] ?? 1440));
        $this->microdescFlavor = $data['flavor'] !== 'ns';

        return $this;
    }

    /**
     * @return array<string, RelayInfo>
     */
    public function relays(): array
    {
        return $this->relays;
    }

    /**
     * @return array<string, string>
     */
    public function consensusParams(): array
    {
        return $this->params;
    }

    public function relayByFingerprint(string $fingerprintHex): ?RelayInfo
    {
        $fingerprint = strtoupper($fingerprintHex);

        return $this->relays[$fingerprint] ?? null;
    }

    /**
     * Pick a random path of $hops relays honouring required flags.
     *
     * @param string[] $require
     * @param string[] $excludeFingerprints
     * @return RelayInfo[]
     */
    public function pickPath(int $hops, array $require = [], array $excludeFingerprints = []): array
    {
        $candidates = [];
        foreach ($this->relays as $fingerprint => $relay) {
            if (in_array($fingerprint, $excludeFingerprints, true)) {
                continue;
            }
            if (!$this->isSelectable($relay)) {
                continue;
            }

            $ok = true;
            foreach ($require as $flag) {
                if (!$relay->hasFlag($flag)) {
                    $ok = false;
                    break;
                }
            }
            if ($ok) {
                $candidates[] = $relay;
            }
        }

        if (count($candidates) < $hops) {
            throw new TorDirectoryException(
                'Not enough usable relays with flags [' . implode(',', $require) . '] ('
                . count($candidates) . ' available, ' . $hops . ' needed)'
            );
        }

        $picked = [];
        $used = $excludeFingerprints;
        for ($i = 0; $i < $hops; $i++) {
            $pool = array_values(array_filter(
                $candidates,
                static fn (RelayInfo $r): bool => $r->canExtend()
                    && !in_array($r->fingerprint, $used, true)
            ));
            if ($pool === []) {
                throw new TorDirectoryException('Unable to complete a ' . $hops . '-hop path');
            }
            $relay = $pool[random_int(0, count($pool) - 1)];
            $picked[] = $relay;
            $used[] = $relay->fingerprint;
        }

        return $picked;
    }

    /**
     * Open a TLS link to the first hop, create the circuit and extend it.
     *
     * @param RelayInfo[] $hops
     */
    public function buildCircuit(array $hops): Circuit
    {
        if ($hops === []) {
            throw new TorException('A circuit needs at least one hop');
        }

        // A microdescriptor consensus supplies every ntor onion key up front;
        // the ns flavor does not, so take the missing keys from each relay's
        // authenticated router descriptor.
        foreach ($hops as $hop) {
            $this->ensureOnionKey($hop);
        }

        $this->timeoutFor(1.0);
        $first = $hops[0];

        // The microdesc consensus already authenticates each relay's ed25519
        // identity, so fetch the router descriptor only when it is missing
        // (ns-flavor consensus). Fetching it per circuit added a clearnet
        // round trip to every build and ignored the request deadline.
        $expectedEd25519 = $first->ed25519Id;
        if ($expectedEd25519 === null) {
            $identity = $this->directory->relayIdentity($first);
            $expectedEd25519 = $identity['ed25519'];
        }

        try {
            $link = LinkSession::connect($first->address, $first->orPort, $this->timeoutFor(15.0));
            $link->negotiate($expectedEd25519, $this->timeoutFor(30.0));
        } catch (\Throwable $e) {
            // guard-spec.txt: an unreachable guard must not stay sticky, or the
            // client would keep retrying the same dead first hop.
            $this->guards?->reject($first->fingerprint);
            throw $e;
        }

        $circuit = Circuit::create($link, $first, Circuit::randomCircuitId(), $this->timeoutFor(20.0));

        try {
            for ($i = 1, $count = count($hops); $i < $count; $i++) {
                $circuit->extend($hops[$i], $this->timeoutFor(20.0));
            }
        } catch (\Throwable $e) {
            $circuit->close();
            throw $e;
        }

        return $circuit;
    }

    /**
     * Build a circuit to $target, retrying with a fresh path when a hop does
     * not answer EXTEND2. Dead or overloaded middles are common on the public
     * network; a single stalled hop must not fail the whole request.
     *
     * @param string[] $exclude
     */
    private function buildCircuitTo(RelayInfo $target, array $exclude = [], int $attempts = 3): Circuit
    {
        $last = null;

        for ($attempt = 1; $attempt <= $attempts; $attempt++) {
            $this->timeoutFor(1.0);
            try {
                return $this->buildCircuit($this->pathTo($target, $exclude));
            } catch (TorException $e) {
                $last = $e;
            }
        }

        throw new TorException(
            'Could not build a circuit to ' . $target->nickname . ': '
            . ($last?->getMessage() ?? 'unknown error')
        );
    }

    /**
     * Fetch a URL through Tor.
     *
     * The raw response is returned by default, including 3xx redirects. Set
     * follow_redirects to have the client follow Location headers itself;
     * max_redirects (default 5) bounds the chain and loops are rejected. Every
     * target is re-checked against the allowClearnet policy, so an onion
     * service cannot bounce the request to the clearnet without permission.
     *
     * @param array<string, mixed> $options allowClearnet (bool), timeout (float),
     *        max_bytes (int), client_auth_key (string), follow_redirects (bool),
     *        max_redirects (int)
     * @return array{status: int, headers: array<string, string[]>, body: string, url: string}
     */
    public function request(string $url, array $options = []): array
    {
        $deadline = (float) ($options['deadline'] ?? 0.0);
        $previous = $this->requestDeadline;
        $this->requestDeadline = $deadline > 0.0 ? $deadline : null;

        try {
            return $this->requestWithRedirects($url, $options);
        } finally {
            $this->requestDeadline = $previous;
        }
    }

    /**
     * Follow redirects; the deadline set by request() clamps every wait.
     *
     * @param array<string, mixed> $options
     * @return array{status: int, headers: array<string, string[]>, body: string, url: string}
     */
    private function requestWithRedirects(string $url, array $options): array
    {
        $followRedirects = (bool) ($options['follow_redirects'] ?? false);
        $maxRedirects = max(0, (int) ($options['max_redirects'] ?? 5));
        $seen = [$url => true];
        $current = $url;

        for ($hop = 0; ; $hop++) {
            $response = $this->requestOnce($current, $options);

            if (!$followRedirects || !in_array($response['status'], [301, 302, 303, 307, 308], true)) {
                return $response;
            }

            $location = $response['headers']['location'][0] ?? null;
            if ($location === null || $location === '') {
                return $response;
            }

            if ($hop >= $maxRedirects) {
                throw new TorException('Too many redirects (limit ' . $maxRedirects . ')');
            }

            $next = self::resolveRedirect($current, $location);
            if (isset($seen[$next])) {
                throw new TorException('Redirect loop detected at ' . $next);
            }

            $seen[$next] = true;
            $current = $next;
        }
    }

    /**
     * Clamp an operation timeout to the time left before the request deadline.
     *
     * @throws TorException when the budget is already exhausted
     */
    private function timeoutFor(float $wanted): float
    {
        if ($this->requestDeadline === null) {
            return $wanted;
        }

        $left = $this->requestDeadline - microtime(true);
        if ($left <= 0.5) {
            throw new TorException('Request deadline exceeded');
        }

        return min($wanted, $left);
    }

    /**
     * Fetch a single URL without following redirects.
     *
     * @param array<string, mixed> $options
     * @return array{status: int, headers: array<string, string[]>, body: string, url: string}
     */
    private function requestOnce(string $url, array $options = []): array
    {
        $target = parse_url($url);
        if (!is_array($target) || !isset($target['host'])) {
            throw new TorException('Invalid URL: ' . $url);
        }

        $scheme = strtolower($target['scheme'] ?? 'http');
        $host = strtolower($target['host']);
        $port = (int) ($target['port'] ?? ($scheme === 'https' ? 443 : 80));
        $path = ($target['path'] ?? '/') . (isset($target['query']) ? '?' . $target['query'] : '');
        $timeout = $this->timeoutFor((float) ($options['timeout'] ?? 30.0));

        if (preg_match('/[\x00-\x20\x7f]/', $host) === 1 || str_contains($host, '/')) {
            throw new TorException('Invalid characters in URL host');
        }
        if (preg_match('/[\x00-\x1f\x7f]/', $path) === 1) {
            throw new TorException('Invalid control characters in URL path');
        }

        if ($scheme !== 'http' && $scheme !== 'https') {
            throw new TorException('Unsupported URL scheme: ' . $scheme . '://' . $host);
        }

        $tls = $scheme === 'https';
        $clientAuthKey = $options['client_auth_key'] ?? null;
        if ($clientAuthKey !== null && !is_string($clientAuthKey)) {
            throw new TorException('client_auth_key must be a 32-byte string or base64');
        }

        if (str_ends_with($host, '.onion')) {
            return $this->requestOnion(
                $host,
                $port,
                $path,
                $timeout,
                $tls,
                $clientAuthKey,
                (int) ($options['max_bytes'] ?? 8388608)
            );
        }

        if (empty($options['allowClearnet'])) {
            throw new TorException('Clearnet access is disabled: ' . $host);
        }

        return $this->requestClearnet(
            $host,
            $port,
            $path,
            $timeout,
            (int) ($options['max_bytes'] ?? 8388608),
            $tls
        );
    }

    /**
     * Resolve a Location header against the URL that produced it.
     */
    private static function resolveRedirect(string $base, string $location): string
    {
        if (preg_match('#^[a-z][a-z0-9+.-]*://#i', $location) === 1) {
            return $location;
        }

        $parts = parse_url($base);
        if (!is_array($parts) || !isset($parts['scheme'], $parts['host'])) {
            return $location;
        }

        $authority = $parts['host'] . (isset($parts['port']) ? ':' . $parts['port'] : '');

        if (str_starts_with($location, '//')) {
            return $parts['scheme'] . ':' . $location;
        }

        if (str_starts_with($location, '/')) {
            $path = $location;
        } else {
            $basePath = $parts['path'] ?? '/';
            $slash = strrpos($basePath, '/');
            $path = ($slash === false ? '/' : substr($basePath, 0, $slash + 1)) . $location;
        }

        return $parts['scheme'] . '://' . $authority . self::normalizePath($path);
    }

    /**
     * Collapse dot segments in a redirect path (RFC 3986 §5.2.4).
     */
    private static function normalizePath(string $path): string
    {
        $suffix = '';
        $cut = strcspn($path, '?#');
        if ($cut < strlen($path)) {
            $suffix = substr($path, $cut);
            $path = substr($path, 0, $cut);
        }

        $segments = [];
        foreach (explode('/', $path) as $segment) {
            if ($segment === '' || $segment === '.') {
                continue;
            }
            if ($segment === '..') {
                array_pop($segments);
                continue;
            }
            $segments[] = $segment;
        }

        $normalized = '/' . implode('/', $segments);
        if ($segments !== [] && str_ends_with($path, '/')) {
            $normalized .= '/';
        }

        return $normalized . $suffix;
    }

    /**
     * Anonymous clearnet request through a three-hop exit circuit.
     *
     * @return array{status: int, headers: array<string, string[]>, body: string, url: string}
     */
    private function requestClearnet(
        string $host,
        int $port,
        string $path,
        float $timeout,
        int $maxBytes = 8388608,
        bool $tls = false
    ): array
    {
        if ($this->relays === []) {
            $this->bootstrap();
        }

        $exit = $this->pickHops(1, ['Exit', 'Fast', 'Running'], [])[0];
        $circuit = $this->buildCircuitTo($exit);

        try {
            $this->timeoutFor(1.0);
            $streamId = $circuit->beginStream($host, $port, false, $this->timeoutFor($timeout));
            $response = $this->httpExchange(
                $circuit,
                $streamId,
                $host,
                $port,
                $path,
                $this->timeoutFor($timeout),
                $maxBytes,
                $tls
            );
            $defaultPort = $tls ? 443 : 80;
            $response['url'] = ($tls ? 'https' : 'http') . '://' . $host
                . ($port === $defaultPort ? '' : ':' . $port) . $path;

            return $response;
        } finally {
            $circuit->close();
        }
    }

    /**
     * Full v3 onion service flow: descriptor, introduction, rendezvous, HTTP.
     *
     * @return array{status: int, headers: array<string, string[]>, body: string, url: string}
     */
    public function requestOnion(
        string $host,
        int $port,
        string $path,
        float $timeout = 30.0,
        bool $tls = false,
        ?string $clientAuthKey = null,
        int $maxBytes = 8388608
    ): array
    {
        if ($this->relays === []) {
            $this->bootstrap();
        }

        $this->timeoutFor(1.0);
        $onion = new OnionV3($host, $this->validAfter, $this->periodLength);
        if ($clientAuthKey !== null) {
            $onion->setClientAuthKey($clientAuthKey);
        }

        $descriptor = $this->fetchOnionDescriptor($onion, $this->timeoutFor($timeout));
        $parsed = $onion->decryptDescriptor($descriptor);

        // Rollback protection: a valid but older descriptor must never replace
        // one this client already accepted for the same blinded key.
        $revision = (int) $parsed['revision'];
        $blindedKey = $onion->blindedPublicKeyValue();
        $accepted = $this->descriptorRevisions[$blindedKey] ?? null;
        if ($accepted !== null && $revision < $accepted) {
            throw new TorOnionException(
                'Descriptor revision ' . $revision . ' for ' . $host
                . ' is older than the accepted revision ' . $accepted
            );
        }
        $this->descriptorRevisions[$blindedKey] = $revision;

        $introPoints = $parsed['introductionPoints'];

        if ($introPoints === []) {
            throw new TorOnionException('Descriptor for ' . $host . ' lists no usable introduction points');
        }

        // Rendezvous point: the circuit must support the HSRend protocol.
        $rendezvousRelay = $this->pickHops(1, ['Fast', 'Running'], [])[0];
        $rendezvousCircuit = $this->buildCircuitTo($rendezvousRelay);

        $introCircuit = null;

        try {
            $cookie = random_bytes(20);
            $rendezvousCircuit->sendRelay(
                Commands::RELAY_ESTABLISH_RENDEZVOUS,
                0,
                $cookie,
                $rendezvousCircuit->hopCount() - 1
            );
            $rendezvousCircuit->waitForRelay(Commands::RELAY_RENDEZVOUS_ESTABLISHED, $this->timeoutFor($timeout));

            $rendezvousSpecs = self::linkSpecifiersFor($rendezvousRelay);
            $ordered = $introPoints;
            shuffle($ordered);

            $introduce = null;
            $lastStatus = null;

            // Try up to three introduction points before giving up; services
            // routinely publish points that have gone away.
            foreach (array_slice($ordered, 0, 3) as $introPoint) {
                $introRelay = $this->relayFromLinkSpecifiers($introPoint['linkSpecifiers']);
                if ($introRelay === null) {
                    continue;
                }

                $introCircuit?->close();
                $introCircuit = $this->buildCircuitTo(
                    $introRelay,
                    [$rendezvousRelay->fingerprint]
                );

                $candidate = $onion->buildIntroduce1(
                    $introPoint,
                    $rendezvousRelay->ntorOnionKey,
                    $rendezvousSpecs,
                    $cookie
                );

                // INTRODUCE1 is not addressed to the first hop, so the circuit
                // layer marks it RELAY_EARLY on its own (tor-spec §5.1.1).
                $introCircuit->sendRelay(
                    Commands::RELAY_INTRODUCE1,
                    0,
                    $candidate['body'],
                    $introCircuit->hopCount() - 1
                );

                $ack = $introCircuit->waitForRelay(Commands::RELAY_INTRODUCE_ACK, $this->timeoutFor($timeout));
                $lastStatus = strlen($ack['data']) >= 2 ? unpack('n', $ack['data'], 0)[1] : -1;
                if ($lastStatus === 0) {
                    $introduce = $candidate;
                    break;
                }
            }

            if ($introduce === null) {
                throw new TorOnionException(
                    'Every introduction point rejected the request (last status ' . ($lastStatus ?? 'none') . ')'
                );
            }

            $rendezvous2 = $rendezvousCircuit->waitForRelay(
                Commands::RELAY_RENDEZVOUS2,
                $this->timeoutFor(max($timeout, 60.0))
            );

            $keys = $onion->processRend2($introduce, $rendezvous2['data']);
            $rendezvousCircuit->addRendezvousLayer($keys['df'], $keys['db'], $keys['kf'], $keys['kb']);

            $streamId = $rendezvousCircuit->beginStream($onion->hostname(), $port, false, $this->timeoutFor($timeout));
            $response = $this->httpExchange(
                $rendezvousCircuit,
                $streamId,
                $host,
                $port,
                $path,
                $this->timeoutFor($timeout),
                $maxBytes,
                $tls
            );
            $defaultPort = $tls ? 443 : 80;
            $response['url'] = ($tls ? 'https' : 'http') . '://' . $host
                . ($port === $defaultPort ? '' : ':' . $port) . $path;

            return $response;
        } finally {
            $introCircuit?->close();
            $rendezvousCircuit->close();
        }
    }

    /**
     * Try several HSDirs and both replicas until a descriptor is returned.
     */
    private function fetchOnionDescriptor(OnionV3 $onion, float $timeout): string
    {
        $errors = [];
        $replicas = max(1, (int) ($this->params['hsdir_n_replicas'] ?? 2));
        $spread = max(1, (int) ($this->params['hsdir_spread_fetch'] ?? 3));
        $attempts = 0;

        for ($replica = 1; $replica <= $replicas; $replica++) {
            $hsdirs = $this->responsibleHsdirs($onion, $replica);
            if ($hsdirs === []) {
                $errors[] = 'no responsible HSDir for replica ' . $replica;
                continue;
            }

            foreach (array_slice($hsdirs, 0, $spread + 1) as $hsdir) {
                if ($attempts++ >= 6) {
                    break 2;
                }

                $circuit = null;
                try {
                    $this->timeoutFor(1.0);
                    $circuit = $this->buildCircuitTo($hsdir);

                    return $onion->fetchDescriptor($circuit, $this->timeoutFor($timeout));
                } catch (TorOnionException | TorException $e) {
                    // A slow or unresponsive HSDir circuit must not abort the
                    // whole lookup: try the next responsible HSDir instead.
                    $errors[] = $hsdir->nickname . ' replica ' . $replica . ': ' . $e->getMessage();
                } finally {
                    $circuit?->close();
                }
            }
        }

        throw new TorOnionException(
            'Could not download the descriptor for ' . $onion->hostname() . ': ' . implode('; ', $errors)
        );
    }

    /**
     * Disaster shared random value used when the consensus carries no SRV
     * (tor hs_common.c compute_disaster_srv):
     *
     *   H("shared-random-disaster" | INT_8(period_length) | INT_8(period_num))
     */
    public static function disasterSharedRandom(int $periodNum, int $periodLengthMinutes): string
    {
        return Keccak::sha3_256(
            'shared-random-disaster'
            . pack('J', $periodLengthMinutes)
            . pack('J', $periodNum)
        );
    }

    /**
     * HSDir's position in the hash ring (rend-spec-v3 §2.2.3).
     */
    public static function hsdirIndex(
        string $ed25519Id,
        string $sharedRandom,
        int $periodNum,
        int $periodLengthMinutes
    ): string {
        return Keccak::sha3_256(
            'node-idx' . $ed25519Id . $sharedRandom
            . pack('J', $periodNum) . pack('J', $periodLengthMinutes)
        );
    }

    /**
     * HSDirs responsible for one replica of this service's descriptor.
     *
     * @return RelayInfo[]
     */
    public function responsibleHsdirs(OnionV3 $onion, int $replica): array
    {
        if ($this->sharedRandom === null) {
            // tor hs_common.c hs_get_current_srv(): with no published SRV Tor
            // does not disable onion services, it falls back to the disaster
            // value for the descriptor's time period.
            $sharedRandom = self::disasterSharedRandom(
                $onion->periodNum(),
                $onion->periodLengthMinutes()
            );
        } else {
            $sharedRandom = self::selectSharedRandom(
                $this->validAfter ?? time(),
                $this->periodLength,
                $this->sharedRandom,
                $this->previousSharedRandom
            );
        }

        $nodes = [];
        foreach ($this->relays as $relay) {
            if ($relay->ed25519Id === null || !$relay->hasFlag('HSDir') || $relay->orPort <= 0) {
                continue;
            }

            $nodes[] = [
                'relay' => $relay,
                'index' => self::hsdirIndex(
                    $relay->ed25519Id,
                    $sharedRandom,
                    $onion->periodNum(),
                    $onion->periodLengthMinutes()
                ),
            ];
        }

        if ($nodes === []) {
            return [];
        }

        usort($nodes, static fn (array $a, array $b): int => strcmp($a['index'], $b['index']));

        $key = $onion->hsIndex($replica);
        $start = 0;
        foreach ($nodes as $index => $node) {
            if (strcmp($node['index'], $key) >= 0) {
                $start = $index;
                break;
            }
        }

        $spread = max(1, (int) ($this->params['hsdir_spread_fetch'] ?? 3));
        $count = count($nodes);
        $selected = [];
        for ($i = 0; $i < $spread && $i < $count; $i++) {
            $selected[] = $nodes[($start + $i) % $count]['relay'];
        }

        return $selected;
    }

    /**
     * Pick the SRV that indexes the current descriptor period.
     *
     * SRV protocol runs are aligned to 00:00 UTC while hidden-service time
     * periods start at 12:00 UTC. During the first half of an SRV run the
     * consensus "current" value belongs to the next period, so the previous
     * value is the one that indexes the period being fetched (Tor's
     * hs_in_period_between_tp_and_srv).
     */
    public static function selectSharedRandom(
        int $validAfter,
        int $periodLengthMinutes,
        string $current,
        ?string $previous
    ): string {
        if ($previous === null || $periodLengthMinutes <= 0) {
            return $current;
        }

        $minutes = intdiv($validAfter, 60);
        $srvRunStart = intdiv($minutes, $periodLengthMinutes) * $periodLengthMinutes;
        $usePrevious = ($minutes - $srvRunStart) < intdiv($periodLengthMinutes, 2);

        return $usePrevious ? $previous : $current;
    }

    /**
     * Build a path ending at $target whose first hop is a Guard.
     *
     * @param string[] $exclude
     * @return RelayInfo[]
     */
    private function pathTo(RelayInfo $target, array $exclude = []): array
    {
        $guard = $this->selectGuard($exclude);
        $middleCount = max(0, $this->pathLength - 2);

        $middles = $middleCount === 0 ? [] : $this->pickHops(
            $middleCount,
            ['Fast', 'Running'],
            array_merge($exclude, [$guard->fingerprint, $target->fingerprint])
        );

        return array_merge([$guard], $middles, [$target]);
    }

    /**
     * Send an HTTP/1.0 request over an open stream and read the response.
     *
     * @return array{status: int, headers: array<string, string[]>, body: string}
     */
    private function httpExchange(
        Circuit $circuit,
        int $streamId,
        string $host,
        int $port,
        string $path,
        float $timeout,
        int $maxBytes = 8388608,
        bool $tls = false
    ): array {
        $defaultPort = $tls ? 443 : 80;
        $authority = $host . ($port === $defaultPort ? '' : ':' . $port);
        $request = 'GET ' . $path . " HTTP/1.0\r\n"
            . 'Host: ' . $authority . "\r\n"
            . "User-Agent: TorPHP/1.0\r\n"
            . "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n"
            . "Accept-Encoding: identity\r\n"
            . "Connection: close\r\n\r\n";

        $tlsStream = null;
        if ($tls) {
            // Onion services use self-signed certificates: the onion address
            // itself authenticates the endpoint, as in Tor Browser. Clearnet
            // hosts are always verified against the system CA store.
            $sslOptions = str_ends_with($host, '.onion') ? ['allow_self_signed' => true] : [];
            $tlsStream = TlsStream::connect(
                new CircuitByteStream($circuit, $streamId),
                $host,
                $sslOptions,
                $timeout
            );
            $tlsStream->write($request);
        } else {
            $circuit->sendData($streamId, $request);
        }

        $raw = '';
        $deadline = microtime(true) + $timeout;
        $contentLength = null;
        $headersParsed = false;

        while (microtime(true) < $deadline) {
            try {
                $chunk = $tlsStream !== null
                    ? $tlsStream->read(max(0.5, $deadline - microtime(true)))
                    : $circuit->readStreamData($streamId, max(0.5, $deadline - microtime(true)));
            } catch (TorStreamException) {
                break;
            }

            if ($chunk === '') {
                continue;
            }

            $raw .= $chunk;
            if (strlen($raw) > $maxBytes) {
                throw new TorException('Proxied response exceeds the ' . $maxBytes . '-byte limit');
            }

            if (!$headersParsed && str_contains($raw, "\r\n\r\n")) {
                $headersParsed = true;
                $response = DirectoryFetcher::parseHttpResponse($raw);
                $contentLength = isset($response['headers']['content-length'][0])
                    ? (int) $response['headers']['content-length'][0]
                    : null;
                $chunked = isset($response['headers']['transfer-encoding'][0])
                    && stripos($response['headers']['transfer-encoding'][0], 'chunked') !== false;

                if ($contentLength === null && !$chunked) {
                    // Read until the remote closes the stream.
                    continue;
                }
            }

            if ($headersParsed && $contentLength !== null) {
                $response = DirectoryFetcher::parseHttpResponse($raw);
                if (strlen($response['body']) >= $contentLength) {
                    break;
                }
            } elseif ($headersParsed && str_ends_with($raw, "0\r\n\r\n")) {
                break;
            }
        }

        if ($tlsStream !== null) {
            $tlsStream->close();
        }
        $circuit->closeStream($streamId);

        return DirectoryFetcher::parseHttpResponse($raw);
    }

    /**
     * Pick $count relays that carry all $flags.
     *
     * @param string[] $flags
     * @param string[] $exclude
     * @return RelayInfo[]
     */
    public function pickHops(int $count, array $flags, array $exclude = []): array
    {
        return $this->pickPath($count, $flags, $exclude);
    }

    /**
     * A ns-flavor consensus carries no ntor onion key, so relays from one are
     * selectable before their descriptor has been fetched.
     */
    private function isSelectable(RelayInfo $relay): bool
    {
        if ($relay->orPort <= 0 || strlen($relay->identityDigest) !== 20) {
            return false;
        }
        if ($relay->ntorOnionKey === null) {
            // With an HSDir-only bootstrap, path relays have no microdescriptor
            // yet; ensureOnionKey() fills them in from router descriptors.
            return $this->hsdirOnlyBootstrap || !$this->microdescFlavor;
        }

        return $relay->isUsable();
    }

    /**
     * Fill in a relay's onion key from its authenticated router descriptor.
     */
    private function ensureOnionKey(RelayInfo $relay): void
    {
        if ($relay->ntorOnionKey !== null) {
            return;
        }

        $identity = $this->directory->relayIdentity($relay);
        if (($identity['ntor'] ?? null) === null) {
            throw new TorDirectoryException(
                'Router descriptor for ' . $relay->nickname . ' has no ntor onion key'
            );
        }

        $relay->ntorOnionKey = $identity['ntor'];
    }

    /**
     * First hop for a circuit: the persisted guard when it is still eligible.
     *
     * @param string[] $exclude
     */
    private function selectGuard(array $exclude): RelayInfo
    {
        $candidates = [];
        foreach ($this->relays as $relay) {
            if (!$relay->hasFlag('Guard') || !$relay->canExtend() || !$this->isSelectable($relay)) {
                continue;
            }
            $candidates[] = $relay;
        }

        $guard = $this->guards?->select($candidates, $exclude);
        if ($guard !== null) {
            return $guard;
        }

        return $this->pickHops(1, ['Guard', 'Fast', 'Running'], $exclude)[0];
    }

    /**
     * Switch the persistent entry guard, never reusing the current one.
     *
     * Used by the bridge's "change guard" control. New circuits after this
     * call start at a different guard; in-flight circuits are unaffected.
     */
    public function changeGuard(): RelayInfo
    {
        if ($this->relays === []) {
            $this->bootstrap();
        }

        $candidates = [];
        foreach ($this->relays as $relay) {
            if ($relay->hasFlag('Guard') && $relay->canExtend() && $this->isSelectable($relay)) {
                $candidates[] = $relay;
            }
        }

        $guard = $this->guards?->rotate($candidates);
        if ($guard === null) {
            throw new TorException('No alternative entry guard is available');
        }

        return $guard;
    }

    /**
     * Map an introduction point's link specifiers onto a consensus relay.
     *
     * @param array<int, array{type: int, data: string}> $specs
     */
    public function relayFromLinkSpecifiers(array $specs): ?RelayInfo
    {
        foreach ($specs as $spec) {
            if ($spec['type'] === 0x02 && strlen($spec['data']) === 20) {
                $relay = $this->relayByFingerprint(bin2hex($spec['data']));
                if ($relay !== null) {
                    return $relay;
                }
            }
        }

        foreach ($specs as $spec) {
            if ($spec['type'] === 0x03 && strlen($spec['data']) === 32) {
                foreach ($this->relays as $relay) {
                    if ($relay->ed25519Id !== null && hash_equals($relay->ed25519Id, $spec['data'])) {
                        return $relay;
                    }
                }
            }
        }

        return null;
    }

    /**
     * Build the link specifiers an introduction point needs to reach a relay.
     *
     * @return array<int, array{type: int, data: string}>
     */
    public static function linkSpecifiersFor(RelayInfo $relay): array
    {
        $specs = [];
        $ipv4 = filter_var($relay->address, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4);
        if ($ipv4 !== false) {
            $specs[] = ['type' => 0x00, 'data' => inet_pton($relay->address) . pack('n', $relay->orPort)];
        }
        $specs[] = ['type' => 0x02, 'data' => $relay->identityDigest];
        if ($relay->ed25519Id !== null) {
            $specs[] = ['type' => 0x03, 'data' => $relay->ed25519Id];
        }

        return $specs;
    }
}
