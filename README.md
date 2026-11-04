# TorPHP — native Tor v3 client and onion bridge

A pure-PHP Tor client that speaks the Tor protocol itself. It builds real
three-hop circuits with `CREATE2`/ntor, extends them with `RELAY_EXTEND2`, and
loads v3 onion services through descriptor fetch, introduction and rendezvous —
with **no `tor` binary, no SOCKS proxy, no HTTP proxy and no external process**.

It also ships `bridge.php`, a small gateway that re-serves `.onion` pages on the
ordinary web with rewritten links, so a normal browser can read onion sites
without Tor Browser.

Verified live against the public network: v3 onion pages return `HTTP 200`
through the full hidden-service flow, clearnet pages load through exit circuits,
and `https://` works over both (self-signed certificates are accepted for
`.onion` only; clearnet certificates are verified normally).

---

## Contents

- [Requirements](#requirements)
- [Installation](#installation)
- [Quick start (library)](#quick-start-library)
- [The bridge](#the-bridge)
- [Entry guards](#entry-guards)
- [Redirects](#redirects)
- [API reference](#api-reference)
- [How it works](#how-it-works)
- [Testing](#testing)
- [Troubleshooting](#troubleshooting)
- [Security notes and limitations](#security-notes-and-limitations)
- [Use cases](#use-cases)
- [File layout](#file-layout)

---

## Requirements

- **PHP 8.1 or newer** (CLI, PHP-FPM, Apache module or the built-in server).
- Extensions: `openssl`, `sodium`, `gmp`, `hash` (built in), `zlib`.
- Outbound TCP to Tor ORPorts (commonly 443, 9001, 9030, 9100…) and to directory
  authorities on 443. No inbound ports are needed.
- A writable directory for the consensus cache and guard state.

No Composer install, database, Redis, or system packages are required.

## Installation

Unzip the archive anywhere:

```
torphp/
├── autoload.php      PSR-4 autoloader for Torv3\
├── bridge.php        web gateway (optional)
├── README.md
├── src/              the client
└── tests/            offline vectors and live smoke tests
```

Include the autoloader and use the `Torv3\` namespace:

```php
require '/path/to/torphp/autoload.php';
```

---

## Quick start (library)

```php
<?php
declare(strict_types=1);

require __DIR__ . '/autoload.php';

use Torv3\TorClient;
use Torv3\TorException;

// The cache file is created on first use; guards.json is stored next to it.
$tor = TorClient::create(__DIR__ . '/cache/consensus.json')
    ->bootstrap();                       // fetch/refresh the consensus (TTL 1h)

try {
    $page = $tor->request(
        'http://duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad.onion/',
        [
            'follow_redirects' => true,  // http -> https on the same onion
            'timeout' => 60,
        ]
    );

    echo $page['status'], "\n";          // 200
    echo strlen($page['body']), " bytes\n";
} catch (TorException $e) {
    echo 'Tor error: ', $e->getMessage(), "\n";
}
```

Clearnet is opt-in per request:

```php
$res = $tor->request('https://example.com/', [
    'allowClearnet' => true,
    'timeout' => 30,
]);
```

A direct onion request when you already have the parts:

```php
$res = $tor->requestOnion('example…56chars….onion', 80, '/path', 60.0);
```

Response shape (all requests):

```php
[
    'status'  => 200,                       // int, upstream HTTP status
    'headers' => ['content-type' => ['text/html']], // lower-case name => list
    'body'    => '…',
    'url'     => 'https://…',               // final URL (after redirects if enabled)
]
```

---

## The bridge

`bridge.php` turns the library into a browser-friendly onion gateway.

### Deploy

Put `bridge.php`, `autoload.php` and `src/` under a web root. The `cache/`
directory is created automatically and must be writable by PHP:

```bash
mkdir -p cache && chmod 700 cache
```

Local test with the built-in server (the file acts as router):

```bash
php -S 127.0.0.1:8080 bridge.php
# open http://127.0.0.1:8080/
```

With Apache/Nginx, serve `bridge.php` as the front controller or call it
directly. Both URL forms work:

```
/bridge.php?url=http://example…onion/path
/bridge.php/http://example…onion/path
```

`https://` targets work as well: TLS is negotiated inside the Tor stream, and
the onion address authenticates the service (its self-signed certificate is
accepted, as in Tor Browser).

### Configuration

Edit the `$config` array at the top of `bridge.php`:

| Key | Default | Meaning |
| --- | --- | --- |
| `cache_file` | `__DIR__/cache/consensus.json` | Consensus cache; also determines where `guards.json` lives |
| `allow` | `['.onion']` | Host policy. `['*']` also allows clearnet; suffixes like `.example.com` are accepted |
| `rate_limit` | `30` requests / `60` s | Per-client-IP limit, stored outside the doc root |
| `timeout` | `45.0` | Per-request timeout in seconds |
| `max_bytes` | `8 MiB` | Hard cap on a proxied response body |
| `banner` | `true` | Inject a small "served via TorPHP" banner into HTML |
| `time_limit` | `0` | Seconds allowed for the whole request; `0` removes PHP's limit. A fetch takes 20-60 s, so keep this at `0` or use at least `120` |
| `deadline` | `55` | Wall-clock budget for one fetch; the bridge returns `504` at the budget. Keep it below the host's PHP/FPM cap |
| `diagnostics` | `true` | Expose the `?diag=1` environment report |

### What the page does

- **Onion-only by default.** Clearnet targets are refused with `403` unless the
  policy allows them, so the bridge cannot be used as an open web proxy by
  accident.
- **Redirects are followed server-side.** If the onion answers `301`/`302`/…,
  the client follows it inside the tunnel and the final page is rendered at the
  bridge URL. The browser receives `200`, not a `Location` header, so it never
  navigates to another host. Chains are limited to 5 hops and loops are errors.
- **Every hop is re-checked against the allow policy**, so an onion cannot
  redirect the bridge to the clearnet when clearnet is disabled.
- **Links, forms and CSS are rewritten** to stay on the bridge. Relative links
  are resolved against the final URL, and clearnet links become bridge URLs
  that the policy will refuse instead of sending the browser away.
- **Cookies are namespaced per onion** and stripped of attributes that would
  leak them to other onions.
- **Responses are sandboxed** with `Content-Security-Policy: sandbox`, and sent
  with `no-store`, `nosniff` and `no-referrer`.
- **Preset targets.** The landing input offers the DuckDuckGo search onion and
  the CIA's onion site as click/type-ahead suggestions, while still accepting
  any URL typed by hand.
- **Guard button.** The landing page has a *Change entry guard* action. It is a
  `POST` (so crawlers and prefetchers cannot trigger it), rate-limited, and
  changes state on the server only; the page is re-rendered in place with a
  confirmation. The new guard can never be the one currently in use.

### Operating notes

- Run the bridge behind HTTPS if it is exposed to the internet.
- It has no authentication of its own. For a private gateway, add HTTP basic
  auth or restrict it at the firewall/reverse proxy.
- Each proxied request builds fresh circuits; there is no page cache.
- **Raise PHP's execution limit.** Bootstrap, descriptor lookup, rendezvous and
  the page load all happen in one request and routinely take 20-60 s, well past
  PHP's web default of 30 s. The bridge calls `set_time_limit(0)` by default;
  where a host disables that function, set `max_execution_time` to at least
  120 in `php.ini`. Otherwise the host kills the request mid-flight and returns
  a bare `500`; when the host refuses `set_time_limit`, the landing page and
  `?diag=1` show the effective limit so the cause is visible. The bridge also
  stops at its own `deadline` (55 s by default) and answers `504` with the
  reason, so a hard host cap does not cut the connection with an empty 500.
- **Use `?diag=1` when something fails.** It reports the PHP version and
  limits, whether the required extensions are loaded, cache writability, whether
  outbound directory TCP is reachable, and the most recent errors (paths
  masked). Fatals are also converted into a readable `500` page instead of an
  empty response.
- PHP workers block while a request is in flight, so concurrency equals the
  number of PHP-FPM workers.

---

## Entry guards

Like Tor, the client pins one entry guard instead of picking a random first hop
for every circuit (guard-spec). The guard is chosen from relays with the `Guard`
flag, persisted in `guards.json`, reused across requests and restarts, and
dropped automatically if it cannot be reached.

```php
$newGuard = $tor->changeGuard();   // RelayInfo of the new entry guard
echo $newGuard->nickname;
```

Rotation never returns the current guard. It replaces the remembered sample so
new circuits start at the new guard; circuits already open keep their old one.
If no alternative guard exists, it throws `TorException` and leaves the current
guard in place.

Middleware selection and the final hop are still randomized per circuit:

- clearnet: random middle (`Fast`, `Running`) + random exit (`Exit`, `Fast`, `Running`);
- onion: the last hop is the responsible HSDir, an introduction point or the
  rendezvous relay — never a clearnet exit.

Unresponsive relays are retried: a circuit that stalls on `EXTEND2` is rebuilt
with a fresh path up to three times before the request fails.

---

## Redirects

`request()` returns the raw upstream response by default, including `3xx`, so
callers can decide what to do. Opt in to automatic following:

```php
$res = $tor->request($url, [
    'follow_redirects' => true,
    'max_redirects'    => 5,     // default 5
]);
```

- Follows `301`, `302`, `303`, `307`, `308`.
- Resolves absolute, scheme-relative, root-relative and path-relative
  `Location` values, collapsing `.`/`..` segments.
- Rejects loops (`Redirect loop detected at …`) and chains over the limit.
- Re-checks `allowClearnet` on every hop, so an onion cannot silently send the
  client to the clearnet.
- `$res['url']` is the final URL.

`bridge.php` always enables this, which is why onion pages that redirect
`http → https` render directly in the browser.

---

## API reference

### `Torv3\TorClient`

| Method | Purpose |
| --- | --- |
| `create(?string $cacheFile = null): self` | New client. `null` means no on-disk cache |
| `bootstrap(bool $force = false, int $ttl = 3600, bool $hsdirOnly = false): self` | Load or refresh the consensus. `hsdirOnly` keeps only HSDir relays for onion lookups |
| `request(string $url, array $options = []): array` | Fetch a URL through Tor (see options below) |
| `requestOnion(string $host, int $port, string $path, float $timeout = 30.0, bool $tls = false, ?string $clientAuthKey = null, int $maxBytes = 8388608): array` | Full v3 onion flow when the URL is already split |
| `changeGuard(): RelayInfo` | Rotate the persistent entry guard |
| `relays(): array` | Consensus relays, keyed by fingerprint |
| `consensusParams(): array` | Consensus parameters (`hsdir-interval`, spreads, …) |
| `relayByFingerprint(string $hex): ?RelayInfo` | Look up one relay |
| `pickPath(int $hops, array $require = [], array $exclude = []): array` | Random path honouring flags |
| `pickHops(int $count, array $flags, array $exclude = []): array` | Random relays with flags |
| `buildCircuit(array $hops): Circuit` | Build a circuit over given relays |
| `responsibleHsdirs(OnionV3 $onion, int $replica): array` | HSDir set for a descriptor replica |
| `relayFromLinkSpecifiers(array $specs): ?RelayInfo` | Map descriptor link specifiers to a relay |

Lower-level building blocks are available too: `Torv3\Circuit\Circuit`,
`Torv3\Onion\OnionV3`, `Torv3\Directory\DirectoryFetcher`,
`Torv3\Link\LinkSession`, `Torv3\Transport\TlsStream` and
`Torv3\Bridge\Rewriter`.

### Request options

| Option | Default | Meaning |
| --- | --- | --- |
| `allowClearnet` | `false` | Permit non-`.onion` hosts |
| `timeout` | `30.0` | Seconds per network operation |
| `deadline` | none | Absolute `microtime(true)` deadline; every wait is clamped to it and a `TorException` is thrown when it expires |
| `max_bytes` | `8388608` | Response body cap (onion and clearnet) |
| `client_auth_key` | `null` | 32 raw bytes or base64 x25519 key for authorized onions |
| `follow_redirects` | `false` | Follow `3xx` responses |
| `max_redirects` | `5` | Redirect chain limit |

### Exceptions

All errors derive from `Torv3\TorException`:
`TorProtocolException`, `TorConnectionException`, `TorDirectoryException`,
`TorNetworkException`, `TorOnionException`, `TorStreamException`.
They carry no relay addresses in the bridge's user-facing messages.

---

## How it works

1. **Directory.** Fetch a microdescriptor consensus from the authorities,
   verify the signatures, parse relays, flags, ntor onion keys and consensus
   parameters (including `hsdir-interval`, replica/spread counts and the shared
   random value). Results are cached as gzipped JSON.
2. **Link.** Open a TLS connection to a guard, negotiate a link version
   (v3/v4, 4-byte circuit IDs), exchange `CERTS`/`AUTH_CHALLENGE`/
   `AUTHENTICATE`/`NETINFO` where required.
3. **Circuits.** `CREATE2` with the ntor handshake for the first hop, then
   `RELAY_EXTEND2` + ntor for each further hop, sealing/decrypting relay cells
   per layer. `RELAY_EARLY` is used only for `EXTEND`. Flow control uses
   authenticated SENDME v1 cells, and streams are multiplexed on the circuit.
4. **Streams.** `RELAY_BEGIN` for TCP, `RELAY_BEGIN_DIR` for directory
   connections. HTTP/1.0 is spoken directly over the stream; `https://` wraps
   the stream in TLS.
5. **v3 onion services.**
   - Decode the 56-character address (pubkey, checksum, version).
   - Blind the identity key for the current time period and derive the
     subcredential.
   - Compute the HSDir ring index from the shared random value (falling back to
     Tor's deterministic disaster value when the consensus has none), pick the
     responsible HSDirs and fetch the descriptor by its blinded-key path.
   - Verify the descriptor's Ed25519 certificate and signature, decrypt the
     superencrypted and encrypted layers, and parse introduction points.
   - `ESTABLISH_RENDEZVOUS`, send `INTRODUCE1` (hs-ntor) to an introduction
     point, wait for `RENDEZVOUS2`, derive the service keys, then `BEGIN` the
     stream to the onion service and speak HTTP over it.
6. **Clearnet.** A three-hop circuit ending at a random exit relay, with normal
   certificate verification for `https://`.

Every request builds new circuits; nothing is shared between requests except
the consensus cache and the guard choice.

---

## Testing

Offline vectors (no network needed):

```bash
php tests/run.php            # main suite: 85 checks
php tests/guard_test.php     # guard stickiness and rotation
php tests/bridge_test.php    # URL/cookie rewriting rules
php tests/srv_test.php       # disaster shared-random value
php tests/onion_vector_test.php  # Tor's own HS vectors
php tests/tls_test.php       # TLS transport (uses tests/tls_echo_server.php)
```

Live network smoke test (downloads a consensus and builds circuits):

```bash
php tests/live_smoke.php
```

A full live check of both paths looks like this:

```php
$tor = TorClient::create('/tmp/tor-cache.json')->bootstrap();

$onion = $tor->request('http://duckduckgogg…onion/', [
    'follow_redirects' => true,
    'timeout' => 60,
]);
echo $onion['status'], ' ', strlen($onion['body']), "\n";   // 200, ~230 KB

$web = $tor->request('http://example.com/', [
    'allowClearnet' => true,
    'timeout' => 30,
]);
echo $web['status'], "\n";                                  // 200
```

Live results depend on relay availability. Expect occasional multi-second
circuit setup; the built-in retry handles one dead middle or exit.

---

## Troubleshooting

| Symptom | Cause / fix |
| --- | --- |
| `403` from the bridge | Target is not allowed by `$config['allow']`; add a suffix or `'*'` deliberately |
| Bare `500` or empty response | The host killed the request at its PHP execution limit (default 30 s, a fetch needs 20-60 s). Raise `max_execution_time` / keep `set_time_limit` enabled, then open `?diag=1` |
| `Bridge error` page | A fatal was turned into a readable 500; `?diag=1` shows the logged cause (missing extension, unwritable cache, blocked egress) |
| `504` "did not finish within the bridge's … budget" | The fetch hit `deadline`; the onion is slow or the host blocks Tor relay ports. Raise `deadline` only if the host's PHP cap is higher |
| `404` from every HSDir | Onion service offline, or the network consensus has no shared random value (see below) |
| `Could not download the descriptor … 404` | Period/SRV mismatch or unpublished service; retry after the next consensus |
| `Timed out waiting for relay command 15` | A middle relay did not answer `EXTEND2`; the client retries with a new path, increase `timeout` if it persists |
| `Unable to open TLS connection …` | Guard/relay unreachable from this host; check egress firewall and ORPort reachability |
| `Descriptor MAC verification failed` | Wrong key material or a corrupt cached consensus — clear `cache/` and retry |
| `No alternative entry guard is available` | Consensus has too few usable `Guard` relays; refresh with `bootstrap(true)` |
| Clearnet blocked | Pass `allowClearnet => true` (library) or adjust the bridge policy |
| `Permission denied` on cache | Make the cache directory writable by the PHP user |

**Shared-random outages.** Tor's hidden-service directory uses a shared random
value published in the 00:00 UTC consensus. If the network's shared-random run
fails, the consensus can carry no current/previous value. The client follows
Tor and falls back to the deterministic disaster value, but onion descriptors may
be missing network-wide until a later round completes. Clearnet circuits are
unaffected. This is a network condition, not a client error.

---

## Security notes and limitations

- **Not audited.** Treat this as experimental software; review it before using
  it where anonymity is critical.
- **Client, not a service.** It fetches onion services; it cannot host one.
- **v3 only.** 16-character v2 addresses are not supported.
- **No SOCKS/HTTP proxy interface.** Use `TorClient` directly or `bridge.php`.
- **Blocking I/O.** Each PHP worker handles one request at a time.
- **Onion TLS** accepts self-signed certificates because the onion address
  authenticates the endpoint (as Tor Browser does). Clearnet TLS is verified
  against the system CA store.
- **Client authorization** can consume an existing x25519 key; it does not
  generate or manage authorized-client key pairs.
- **The bridge operator can see destinations.** It is a gateway, not a
  anonymity network for its users. Add authentication/TLS and rate limits
  before exposing it.
- **No traffic-analysis resistance beyond Tor's own.** Circuit timing and sizes
  are ordinary Tor traffic, but the PHP implementation is not hardened against a
  local observer.
- **No license file is bundled** with this archive; add one before
  redistributing.

---

## Use cases

- **Onion access on shared hosting** where installing `tor`, a daemon or a
  SOCKS proxy is impossible — only PHP and outbound TCP are needed.
- **Server-side onion fetching**: mirrors, archives, feed readers, uptime and
  content monitoring, or scheduled jobs that read `.onion` pages.
- **A team or browser gateway**: let people read onion sites from an ordinary
  browser through `bridge.php`, with an onion-only policy and per-IP limits.
- **CI and integration tests** for onion services: assert that a descriptor is
  published and the service answers, without a tor binary in the image.
- **Protocol work and teaching**: the circuit, relay-cell, SENDME and HS v3
  flows are readable PHP with Tor's test vectors in `tests/`.
- **Policy front-ends**: embed the client in an application that needs to fetch
  onion content but must enforce its own allow-list, size limits and timeouts.

---

## File layout

```
autoload.php                 PSR-4 autoloader
bridge.php                   web gateway
src/
├── Bridge/Rewriter.php      link, form, CSS and cookie rewriting
├── Cell/                    cell framing and relay commands
├── Circuit/                 circuit creation, extension, streams, flow control
├── Crypto/                  AES-CTR, Ed25519, Keccak/SHAKE, ntor, RSA verify
├── Directory/               consensus/microdescriptor fetch, guards, relay info
├── Link/                    TLS link handshake and authentication
├── Onion/                   v3 addresses, descriptors, hs-ntor, INTRODUCE1
├── Transport/               byte streams over TLS and circuits
├── TorClient.php            high-level API
└── TorException.php         exception hierarchy
tests/                       vectors, unit checks and live smoke test
```

---

*TorPHP speaks the Tor protocol directly. It is independent of the Tor Project
and is not endorsed by it.*
