<?php

declare(strict_types=1);

/**
 * TorPHP bridge: fetch a .onion page through a native PHP Tor v3 client and
 * re-serve it on the ordinary web, rewriting links so navigation stays inside
 * the bridge.
 *
 * Deploy this file, autoload.php and src/ on any PHP 8.1+ web server.
 * No tor binary, no SOCKS proxy, no external process.
 */

require __DIR__ . '/autoload.php';

use Torv3\Bridge\Rewriter;
use Torv3\Directory\DirectoryFetcher;
use Torv3\Onion\OnionV3;
use Torv3\TorClient;
use Torv3\TorException;

$config = [
    // Consensus cache; the directory is re-fetched when older than an hour.
    'cache_file' => __DIR__ . '/cache/consensus.json',
    // Default policy: onion services only. Use ['*'] to allow clearnet too.
    'allow' => ['.onion'],
    // Per-client-IP rate limit.
    'rate_limit' => ['requests' => 30, 'window' => 60],
    'timeout' => 45.0,
    // Hard cap on a proxied response body.
    'max_bytes' => 8 * 1024 * 1024,
    'banner' => true,
    // A fetch routinely takes 20-60 s end to end: bootstrap, descriptor
    // lookup, rendezvous and TLS all happen inside this one web request.
    // PHP's default web limit of 30 s aborts that mid-flight, which most
    // hosts surface as a bare HTTP 500. 0 removes the limit; a number caps it.
    'time_limit' => 0,
    // Wall-clock budget for one fetch. Keep it below the host's own PHP or
    // FPM cap (for example 55 on a 60 s host): the bridge answers 504 at the
    // budget instead of being killed mid-request.
    'deadline' => 55.0,
    // ?diag=1 reports PHP limits, extensions, cache state and egress.
    'diagnostics' => true,
];

// Without this the host kills the request at its 30 s default and the visitor
// gets an empty 500. set_time_limit returns false when a host disables it;
// ?diag=1 reports that so the limit can be raised in php.ini instead.
@set_time_limit((int) ($config['time_limit'] ?? 0));
@ini_set('max_execution_time', (string) ($config['time_limit'] ?? 0));

// Any fatal (timeout, memory limit, missing extension) would otherwise reach
// the visitor as an empty 500 with no clue what happened.
register_shutdown_function('bridge_fatal_handler');

/* --------------------------------------------------------------------------
 * Request routing
 * -------------------------------------------------------------------------- */

$method = strtoupper($_SERVER['REQUEST_METHOD'] ?? 'GET');

// Entry-guard rotation is the only state-changing action the bridge exposes.
// It is a POST so link prefetchers and crawlers cannot rotate the guard, and
// it passes through the same per-IP rate limit as fetches.
if ($method === 'POST') {
    if (($_POST['action'] ?? '') !== 'change-guard') {
        send_error(405, 'Method not allowed', 'The bridge only accepts POST for guard changes.');
    }

    enforce_rate_limit($config);

    try {
        $tor = TorClient::create($config['cache_file'])->bootstrap(false, 3600);
        $tor->changeGuard();
    } catch (TorException $e) {
        send_error(502, 'Guard change failed', 'Could not switch to another entry guard. Try again later.');
    } catch (\Throwable $e) {
        bridge_log('guard change failed: ' . $e->getMessage());
        send_error(500, 'Bridge error', 'The bridge could not change its entry guard. Open ?diag=1 for the environment report.');
    }

    show_landing_page('Entry guard changed. New circuits start at a different guard.');
    exit;
}

if ($method !== 'GET' && $method !== 'HEAD') {
    send_error(405, 'Method not allowed', 'The bridge only serves GET and HEAD requests.');
}

if (isset($_GET['diag']) && ($config['diagnostics'] ?? false)) {
    show_diagnostics($config);
    exit;
}

$target = null;

if (isset($_GET['url']) && is_string($_GET['url']) && $_GET['url'] !== '') {
    $target = $_GET['url'];
} elseif (isset($_SERVER['PATH_INFO']) && $_SERVER['PATH_INFO'] !== '/') {
    $target = ltrim((string) $_SERVER['PATH_INFO'], '/');
}

if ($target === null) {
    show_landing_page();
    exit;
}

$target = trim($target);
if (!preg_match('#^https?://#i', $target)) {
    if (preg_match('#^[a-z2-7]{56}\.onion#i', $target)) {
        $target = 'http://' . $target;
    } else {
        send_error(400, 'Bad request', 'Provide a URL such as ?url=http://example.onion/path');
    }
}

$parts = parse_url($target);
if (!is_array($parts) || !isset($parts['host'])) {
    send_error(400, 'Bad request', 'That URL could not be parsed.');
}

$host = strtolower($parts['host']);
$scheme = strtolower($parts['scheme'] ?? 'http');

if (!is_host_allowed($host, $config)) {
    send_error(403, 'Blocked by policy', 'The bridge is configured to reach onion services only.');
}

if ($scheme !== 'http' && $scheme !== 'https') {
    send_error(501, 'Scheme not supported', 'The bridge supports HTTP and HTTPS URLs.');
}

enforce_rate_limit($config);

$path = ($parts['path'] ?? '/') . (isset($parts['query']) ? '?' . $parts['query'] : '');

// A CR/LF in the path would be injected into the request line sent through
// the tunnel, so reject control characters outright.
if (preg_match('/[\x00-\x1f\x7f]/', $path) === 1 || preg_match('/[\x00-\x20\x7f]/', $host) === 1) {
    send_error(400, 'Bad request', 'That URL contains invalid characters.');
}

$startedAt = microtime(true);
$deadline = $startedAt + (float) $config['deadline'];

try {
    $tor = TorClient::create($config['cache_file'])->bootstrap(false, 3600);
    $response = $tor->request($target, [
        'timeout' => $config['timeout'],
        'max_bytes' => $config['max_bytes'],
        'deadline' => $deadline,
        // Resolve onion redirects server-side so the visitor stays on the
        // bridge page. Cross-host targets still have to pass the allow policy
        // (onion-only by default), so a service cannot bounce the browser to
        // the clearnet.
        'follow_redirects' => true,
        'max_redirects' => 5,
    ]);
} catch (TorException $e) {
    $message = strtolower($e->getMessage());
    bridge_log('request failed: ' . $e->getMessage());

    if (str_contains($message, 'deadline')) {
        send_error(
            504,
            'Tor request timed out',
            'The fetch did not finish within the bridge\'s ' . (int) $config['deadline']
            . ' s budget. The onion may be slow, or this host blocks some Tor relay ports.'
        );
    }

    $code = str_contains($message, 'timed out') ? 504 : 502;
    // Do not leak relay names, addresses or internal exception details.
    send_error($code, 'Tor request failed', 'The request through the Tor network failed. Check the address and try again.');
} catch (\Throwable $e) {
    // Errors such as a missing extension or an unwritable cache are not
    // TorExceptions; log the detail and fail with a readable page.
    bridge_log('request failed: ' . get_class($e) . ': ' . $e->getMessage());
    send_error(500, 'Bridge error', 'The Tor client could not complete this request. Open ?diag=1 for the environment report.');
}

$elapsed = microtime(true) - $startedAt;
if ($elapsed > 5.0) {
    bridge_log(sprintf('fetch %s completed in %.1fs', $host, $elapsed));
}

$status = (int) $response['status'];
$headers = $response['headers'];
$body = $response['body'];
$contentType = $headers['content-type'][0] ?? 'application/octet-stream';

// Redirects are followed inside the tunnel; link rewriting, cookie scoping
// and the display header must use where the content actually came from.
$finalUrl = is_string($response['url'] ?? null) && $response['url'] !== '' ? $response['url'] : $target;
$finalParts = parse_url($finalUrl);
if (is_array($finalParts) && isset($finalParts['host'])) {
    $host = strtolower($finalParts['host']);
}

foreach (['content-security-policy', 'content-security-policy-report-only', 'x-frame-options', 'strict-transport-security'] as $blocked) {
    unset($headers[$blocked]);
}

// Cookies must be forwarded even when the upstream response is a redirect.
foreach ($headers['set-cookie'] ?? [] as $cookie) {
    $scoped = scope_cookie($cookie, $host);
    if ($scoped !== '') {
        header('Set-Cookie: ' . $scoped, false);
    }
}

http_response_code($status === 0 ? 502 : $status);
header('Content-Type: ' . $contentType);
header('X-TorPHP-Onion: ' . $host);
header('Cache-Control: no-store');
header('X-Content-Type-Options: nosniff');
header('Referrer-Policy: no-referrer');
// Any onion service can return arbitrary HTML/JS. Sandbox it in an opaque
// origin so it cannot read the bridge's cookies, call the bridge API for a
// different onion, or touch same-origin storage.
header('Content-Security-Policy: sandbox allow-forms allow-popups allow-scripts');

if (isset($headers['location'][0])) {
    $location = absolute_url($finalUrl, $headers['location'][0]);
    header('Location: ' . proxy_url($location), true, 302);
    exit;
}

$isHtml = stripos($contentType, 'text/html') !== false || stripos($contentType, 'application/xhtml') !== false;
$isCss = stripos($contentType, 'text/css') !== false;

if ($isHtml) {
    $body = rewrite_html($body, $finalUrl);
    if ($config['banner']) {
        $body = inject_banner($body, $host);
    }
} elseif ($isCss) {
    $body = rewrite_css($body, $finalUrl);
}

// Report the length of the body we would actually send, including for HEAD.
header('Content-Length: ' . strlen($body));

if ($method === 'HEAD' || $status === 204 || $status === 304) {
    exit;
}

echo $body;

/* --------------------------------------------------------------------------
 * Policy, rate limiting, errors
 * -------------------------------------------------------------------------- */

function is_host_allowed(string $host, array $config): bool
{
    return Rewriter::isHostAllowed($host, $config['allow']);
}

function enforce_rate_limit(array $config): void
{
    $limit = (int) ($config['rate_limit']['requests'] ?? 0);
    if ($limit <= 0) {
        return;
    }
    $window = (int) ($config['rate_limit']['window'] ?? 60);

    $ip = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
    // Rate-limit state does not belong under the document root.
    $dir = rtrim(sys_get_temp_dir(), '/') . '/torphp-rate';
    if (!is_dir($dir)) {
        @mkdir($dir, 0770, true);
    }

    $file = $dir . '/rate-' . md5($ip) . '.json';
    $handle = @fopen($file, 'c+');
    if ($handle === false) {
        return;
    }

    if (!flock($handle, LOCK_EX)) {
        fclose($handle);

        return;
    }

    $contents = stream_get_contents($handle);
    $stamps = json_decode($contents ?: '[]', true);
    if (!is_array($stamps)) {
        $stamps = [];
    }

    $now = time();
    $stamps = array_values(array_filter($stamps, static fn ($t): bool => is_int($t) && $now - $t < $window));

    if (count($stamps) >= $limit) {
        flock($handle, LOCK_UN);
        fclose($handle);
        header('Retry-After: ' . $window);
        send_error(429, 'Too many requests', 'Slow down and try again in a minute.');
    }

    $stamps[] = $now;
    ftruncate($handle, 0);
    rewind($handle);
    fwrite($handle, json_encode($stamps));
    fflush($handle);
    flock($handle, LOCK_UN);
    fclose($handle);

    // Occasionally reap stale per-IP files so the directory cannot grow
    // without bound.
    if (random_int(1, 50) === 1) {
        foreach (glob($dir . '/rate-*.json') ?: [] as $stale) {
            if (@filemtime($stale) < $now - 3600) {
                @unlink($stale);
            }
        }
    }
}

/**
 * Namespace a cookie to one onion service and drop attributes that would
 * leak it to other onions or to plain-HTTP clients.
 */
function scope_cookie(string $cookie, string $host): string
{
    return Rewriter::scopeCookie($cookie, $host);
}

function send_error(int $code, string $title, string $detail): void
{
    http_response_code($code);
    header('Content-Type: text/html; charset=utf-8');
    $safeTitle = htmlspecialchars($title, ENT_QUOTES);
    $safeDetail = htmlspecialchars($detail, ENT_QUOTES);
    $codeText = (string) $code;

    echo <<<HTML
<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{$safeTitle}</title>
<style>
:root{color-scheme:dark}
body{margin:0;min-height:100vh;display:grid;place-items:center;background:#0d0b12;color:#e8e3f2;
font:16px/1.6 ui-sans-serif,system-ui,-apple-system,Segoe UI,sans-serif}
.card{max-width:36rem;padding:2.5rem;border:1px solid #322a44;border-radius:1rem;background:#161222}
h1{margin:0 0 .5rem;font-size:1.4rem}
p{margin:.5rem 0;color:#b9aecb}
code{background:#221b33;padding:.15rem .4rem;border-radius:.3rem;font-size:.9em}
a{color:#c4a7ff}
</style></head><body><div class="card">
<h1>{$safeTitle}</h1>
<p><code>HTTP {$codeText}</code></p>
<p>{$safeDetail}</p>
<p><a href="?">Start over</a></p>
</div></body></html>
HTML;

    exit;
}

/**
 * Append one line to the bridge log, rotating it at 1 MiB. The log lives in
 * the system temp directory so it is never served under the document root.
 */
function bridge_log(string $message): void
{
    $dir = rtrim(sys_get_temp_dir(), '/') . '/torphp-logs';
    if (!is_dir($dir) && !@mkdir($dir, 0770, true) && !is_dir($dir)) {
        return;
    }

    $file = $dir . '/bridge.log';
    if (@filesize($file) > 1048576) {
        @rename($file, $file . '.1');
    }

    @file_put_contents(
        $file,
        date('Y-m-d H:i:s') . ' ' . str_replace(["\r", "\n"], ' ', $message) . "\n",
        FILE_APPEND | LOCK_EX
    );
}

/**
 * Turn a fatal error into a readable 500 instead of an empty response, and
 * record it for ?diag=1. Runs on every request; only fatals are reported.
 */
function bridge_fatal_handler(): void
{
    $error = error_get_last();
    if ($error === null || !in_array($error['type'], [E_ERROR, E_PARSE, E_CORE_ERROR, E_COMPILE_ERROR, E_USER_ERROR], true)) {
        return;
    }

    bridge_log('fatal: ' . $error['message'] . ' in ' . $error['file'] . ':' . $error['line']);

    if (headers_sent()) {
        return;
    }

    if (stripos($error['message'], 'maximum execution time') !== false) {
        $hint = 'The host stopped the request at its PHP execution limit. Raise max_execution_time to 120 or more (or keep set_time_limit enabled), then reload.';
    } elseif (stripos($error['message'], 'memory') !== false) {
        $hint = 'The request ran out of PHP memory. Allow at least 128M; a cold fetch peaks around 50-90 MB.';
    } else {
        $hint = 'A fatal PHP error stopped the request. The diagnostics page reports the environment and the logged message.';
    }

    http_response_code(500);
    header('Content-Type: text/html; charset=utf-8');
    header('Cache-Control: no-store');
    header('X-Robots-Tag: noindex');

    $safeHint = htmlspecialchars($hint, ENT_QUOTES);

    echo <<<HTML
<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Bridge error</title>
<style>
:root{color-scheme:dark}
body{margin:0;min-height:100vh;display:grid;place-items:center;background:#0d0b12;color:#e8e3f2;
font:16px/1.6 ui-sans-serif,system-ui,-apple-system,Segoe UI,sans-serif}
.card{max-width:38rem;padding:2.5rem;border:1px solid #322a44;border-radius:1rem;background:#161222}
h1{margin:0 0 .5rem;font-size:1.4rem}
p{margin:.5rem 0;color:#b9aecb}
code{background:#221b33;padding:.15rem .4rem;border-radius:.3rem;font-size:.9em}
a{color:#c4a7ff}
</style></head><body><div class="card">
<h1>Bridge error</h1>
<p><code>HTTP 500</code></p>
<p>{$safeHint}</p>
<p><a href="?diag=1">Diagnostics</a> &middot; <a href="?">Start over</a></p>
</div></body></html>
HTML;
}

/**
 * Environment report for ?diag=1: what the host allows, whether the cache is
 * usable, whether outbound Tor directory TCP works, and the latest errors.
 * Paths in the log tail are masked before they are rendered.
 */
function show_diagnostics(array $config): void
{
    header('Content-Type: text/html; charset=utf-8');
    header('Cache-Control: no-store');
    header('X-Robots-Tag: noindex');

    $required = ['openssl', 'sodium', 'gmp', 'hash', 'zlib'];
    $missing = array_values(array_filter(
        $required,
        static fn (string $extension): bool => !extension_loaded($extension)
    ));

    $cacheFile = (string) $config['cache_file'];
    $cacheDir = dirname($cacheFile);

    if (is_file($cacheFile)) {
        $age = max(0, time() - (int) filemtime($cacheFile));
        $cacheState = sprintf('present, %.1f MB, %d min old', (int) filesize($cacheFile) / 1048576, intdiv($age, 60));
    } else {
        $cacheState = 'missing (the next fetch downloads and verifies the consensus first)';
    }

    $disabled = array_map('trim', explode(',', (string) ini_get('disable_functions')));
    $canSetLimit = function_exists('set_time_limit') && !in_array('set_time_limit', $disabled, true);

    // A single authority or port can be down or filtered on its own, so try
    // several before declaring outbound Tor directory TCP blocked.
    $authorities = [
        ['217.196.147.77', 80],
        ['193.23.244.244', 80],
        ['131.188.40.189', 80],
        ['171.25.193.9', 443],
        ['128.31.0.39', 9231],
    ];
    $egress = 'blocked (no directory authority accepted a TCP connection)';
    if (function_exists('stream_socket_client')) {
        foreach ($authorities as [$address, $port]) {
            $errno = 0;
            $errstr = '';
            $probe = @stream_socket_client(
                'tcp://' . $address . ':' . $port,
                $errno,
                $errstr,
                2.0,
                STREAM_CLIENT_CONNECT
            );
            if (is_resource($probe)) {
                fclose($probe);
                $egress = 'reachable (' . $address . ':' . $port . ')';
                break;
            }
        }
    } else {
        $egress = 'unknown (stream_socket_client is disabled)';
    }

    $logFile = rtrim(sys_get_temp_dir(), '/') . '/torphp-logs/bridge.log';
    $logLines = [];
    if (is_file($logFile)) {
        $lines = @file($logFile, FILE_IGNORE_NEW_LINES) ?: [];
        $logLines = array_slice($lines, -8);
    }
    $logLines = array_map(
        static fn (string $line): string => preg_replace('#(?:/[A-Za-z0-9._-]+){2,}#', '<path>', $line) ?? $line,
        $logLines
    );

    $rows = [
        'PHP' => PHP_VERSION . ' (' . PHP_SAPI . ')',
        'Required extensions' => $missing === [] ? 'all loaded' : 'missing: ' . implode(', ', $missing),
        'max_execution_time' => (string) ini_get('max_execution_time')
            . ($canSetLimit ? ' (set_time_limit is available)' : ' (set_time_limit is disabled; raise it in php.ini)'),
        'memory_limit' => (string) ini_get('memory_limit'),
        'Bridge deadline' => (int) $config['deadline'] . ' s'
            . ((int) ini_get('max_execution_time') > 0
                ? ' (host stops PHP at ' . ini_get('max_execution_time') . ' s)'
                : ''),
        'Consensus cache' => $cacheState,
        'Cache directory' => is_dir($cacheDir) ? (is_writable($cacheDir) ? 'writable' : 'not writable') : 'missing',
        'Outbound directory TCP' => $egress,
    ];

    $rowsHtml = '';
    foreach ($rows as $label => $value) {
        $rowsHtml .= '<tr><th>' . htmlspecialchars($label, ENT_QUOTES) . '</th><td>'
            . htmlspecialchars($value, ENT_QUOTES) . '</td></tr>';
    }

    $logHtml = $logLines === []
        ? '<p>No errors have been logged.</p>'
        : '<pre>' . htmlspecialchars(implode("\n", $logLines), ENT_QUOTES) . '</pre>';

    echo <<<HTML
<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Bridge diagnostics</title>
<style>
:root{color-scheme:dark}
body{margin:0;min-height:100vh;display:grid;place-items:center;background:#0d0b12;color:#e8e3f2;
font:16px/1.6 ui-sans-serif,system-ui,-apple-system,Segoe UI,sans-serif}
.card{width:min(44rem,92vw);padding:2rem;border:1px solid #322a44;border-radius:1rem;background:#161222}
h1{margin:0 0 .75rem;font-size:1.3rem}
table{width:100%;border-collapse:collapse;font-size:.9rem}
th,td{text-align:left;padding:.4rem .5rem;border-bottom:1px solid #2a2338;vertical-align:top}
th{color:#b9aecb;font-weight:500;white-space:nowrap}
td{color:#e8e3f2;word-break:break-word}
pre{white-space:pre-wrap;word-break:break-word;background:#0f0c17;padding:.75rem;border-radius:.5rem;
font-size:.8rem;max-height:16rem;overflow:auto}
p{color:#b9aecb;font-size:.9rem}
a{color:#c4a7ff}
</style></head><body><div class="card">
<h1>Bridge diagnostics</h1>
<table>{$rowsHtml}</table>
<h2 style="font-size:1rem;margin:1.25rem 0 .25rem">Recent log</h2>
{$logHtml}
<p style="margin-top:1.25rem">A fetch needs roughly 20-60 s and about 50-90 MB of memory. If the log reports
<code>Maximum execution time</code>, raise <code>max_execution_time</code>; if directory TCP is blocked,
the host is filtering outbound Tor traffic.</p>
<p><a href="?">Start over</a></p>
</div></body></html>
HTML;
}

function show_landing_page(?string $notice = null): void
{
    header('Content-Type: text/html; charset=utf-8');
    $noticeHtml = $notice === null
        ? ''
        : '<p class="notice">' . htmlspecialchars($notice, ENT_QUOTES) . '</p>';

    // If the host refused set_time_limit(), say so up front: a fetch needs
    // 20-60 s and would otherwise fail later as an unexplained 500.
    $execLimit = (int) ini_get('max_execution_time');
    $limitWarning = $execLimit > 0 && $execLimit <= 60
        ? '<p class="warn">This host stops PHP after ' . $execLimit
            . ' s. An onion fetch usually needs 20-60 s, so slow runs are cut off; raise <code>max_execution_time</code>'
            . ' or enable <code>set_time_limit</code> for reliable fetches.</p>'
        : '';

    echo <<<HTML
<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>TorPHP bridge</title>
<style>
:root{color-scheme:dark}
body{margin:0;min-height:100vh;display:grid;place-items:center;background:#0d0b12;color:#e8e3f2;
font:16px/1.6 ui-sans-serif,system-ui,-apple-system,Segoe UI,sans-serif}
.card{width:min(38rem,90vw);padding:2.5rem;border:1px solid #322a44;border-radius:1rem;background:#161222}
h1{margin:0 0 .25rem;font-size:1.5rem}
p{color:#b9aecb}
form{display:flex;gap:.5rem;margin-top:1.25rem}
input{flex:1;padding:.7rem .9rem;border-radius:.6rem;border:1px solid #3a3150;background:#0f0c17;color:inherit;font:inherit}
button{padding:.7rem 1.1rem;border-radius:.6rem;border:0;background:#7c5cff;color:#fff;font-weight:600;cursor:pointer}
form.guard button{background:#2b2440;border:1px solid #4a3d6b}
.notice{margin-top:.9rem;padding:.6rem .8rem;border-radius:.5rem;background:#17251a;border:1px solid #2f4a34;color:#cfe8cf}
.warn{margin-top:.9rem;padding:.6rem .8rem;border-radius:.5rem;background:#2a1c12;border:1px solid #5a3a1f;color:#f0c9a0}
code{background:#221b33;padding:.15rem .4rem;border-radius:.3rem}
</style></head><body><div class="card">
<h1>🧅 TorPHP bridge</h1>
<p>Native PHP Tor v3 client — no tor binary, no SOCKS, no proxy.</p>
<form method="get">
<input name="url" list="onion-presets" placeholder="http://example.onion/" autofocus>
<datalist id="onion-presets">
<option value="http://duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad.onion/">DuckDuckGo</option>
<option value="http://ciadotgov4sjwlzihbbgxnqg3xiyrg7so2r2o3lt5wz5ypk4sxyjstad.onion/">CIA</option>
</datalist>
<button>Fetch</button></form>
<form method="post" class="guard">
<input type="hidden" name="action" value="change-guard">
<button type="submit">Change entry guard</button>
</form>
{$noticeHtml}
{$limitWarning}
<p style="margin-top:1rem;font-size:.9rem">Direct routing also works: <code>/bridge.php/http://example.onion/path</code></p>
</div><center><a href="./about.html">About</a></center>
</body></html>
HTML;
}

/* --------------------------------------------------------------------------
 * URL rewriting
 *
 * The rules live in Torv3\Bridge\Rewriter so they can be tested without a web
 * server; these wrappers keep the call sites in this file readable.
 * -------------------------------------------------------------------------- */

function bridge_base(): string
{
    return Rewriter::fromServer()->basePath();
}

function proxy_url(string $absolute): string
{
    return Rewriter::fromServer()->proxyUrl($absolute);
}

function absolute_url(string $base, string $reference): string
{
    return Rewriter::fromServer()->absoluteUrl($base, $reference);
}

function normalize_path(string $path): string
{
    return Rewriter::normalizePath($path);
}

function rewrite_html(string $html, string $base): string
{
    return Rewriter::fromServer()->rewriteHtml($html, $base);
}

function rewrite_css(string $css, string $base): string
{
    return Rewriter::fromServer()->rewriteCss($css, $base);
}

function inject_banner(string $html, string $host): string
{
    return Rewriter::injectBanner($html, $host);
}
