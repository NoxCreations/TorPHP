<?php

declare(strict_types=1);

namespace Torv3\Bridge;

/**
 * URL, HTML and CSS rewriting for the bridge web front end.
 *
 * Every link in a proxied document must be routed back through the bridge, or
 * the browser would escape the onion service and hit the address directly.
 * Keeping the rules in a class makes them testable without a web server.
 */
final class Rewriter
{
    public function __construct(private string $basePath = '/bridge.php')
    {
    }

    /**
     * Derive the bridge script path, tolerating PATH_INFO routing such as
     * "/bridge.php/http://example.onion/".
     */
    public static function fromServer(): self
    {
        $script = $_SERVER['SCRIPT_NAME'] ?? '/bridge.php';
        $pathInfo = $_SERVER['PATH_INFO'] ?? '';

        if ($pathInfo !== '' && str_ends_with($script, $pathInfo)) {
            $script = substr($script, 0, -strlen($pathInfo));
        }

        return new self($script === '' ? '/bridge.php' : $script);
    }

    public function basePath(): string
    {
        return $this->basePath;
    }

    /**
     * Wrap an absolute URL so it is fetched through the bridge.
     */
    public function proxyUrl(string $absolute): string
    {
        return $this->basePath . '?url=' . rawurlencode($absolute);
    }

    /**
     * Resolve a reference against the document URL (RFC 3986 §5.2).
     */
    public function absoluteUrl(string $base, string $reference): string
    {
        $reference = trim(html_entity_decode($reference, ENT_QUOTES));
        if ($reference === '') {
            return $base;
        }
        if (str_starts_with($reference, '#')) {
            return $base . $reference;
        }
        if (preg_match('#^(mailto|tel|javascript|data|about|blob|chrome|file):#i', $reference) === 1) {
            return $reference;
        }

        $parts = parse_url($base);
        if (!is_array($parts)) {
            return $reference;
        }

        $scheme = $parts['scheme'] ?? 'http';
        $host = $parts['host'] ?? '';
        $port = $parts['port'] ?? null;
        $origin = $scheme . '://' . $host . ($port !== null ? ':' . $port : '');

        if (str_starts_with($reference, '//')) {
            return $scheme . ':' . $reference;
        }
        if (preg_match('#^[a-z][a-z0-9+.\-]*://#i', $reference) === 1) {
            return $reference;
        }

        $basePath = $parts['path'] ?? '/';

        if (str_starts_with($reference, '/')) {
            $path = $reference;
        } elseif (str_starts_with($reference, '?')) {
            return $origin . $basePath . $reference;
        } else {
            $slash = strrpos($basePath, '/');
            $directory = $slash === false ? '/' : substr($basePath, 0, $slash + 1);
            $path = $directory . $reference;
        }

        $fragment = null;
        $hash = strpos($path, '#');
        if ($hash !== false) {
            $fragment = substr($path, $hash + 1);
            $path = substr($path, 0, $hash);
        }

        $query = null;
        $question = strpos($path, '?');
        if ($question !== false) {
            $query = substr($path, $question + 1);
            $path = substr($path, 0, $question);
        }

        return $origin . self::normalizePath($path)
            . ($query !== null ? '?' . $query : '')
            . ($fragment !== null ? '#' . $fragment : '');
    }

    /**
     * Collapse "." and ".." segments without letting ".." escape the root.
     */
    public static function normalizePath(string $path): string
    {
        $trailingSlash = str_ends_with($path, '/');
        $segments = explode('/', $path);
        $output = [];

        foreach ($segments as $segment) {
            if ($segment === '' || $segment === '.') {
                continue;
            }
            if ($segment === '..') {
                array_pop($output);
                continue;
            }
            $output[] = $segment;
        }

        $normalized = '/' . implode('/', $output);
        if ($trailingSlash && !str_ends_with($normalized, '/')) {
            $normalized .= '/';
        }

        return $normalized;
    }

    public function rewriteHtml(string $html, string $base): string
    {
        if (preg_match('#<base\s[^>]*href\s*=\s*["\']?([^"\'>\s]+)#i', $html, $match) === 1) {
            $base = $this->absoluteUrl($base, $match[1]);
        }

        $rewrite = function (string $url) use ($base): string {
            if ($url === '') {
                return $url;
            }
            if (str_starts_with($url, '#')) {
                return $this->proxyUrl($base) . $url;
            }
            if (str_starts_with($url, 'data:') || str_starts_with($url, 'javascript:') || str_starts_with($url, 'blob:')) {
                return $url;
            }

            return $this->proxyUrl($this->absoluteUrl($base, $url));
        };

        $html = preg_replace_callback(
            '#\b(href|src|action|poster|data-src|formaction)\s*=\s*(["\'])(.*?)\2#is',
            static function (array $m) use ($rewrite): string {
                return $m[1] . '=' . $m[2] . htmlspecialchars($rewrite($m[3]), ENT_QUOTES) . $m[2];
            },
            $html
        ) ?? $html;

        $html = preg_replace_callback(
            '#\bsrcset\s*=\s*(["\'])(.*?)\1#is',
            static function (array $m) use ($rewrite): string {
                $items = [];
                foreach (explode(',', $m[2]) as $item) {
                    $item = trim($item);
                    if ($item === '') {
                        continue;
                    }
                    $bits = preg_split('/\s+/', $item, 2) ?: [$item];
                    $url = $rewrite($bits[0]);
                    $items[] = isset($bits[1]) ? $url . ' ' . $bits[1] : $url;
                }

                return 'srcset=' . $m[1] . implode(', ', $items) . $m[1];
            },
            $html
        ) ?? $html;

        $html = preg_replace_callback(
            '#(<style\b[^>]*>)(.*?)(</style>)#is',
            fn (array $m): string => $m[1] . $this->rewriteCss($m[2], $base) . $m[3],
            $html
        ) ?? $html;

        $html = preg_replace_callback(
            '#\bstyle\s*=\s*(["\'])(.*?)\1#is',
            static function (array $m) use ($base): string {
                $rewritten = (new self())->rewriteCss(html_entity_decode($m[2]), $base);

                return 'style=' . $m[1] . htmlspecialchars($rewritten, ENT_QUOTES) . $m[1];
            },
            $html
        ) ?? $html;

        $html = preg_replace_callback(
            '#(http-equiv\s*=\s*["\']?refresh["\']?[^>]*content\s*=\s*["\'])([^"\']*)(["\'])#is',
            static function (array $m) use ($rewrite): string {
                $content = preg_replace_callback(
                    '#(url\s*=\s*)([^;]+)#i',
                    static fn (array $u): string => $u[1] . $rewrite(trim($u[2], " \"'")),
                    $m[2]
                ) ?? $m[2];

                return $m[1] . $content . $m[3];
            },
            $html
        ) ?? $html;

        return $html;
    }

    public function rewriteCss(string $css, string $base): string
    {
        $rewrite = function (string $url) use ($base): string {
            if ($url === '' || str_starts_with($url, 'data:')) {
                return $url;
            }

            return $this->proxyUrl($this->absoluteUrl($base, $url));
        };

        $css = preg_replace_callback(
            '#url\(\s*(["\']?)(.*?)\1\s*\)#is',
            static fn (array $m): string => 'url(' . $m[1] . $rewrite($m[2]) . $m[1] . ')',
            $css
        ) ?? $css;

        return preg_replace_callback(
            '#@import\s+(["\'])(.*?)\1#is',
            static fn (array $m): string => '@import ' . $m[1] . $rewrite($m[2]) . $m[1],
            $css
        ) ?? $css;
    }

    /**
     * Inject the bridge banner as the first element inside <body>.
     */
    public static function injectBanner(string $html, string $host): string
    {
        $safeHost = htmlspecialchars($host, ENT_QUOTES);
        $banner = '<div id="torphp-banner" style="position:sticky;top:0;z-index:2147483647;display:flex;'
            . 'align-items:center;gap:.6rem;padding:.55rem .9rem;background:#161222;color:#e8e3f2;'
            . 'border-bottom:1px solid #3a3150;font:13px/1.4 ui-sans-serif,system-ui,sans-serif">'
            . '<span>🧅</span><strong style="font-weight:600">' . $safeHost . '</strong>'
            . '<span style="opacity:.75">via TorPHP — native PHP Tor v3</span>'
            . '<button type="button" aria-label="Dismiss" onclick="this.parentNode.remove()" '
            . 'style="margin-left:auto;background:transparent;border:1px solid #3a3150;border-radius:6px;'
            . 'color:inherit;padding:.15rem .5rem;cursor:pointer">✕</button></div>';

        if (preg_match('#<body\b[^>]*>#i', $html, $match, PREG_OFFSET_CAPTURE) === 1) {
            $offset = (int) $match[0][1] + strlen($match[0][0]);

            return substr($html, 0, $offset) . $banner . substr($html, $offset);
        }

        return $banner . $html;
    }

    /**
     * @param string[] $allow
     */
    public static function isHostAllowed(string $host, array $allow): bool
    {
        if (in_array('*', $allow, true)) {
            return true;
        }

        foreach ($allow as $suffix) {
            $suffix = strtolower($suffix);
            if ($suffix === '.onion') {
                if (preg_match('#^([a-z2-7]{56}|[a-z2-7]{16})\.onion$#', $host) === 1) {
                    return true;
                }
                continue;
            }
            if ($host === ltrim($suffix, '.') || str_ends_with($host, $suffix)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Namespace a cookie to one onion service and drop attributes that would
     * leak it to other onions or to plain-HTTP clients.
     */
    public static function scopeCookie(string $cookie, string $host): string
    {
        $parts = explode(';', $cookie);
        $pair = trim((string) array_shift($parts));
        $equals = strpos($pair, '=');
        if ($equals === false) {
            return '';
        }

        $name = trim(substr($pair, 0, $equals));
        $value = substr($pair, $equals + 1);
        if (preg_match('/^[A-Za-z0-9_\-]+$/', $name) !== 1) {
            return '';
        }

        $name = preg_replace('/^__(Host|Secure)-/i', '', $name) ?? $name;
        $name = 'tp_' . substr(hash('sha256', $host), 0, 10) . '_' . $name;

        $attributes = [];
        foreach ($parts as $attribute) {
            $attribute = trim($attribute);
            if ($attribute === '' || preg_match('/^(domain|path|secure)\b/i', $attribute) === 1) {
                continue;
            }
            $attributes[] = $attribute;
        }
        $attributes[] = 'Path=/';

        return $name . '=' . $value . '; ' . implode('; ', $attributes);
    }
}
