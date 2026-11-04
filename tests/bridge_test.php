<?php

declare(strict_types=1);

/**
 * Bridge rewriting test: resolves and rewrites links, CSS references, banner
 * injection, host policy and cookie scoping without a web server.
 *
 * Run: php tests/bridge_test.php
 */

require __DIR__ . '/../autoload.php';

use Torv3\Bridge\Rewriter;

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

$rewriter = new Rewriter();
$base = 'http://abc.onion/dir/page?q=1';

$encoded = static fn (string $absolute): string => '/bridge.php?url=' . rawurlencode($absolute);

check('proxy URLs carry the target as an encoded query value', $rewriter->proxyUrl('http://abc.onion/x y') === $encoded('http://abc.onion/x y'));
check('relative references resolve against the document directory', $rewriter->absoluteUrl($base, 'img.png') === 'http://abc.onion/dir/img.png');
check('root-relative references keep the origin', $rewriter->absoluteUrl($base, '/x/y') === 'http://abc.onion/x/y');
check('protocol-relative references inherit the scheme', $rewriter->absoluteUrl($base, '//cdn.example.com/a.js') === 'http://cdn.example.com/a.js');
check('query-only references replace the query', $rewriter->absoluteUrl($base, '?page=2') === 'http://abc.onion/dir/page?page=2');
check('fragments stay on the current document', $rewriter->absoluteUrl($base, '#top') === $base . '#top');
check('absolute https URLs are preserved', $rewriter->absoluteUrl($base, 'https://other.example/z') === 'https://other.example/z');
check('mailto links are preserved', $rewriter->absoluteUrl($base, 'mailto:a@example.com') === 'mailto:a@example.com');
check('javascript: links are preserved but never proxied', $rewriter->absoluteUrl($base, 'javascript:alert(1)') === 'javascript:alert(1)');
check('dot segments are removed', $rewriter->absoluteUrl($base, 'a/../b/./c') === 'http://abc.onion/dir/b/c');
check('non-default ports survive resolution', $rewriter->absoluteUrl('http://abc.onion:8080/dir/', 'x') === 'http://abc.onion:8080/dir/x');
check('leading dot-segments cannot escape the root', Rewriter::normalizePath('/../../etc/passwd') === '/etc/passwd');
check('trailing slashes are preserved', Rewriter::normalizePath('/a/../b/./c/') === '/b/c/');

$html = '<a href="/x">x</a><a href="javascript:void(0)">j</a><img src="data:image/png;base64,AA">';
$rewritten = $rewriter->rewriteHtml($html, 'http://abc.onion/');
check('href links are routed through the bridge', str_contains($rewritten, 'href="/bridge.php?url=http%3A%2F%2Fabc.onion%2Fx"'));
check('javascript: hrefs are left untouched', str_contains($rewritten, 'href="javascript:void(0)"'));
check('data: images are left untouched', str_contains($rewritten, 'src="data:image/png;base64,AA"'));

$srcset = $rewriter->rewriteHtml('<img srcset="/a.png 1x, /b.png 2x">', 'http://abc.onion/');
check(
    'every srcset candidate is rewritten with its descriptor',
    str_contains($srcset, $encoded('http://abc.onion/a.png') . ' 1x')
        && str_contains($srcset, $encoded('http://abc.onion/b.png') . ' 2x')
);

$styleBlock = $rewriter->rewriteHtml(
    '<style>@import "theme.css"; body{background:url("/bg.png")}</style>',
    'http://abc.onion/css/main.css'
);
check('style-block imports resolve against the stylesheet', str_contains($styleBlock, $encoded('http://abc.onion/css/theme.css')));
check('style-block url() references are rewritten', str_contains($styleBlock, $encoded('http://abc.onion/bg.png')));

$styleAttribute = $rewriter->rewriteHtml('<div style="background:url(\'/bg.png\')"></div>', 'http://abc.onion/');
check('inline style url() references are rewritten', str_contains($styleAttribute, 'bg.png') && str_contains($styleAttribute, 'url('));

$refresh = $rewriter->rewriteHtml(
    '<meta http-equiv="refresh" content="5; url=/next">',
    'http://abc.onion/'
);
check('meta refresh targets are rewritten', str_contains($refresh, $encoded('http://abc.onion/next')));

$based = $rewriter->rewriteHtml('<base href="http://other.onion/sub/"><a href="x">x</a>', 'http://abc.onion/');
check('a base element changes the resolution base', str_contains($based, $encoded('http://other.onion/sub/x')));

$attr = $rewriter->rewriteHtml('<a href="/x?a=1&b=2">x</a>', 'http://abc.onion/');
check(
    'rewritten attributes stay inside their quotes',
    str_contains($attr, '%3Fa%3D1%26b%3D2') && !str_contains($attr, '?a=1&b=2')
);

$css = $rewriter->rewriteCss('body{background:url("/img/a.png")} @import "x.css";', 'http://abc.onion/css/main.css');
check('CSS url() is rewritten', str_contains($css, 'url("' . $encoded('http://abc.onion/img/a.png') . '")'));
check('CSS @import is rewritten', str_contains($css, '@import "' . $encoded('http://abc.onion/css/x.css') . '"'));
check('CSS data: URLs are untouched', $rewriter->rewriteCss('a{background:url(data:image/gif;base64,AA)}', 'http://abc.onion/') === 'a{background:url(data:image/gif;base64,AA)}');

$bannered = Rewriter::injectBanner('<html><body class="x"><p>hi</p></body></html>', 'abc.onion');
check('the banner is inserted directly after <body>', str_contains($bannered, '<body class="x"><div id="torphp-banner"'));
check('the banner names the onion host', str_contains($bannered, 'abc.onion'));
check('a document without <body> still gets the banner', str_starts_with(Rewriter::injectBanner('<p>x</p>', 'abc.onion'), '<div id="torphp-banner"'));
check('the banner escapes the host', str_contains(Rewriter::injectBanner('<body>', 'a<b'), 'a&lt;b'));

$allowOnion = ['.onion'];
check('a v3 onion address is allowed', Rewriter::isHostAllowed(str_repeat('a', 56) . '.onion', $allowOnion));
check('a v2 onion address is allowed', Rewriter::isHostAllowed(str_repeat('a', 16) . '.onion', $allowOnion));
check('clearnet hosts are blocked by the onion-only policy', !Rewriter::isHostAllowed('example.com', $allowOnion));
check('a lookalike host is not treated as an onion', !Rewriter::isHostAllowed('abc.onion.example.com', $allowOnion));
check('a wildcard policy allows any host', Rewriter::isHostAllowed('example.com', ['*']));
check('a suffix policy allows subdomains', Rewriter::isHostAllowed('www.example.com', ['example.com']));

$prefix = 'tp_' . substr(hash('sha256', 'abc.onion'), 0, 10);
check(
    'cookies are namespaced per onion and lose Domain/Path/Secure',
    Rewriter::scopeCookie('sid=abc; Domain=evil.com; Path=/sub; Secure; HttpOnly', 'abc.onion')
        === $prefix . '_sid=abc; HttpOnly; Path=/'
);
check(
    '__Host- cookies have their prefix stripped',
    Rewriter::scopeCookie('__Host-sid=1', 'abc.onion') === $prefix . '_sid=1; Path=/'
);
check('cookies with invalid names are dropped', Rewriter::scopeCookie('bad name=1', 'abc.onion') === '');
check('cookie strings without a value are dropped', Rewriter::scopeCookie('novalue', 'abc.onion') === '');
check(
    'different onions never share a cookie name',
    Rewriter::scopeCookie('sid=1', 'abc.onion') !== Rewriter::scopeCookie('sid=1', 'def.onion')
);

$_SERVER['SCRIPT_NAME'] = '/bridge.php/http://a.onion/x';
$_SERVER['PATH_INFO'] = '/http://a.onion/x';
check('PATH_INFO routing is stripped from the bridge path', Rewriter::fromServer()->basePath() === '/bridge.php');
$_SERVER['SCRIPT_NAME'] = '/sub/bridge.php';
$_SERVER['PATH_INFO'] = '';
check('the bridge path honours a subdirectory deployment', Rewriter::fromServer()->basePath() === '/sub/bridge.php');

echo $failures === 0 ? "\nAll bridge checks passed.\n" : "\n{$failures} bridge check(s) failed.\n";
exit($failures === 0 ? 0 : 1);
