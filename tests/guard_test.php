<?php

declare(strict_types=1);

/**
 * Persistent guard selection test: a chosen guard must stay sticky across
 * instances, rotate when excluded or rejected, and never trust a corrupt or
 * oversized state file.
 *
 * Run: php tests/guard_test.php
 */

require __DIR__ . '/../autoload.php';

use Torv3\Directory\GuardSet;
use Torv3\Directory\RelayInfo;

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

/**
 * @param string[] $flags
 */
function guardRelay(string $fingerprint, array $flags = ['Guard', 'Fast', 'Running']): RelayInfo
{
    return new RelayInfo(
        'guard' . substr($fingerprint, 0, 3),
        $fingerprint,
        random_bytes(20),
        '192.0.2.7',
        9001,
        0,
        $flags,
        random_bytes(32),
        random_bytes(32)
    );
}

$dir = sys_get_temp_dir() . '/torphp-guard-' . bin2hex(random_bytes(6));
mkdir($dir, 0700, true);
$file = $dir . '/guards.json';

$a = guardRelay(str_repeat('A', 40));
$b = guardRelay(str_repeat('B', 40));

$set = new GuardSet($file);
check('a new guard set starts empty', $set->fingerprints() === []);

$picked = $set->select([$a, $b]);
check('select returns an eligible guard', $picked !== null);
check('the chosen guard is persisted', is_file($file) && count((new GuardSet($file))->fingerprints()) === 1);

$reloaded = new GuardSet($file);
$again = $reloaded->select([$a, $b]);
check('a persisted guard is reused', $again !== null && $again->fingerprint === $picked?->fingerprint);

$other = $picked?->fingerprint === $a->fingerprint ? $b : $a;
$alternate = (new GuardSet($file))->select([$a, $b], [$picked?->fingerprint ?? '']);
check('an excluded guard is not reused', $alternate !== null && $alternate->fingerprint === $other->fingerprint);

(new GuardSet($file))->reject($other->fingerprint);
check(
    'rejecting a guard removes it from the persisted set',
    !in_array($other->fingerprint, (new GuardSet($file))->fingerprints(), true)
);
check('select returns null when no candidate is eligible', $reloaded->select([]) === null);

file_put_contents($file, 'not json at all');
check('a corrupt guard state is ignored', (new GuardSet($file))->fingerprints() === []);

$capped = new GuardSet($file);
for ($i = 1; $i <= 12; $i++) {
    $capped->remember(sprintf('%040X', $i));
}
check(
    'the guard set keeps at most eight entries',
    count($capped->fingerprints()) === 8
        && in_array(sprintf('%040X', 12), $capped->fingerprints(), true)
        && !in_array(sprintf('%040X', 1), $capped->fingerprints(), true)
);

$before = count($capped->fingerprints());
$capped->remember('not-a-fingerprint');
check('invalid fingerprints are ignored', count($capped->fingerprints()) === $before);

/* Manual rotation (the bridge's "change guard" button). */
$rotateFile = $dir . '/rotate.json';
$rotating = new GuardSet($rotateFile);
$current = $rotating->select([$a, $b]);
$rotated = $rotating->rotate([$a, $b]);
check('rotate returns a different guard', $rotated !== null && $current !== null && $rotated->fingerprint !== $current->fingerprint);
check(
    'the rotated guard becomes the persisted preference',
    (new GuardSet($rotateFile))->fingerprints() === [$rotated?->fingerprint]
);
$preferred = (new GuardSet($rotateFile))->select([$a, $b]);
check('select prefers the rotated guard', $preferred !== null && $preferred->fingerprint === $rotated?->fingerprint);

$alternating = new GuardSet($dir . '/alternate.json');
$first = $alternating->rotate([$a, $b]);
$second = $alternating->rotate([$a, $b]);
check(
    'successive rotations alternate between guards',
    $first !== null && $second !== null && $first->fingerprint !== $second->fingerprint
);

$stuck = new GuardSet($dir . '/stuck.json');
$stuck->remember($a->fingerprint);
check('rotate returns null when the only usable guard is the current one', $stuck->rotate([$a]) === null);
check('a failed rotation keeps the current guard', $stuck->fingerprints() === [$a->fingerprint]);

@unlink($file);
@unlink($rotateFile);
@unlink($dir . '/alternate.json');
@unlink($dir . '/stuck.json');
@rmdir($dir);

echo $failures === 0 ? "\nAll guard checks passed.\n" : "\n{$failures} guard check(s) failed.\n";
exit($failures === 0 ? 0 : 1);
