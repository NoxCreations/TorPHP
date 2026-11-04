<?php

declare(strict_types=1);

namespace Torv3\Directory;

/**
 * Persistent entry-guard selection (guard-spec.txt §2).
 *
 * Reusing one entry guard across circuits and across restarts is what limits
 * the number of relays that learn "this client" — picking a random first hop
 * per circuit exposes the same client to every guard in the network. The set
 * is kept as a small newest-first list of v3 identity fingerprints, stored
 * beside the consensus cache with restrictive permissions.
 */
final class GuardSet
{
    private const VERSION = 1;

    /** How many previously chosen guards to remember (Tor keeps a sample). */
    private const MAX_GUARDS = 8;

    private ?string $file;

    /** @var list<string> Uppercase 40-hex fingerprints, oldest first. */
    private array $fingerprints = [];

    public function __construct(?string $file)
    {
        $this->file = $file;
        $this->fingerprints = $this->load();
    }

    /**
     * Store the guard list next to a consensus cache file.
     */
    public static function forCacheFile(?string $cacheFile): self
    {
        if ($cacheFile === null || $cacheFile === '') {
            return new self(null);
        }

        return new self(rtrim(dirname($cacheFile), '/') . '/guards.json');
    }

    /**
     * @return list<string>
     */
    public function fingerprints(): array
    {
        return $this->fingerprints;
    }

    /**
     * Pick a guard, preferring one this client has already used.
     *
     * @param RelayInfo[] $candidates eligible relays (Guard flag, extendable)
     * @param string[] $exclude fingerprints that must not be used
     */
    public function select(array $candidates, array $exclude = []): ?RelayInfo
    {
        $eligible = [];
        foreach ($candidates as $relay) {
            if (!in_array($relay->fingerprint, $exclude, true)) {
                $eligible[$relay->fingerprint] = $relay;
            }
        }

        if ($eligible === []) {
            return null;
        }

        foreach ($this->fingerprints as $fingerprint) {
            if (isset($eligible[$fingerprint])) {
                return $eligible[$fingerprint];
            }
        }

        $fresh = array_values(array_filter(
            $eligible,
            fn (RelayInfo $relay): bool => !in_array($relay->fingerprint, $this->fingerprints, true)
        ));
        if ($fresh === []) {
            $fresh = array_values($eligible);
        }

        $chosen = $fresh[random_int(0, count($fresh) - 1)];
        $this->remember($chosen->fingerprint);

        return $chosen;
    }

    /**
     * Switch to a guard this client is not already using.
     *
     * The current entry guard is never returned: every remembered guard is
     * excluded, and the chosen relay replaces the sample so select() cannot
     * keep preferring the old one. If only remembered guards are available,
     * the current one is still ruled out so successive rotations alternate.
     *
     * @param RelayInfo[] $candidates eligible relays (Guard flag, extendable)
     * @param string[] $exclude additional fingerprints that must not be used
     */
    public function rotate(array $candidates, array $exclude = []): ?RelayInfo
    {
        $eligible = [];
        foreach ($candidates as $relay) {
            if (!in_array($relay->fingerprint, $exclude, true)) {
                $eligible[$relay->fingerprint] = $relay;
            }
        }

        $fresh = array_values(array_filter(
            $eligible,
            fn (RelayInfo $relay): bool => !in_array($relay->fingerprint, $this->fingerprints, true)
        ));

        if ($fresh === []) {
            $current = $this->fingerprints[0] ?? null;
            $fresh = array_values(array_filter(
                $eligible,
                fn (RelayInfo $relay): bool => $relay->fingerprint !== $current
            ));
        }

        if ($fresh === []) {
            return null;
        }

        $chosen = $fresh[random_int(0, count($fresh) - 1)];

        // Replace, rather than extend, the sample: select() returns the first
        // remembered guard that is still eligible.
        $this->fingerprints = [$chosen->fingerprint];
        $this->save();

        return $chosen;
    }

    /**
     * Add a guard to the persisted sample, dropping the oldest entries.
     */
    public function remember(string $fingerprint): void
    {
        $fingerprint = strtoupper($fingerprint);
        if (preg_match('/^[0-9A-F]{40}$/', $fingerprint) !== 1) {
            return;
        }
        if (in_array($fingerprint, $this->fingerprints, true)) {
            return;
        }

        $this->fingerprints[] = $fingerprint;
        if (count($this->fingerprints) > self::MAX_GUARDS) {
            $this->fingerprints = array_slice($this->fingerprints, -self::MAX_GUARDS);
        }
        $this->save();
    }

    /**
     * Forget a guard that could not be reached, so the next circuit picks a
     * different first hop.
     */
    public function reject(string $fingerprint): void
    {
        $fingerprint = strtoupper($fingerprint);
        $remaining = array_values(array_diff($this->fingerprints, [$fingerprint]));
        if ($remaining === $this->fingerprints) {
            return;
        }

        $this->fingerprints = $remaining;
        $this->save();
    }

    /**
     * @return list<string>
     */
    private function load(): array
    {
        if ($this->file === null || !is_file($this->file)) {
            return [];
        }

        $raw = @file_get_contents($this->file);
        if ($raw === false || $raw === '') {
            return [];
        }

        $data = json_decode($raw, true);
        if (!is_array($data) || ($data['version'] ?? 0) !== self::VERSION) {
            return [];
        }

        $stored = $data['guards'] ?? null;
        if (!is_array($stored)) {
            return [];
        }

        $guards = [];
        foreach ($stored as $value) {
            if (!is_string($value)) {
                continue;
            }
            $fingerprint = strtoupper($value);
            if (preg_match('/^[0-9A-F]{40}$/', $fingerprint) === 1) {
                $guards[$fingerprint] = true;
            }
        }

        return array_slice(array_keys($guards), -self::MAX_GUARDS);
    }

    private function save(): void
    {
        if ($this->file === null) {
            return;
        }

        $dir = dirname($this->file);
        if (!is_dir($dir)) {
            @mkdir($dir, 0700, true);
        }

        $payload = json_encode([
            'version' => self::VERSION,
            'guards' => $this->fingerprints,
            'updated' => time(),
        ]);
        if ($payload === false) {
            return;
        }

        $tmp = $this->file . '.tmp';
        if (@file_put_contents($tmp, $payload) === false) {
            return;
        }
        @chmod($tmp, 0600);
        @rename($tmp, $this->file);
    }
}
