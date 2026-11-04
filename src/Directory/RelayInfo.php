<?php

declare(strict_types=1);

namespace Torv3\Directory;

use Torv3\TorProtocolException;

/**
 * An onion router as described by the consensus plus its microdescriptor.
 */
final class RelayInfo
{
    /**
     * @param string[] $flags
     */
    public function __construct(
        public string $nickname,
        public string $fingerprint,      // 40 uppercase hex chars
        public string $identityDigest,   // 20 raw bytes (ntor NODEID)
        public string $address,          // IPv4 literal
        public int $orPort,
        public int $dirPort,
        public array $flags,
        public ?string $ntorOnionKey = null,   // 32 raw bytes
        public ?string $ed25519Id = null,      // 32 raw bytes
        public ?string $version = null,
        public int $bandwidth = 0,
        public ?string $microdescDigest = null
    ) {
    }

    public function hasFlag(string $flag): bool
    {
        return in_array($flag, $this->flags, true);
    }

    public function isUsable(): bool
    {
        return $this->orPort > 0
            && $this->ntorOnionKey !== null
            && strlen($this->identityDigest) === 20;
    }

    /**
     * True when the relay advertises an ntor onion key and is not an authority
     * we cannot extend to.
     */
    public function canExtend(): bool
    {
        return $this->ntorOnionKey !== null && strlen($this->ntorOnionKey) === 32;
    }

    /**
     * Relay fingerprint in the "r" line's base64 form (27 chars), used when
     * matching a consensus entry.
     */
    public function fingerprintBase64(): string
    {
        return rtrim(strtr(base64_encode($this->identityDigest), '+/', '-_'), '=');
    }

    public function endpoint(): string
    {
        return $this->address . ':' . $this->orPort;
    }

    public function toArray(): array
    {
        return [
            'nickname' => $this->nickname,
            'fingerprint' => $this->fingerprint,
            'identity' => base64_encode($this->identityDigest),
            'address' => $this->address,
            'orPort' => $this->orPort,
            'dirPort' => $this->dirPort,
            'flags' => $this->flags,
            'ntorOnionKey' => $this->ntorOnionKey === null ? null : base64_encode($this->ntorOnionKey),
            'ed25519Id' => $this->ed25519Id === null ? null : base64_encode($this->ed25519Id),
            'version' => $this->version,
            'bandwidth' => $this->bandwidth,
            'microdescDigest' => $this->microdescDigest,
        ];
    }

    public static function fromArray(array $data): self
    {
        $decode = static function (?string $value): ?string {
            if ($value === null) {
                return null;
            }
            $decoded = base64_decode($value, true);

            return $decoded === false ? null : $decoded;
        };

        if (!isset($data['nickname'], $data['identity'], $data['address'], $data['orPort'])) {
            throw new TorProtocolException('Incomplete relay data in cache');
        }

        return new self(
            (string) $data['nickname'],
            (string) ($data['fingerprint'] ?? ''),
            (string) base64_decode((string) $data['identity'], true),
            (string) $data['address'],
            (int) $data['orPort'],
            (int) ($data['dirPort'] ?? 0),
            array_values($data['flags'] ?? []),
            $decode($data['ntorOnionKey'] ?? null),
            $decode($data['ed25519Id'] ?? null),
            $data['version'] ?? null,
            (int) ($data['bandwidth'] ?? 0),
            $data['microdescDigest'] ?? null
        );
    }
}
