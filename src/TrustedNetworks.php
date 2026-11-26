<?php

declare(strict_types=1);

namespace Componenta\Http\Middleware\TrustedProxy;

/** @internal */
final readonly class TrustedNetworks
{
    /** @var list<array{string, string}> */
    private array $networks;

    public function __construct(TrustedProxyConfiguration $configuration)
    {
        $networks = [];
        foreach ($configuration->effectiveProxies() as $entry) {
            [$address, $prefix] = array_pad(explode('/', $entry, 2), 2, null);
            $binary = inet_pton($address);
            if ($binary === false) {
                throw new \InvalidArgumentException('Invalid trusted network.');
            }
            $bits = $prefix === null ? strlen($binary) * 8 : (int) $prefix;
            if (self::isMapped($binary) && $bits >= 96) {
                $binary = substr($binary, 12);
                $bits -= 96;
            }
            $mask = str_repeat("\xff", intdiv($bits, 8));
            if ($bits % 8 !== 0) {
                $mask .= chr((0xff << (8 - $bits % 8)) & 0xff);
            }
            $mask = str_pad($mask, strlen($binary), "\0");
            $networks[] = [$binary & $mask, $mask];
        }
        $this->networks = $networks;
    }

    public static function normalize(string $address): ?string
    {
        if (filter_var($address, FILTER_VALIDATE_IP) === false) {
            return null;
        }
        $binary = inet_pton($address);
        if ($binary === false) {
            return null;
        }
        $normalized = inet_ntop(self::isMapped($binary) ? substr($binary, 12) : $binary);
        return $normalized === false ? null : $normalized;
    }

    public function contains(string $address): bool
    {
        $normalized = self::normalize($address);
        if ($normalized === null) {
            return false;
        }
        $binary = inet_pton($normalized);
        if ($binary === false) {
            return false;
        }
        foreach ($this->networks as [$network, $mask]) {
            if (strlen($binary) === strlen($mask) && ($binary & $mask) === $network) {
                return true;
            }
        }
        return false;
    }

    private static function isMapped(string $binary): bool
    {
        return strlen($binary) === 16 && substr($binary, 0, 12) === str_repeat("\0", 10) . "\xff\xff";
    }
}
