<?php

declare(strict_types=1);

namespace Componenta\Http\Middleware\TrustedProxy;

/**
 * Configuration for the trusted proxy middleware.
 *
 * Defines which reverse proxies are trusted and which forwarding
 * headers to read. When REMOTE_ADDR matches a trusted proxy,
 * the middleware resolves the real client IP from the configured
 * header format.
 *
 * @see RFC 7239  - Forwarded HTTP Extension
 * @see RFC 1918  - Private IPv4 address space
 * @see RFC 4193  - Unique Local IPv6 Unicast Addresses
 */
final readonly class TrustedProxyConfiguration
{
    /** RFC 1918 + loopback (IPv4) and RFC 4193 + link-local + loopback (IPv6). */
    private const array PRIVATE_RANGES = [
        '10.0.0.0/8',
        '172.16.0.0/12',
        '192.168.0.0/16',
        '127.0.0.0/8',
        '::1/128',
        'fc00::/7',
        'fe80::/10',
    ];

    /** @var list<string> */
    public array $trustedProxies;

    /**
     * @param array<array-key, mixed> $trustedProxies       IP addresses or CIDR ranges of trusted proxies.
     * @param TrustedHeaders $trustedHeaders        Which forwarding header format to trust.
     * @param bool           $trustPrivateNetworks  Implicitly trust RFC 1918/4193 private ranges.
     */
    public function __construct(
        array $trustedProxies = [],
        public TrustedHeaders $trustedHeaders = TrustedHeaders::XForwarded,
        public bool $trustPrivateNetworks = false,
    ) {
        $normalized = [];
        foreach ($trustedProxies as $entry) {
            if (!is_string($entry)) {
                throw new \InvalidArgumentException('Trusted proxy entries must be strings.');
            }
            $this->validateEntry($entry);
            $normalized[] = $entry;
        }
        $this->trustedProxies = $normalized;
    }

    /**
     * Returns all effective trusted ranges including private networks if enabled.
     *
     * @return list<string>
     */
    public function effectiveProxies(): array
    {
        if (!$this->trustPrivateNetworks) {
            return $this->trustedProxies;
        }

        return [...$this->trustedProxies, ...self::PRIVATE_RANGES];
    }

    private function validateEntry(string $entry): void
    {
        if (str_contains($entry, '/')) {
            [$ip, $prefix] = explode('/', $entry, 2);

            if (!filter_var($ip, FILTER_VALIDATE_IP)) {
                throw new \InvalidArgumentException("Invalid IP in CIDR: {$entry}");
            }

            $prefixLen = (int) $prefix;
            $isIpv6 = str_contains($ip, ':');
            $max = $isIpv6 ? 128 : 32;

            if ((string) $prefixLen !== $prefix || $prefixLen < 0 || $prefixLen > $max) {
                throw new \InvalidArgumentException("Invalid prefix length in CIDR: {$entry}");
            }

            return;
        }

        if (!filter_var($entry, FILTER_VALIDATE_IP)) {
            throw new \InvalidArgumentException("Invalid IP address: {$entry}");
        }
    }
}
