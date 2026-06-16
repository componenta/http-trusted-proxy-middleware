<?php

declare(strict_types=1);

namespace Componenta\Http\Middleware\TrustedProxy;

use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Message\UriInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;

/**
 * Restores the real client IP, scheme, host, and port when the application
 * runs behind one or more reverse proxies (Nginx, HAProxy, Cloudflare, etc.).
 *
 * Algorithm (RFC 7239 §5.2 - right-to-left walk):
 *
 * 1. If REMOTE_ADDR is not a trusted proxy, the forwarding headers are
 *    untrusted - strip them and set client_ip = REMOTE_ADDR.
 * 2. If REMOTE_ADDR is trusted, parse the forwarding header chain,
 *    walk right-to-left, and take the first untrusted IP as the client IP.
 *    Update the request URI with the forwarded scheme/host/port.
 * 3. Strip all forwarding headers before passing the request downstream
 *    so that application code cannot accidentally read spoofed values.
 *
 * @see RFC 7239        - Forwarded HTTP Extension
 * @see RFC 7239 §5.2   - Determining the Client Address
 * @see RFC 1918        - Private IPv4 address space
 * @see RFC 4193        - Unique Local IPv6 Unicast Addresses
 */
final readonly class TrustedProxyMiddleware implements MiddlewareInterface
{
    /** Request attribute name for the resolved client IP. */
    public const string ATTR_CLIENT_IP = 'client_ip';

    /** All forwarding headers that must be stripped from downstream requests. */
    private const array FORWARDED_HEADERS = [
        'Forwarded',
        'X-Forwarded-For',
        'X-Forwarded-Proto',
        'X-Forwarded-Host',
        'X-Forwarded-Port',
    ];

    public function __construct(
        private TrustedProxyConfiguration $config,
    ) {}

    #[\Override]
    public function process(
        ServerRequestInterface $request,
        RequestHandlerInterface $handler,
    ): ResponseInterface {
        $remoteAddr = $request->getServerParams()['REMOTE_ADDR'] ?? '';

        if ($remoteAddr === '' || !$this->isTrustedProxy($remoteAddr)) {
            // Untrusted origin: client_ip = REMOTE_ADDR, strip headers
            $request = $request->withAttribute(self::ATTR_CLIENT_IP, $remoteAddr);
            $request = $this->stripForwardedHeaders($request);

            return $handler->handle($request);
        }

        // REMOTE_ADDR is trusted - resolve real values from forwarding headers
        $clientIp = $this->resolveClientIp($request, $remoteAddr);
        $request = $request->withAttribute(self::ATTR_CLIENT_IP, $clientIp);

        $request = $this->resolveUri($request);
        $request = $this->stripForwardedHeaders($request);

        return $handler->handle($request);
    }


    /**
     * Resolves the real client IP using a right-to-left walk.
     *
     * Per RFC 7239 §5.2, the rightmost untrusted address in the chain
     * is the actual client. We build the chain from the forwarding header
     * and append REMOTE_ADDR as the rightmost entry, then walk from right
     * to left: while an IP is trusted, continue; the first untrusted IP
     * is the client. If all IPs are trusted, the leftmost entry is used.
     *
     * This approach is the only secure way to determine the client IP when
     * multiple proxies are involved - reading only the leftmost entry of
     * X-Forwarded-For is trivially spoofable by the client.
     */
    private function resolveClientIp(ServerRequestInterface $request, string $remoteAddr): string
    {
        $chain = $this->parseIpChain($request);

        if ($chain === []) {
            return $remoteAddr;
        }

        // Append REMOTE_ADDR as the rightmost entry (the immediate peer)
        $chain[] = $remoteAddr;

        // Walk right-to-left: skip trusted proxies, take first untrusted
        for ($i = count($chain) - 1; $i >= 0; $i--) {
            $ip = $this->normalizeIp(trim($chain[$i]));

            if ($ip === '' || !filter_var($ip, FILTER_VALIDATE_IP)) {
                continue;
            }

            if (!$this->isTrustedProxy($ip)) {
                return $ip;
            }
        }

        // All entries trusted - return the leftmost (original client claim)
        $first = $this->normalizeIp(trim($chain[0]));

        return $first !== '' && filter_var($first, FILTER_VALIDATE_IP) ? $first : $remoteAddr;
    }

    /**
     * Parses the IP chain from the configured header format.
     *
     * @return list<string>
     */
    private function parseIpChain(ServerRequestInterface $request): array
    {
        return match ($this->config->trustedHeaders) {
            TrustedHeaders::XForwarded => $this->parseXForwardedFor($request),
            TrustedHeaders::Forwarded => $this->parseForwardedFor($request),
            TrustedHeaders::All => $this->parseForwardedFor($request) ?: $this->parseXForwardedFor($request),
        };
    }

    /**
     * Parses IP addresses from the X-Forwarded-For header.
     *
     * Format: `X-Forwarded-For: client, proxy1, proxy2`
     *
     * Each value is a bare IP (IPv4 or IPv6). Multiple headers are
     * combined per RFC 9110 §5.3 (comma-separated concatenation).
     *
     * @return list<string>
     */
    private function parseXForwardedFor(ServerRequestInterface $request): array
    {
        $header = $request->getHeaderLine('X-Forwarded-For');

        if ($header === '') {
            return [];
        }

        $ips = array_map('trim', explode(',', $header));

        return array_values(array_filter($ips, fn(string $ip): bool => $ip !== ''));
    }

    /**
     * Extracts the `for` directive values from the RFC 7239 Forwarded header.
     *
     * Format: `Forwarded: for=192.0.2.43, for="[2001:db8::1]";proto=https`
     *
     * Per RFC 7239 §4:
     * - IPv6 addresses are enclosed in quotes and square brackets: `for="[::1]"`
     * - Obfuscated identifiers (e.g., `for=_hidden`) and `unknown` are skipped
     * - Multiple forwarded-element entries are comma-separated
     * - Directives within an element are semicolon-separated
     *
     * @return list<string>
     */
    private function parseForwardedFor(ServerRequestInterface $request): array
    {
        $header = $request->getHeaderLine('Forwarded');

        if ($header === '') {
            return [];
        }

        $ips = [];

        // Split by comma to get individual forwarded-element entries
        $elements = explode(',', $header);

        foreach ($elements as $element) {
            $ip = $this->extractForwardedDirective(trim($element), 'for');

            if ($ip !== null) {
                $normalized = $this->normalizeForwardedValue($ip);

                if ($normalized !== '' && filter_var($normalized, FILTER_VALIDATE_IP)) {
                    $ips[] = $normalized;
                }
            }
        }

        return $ips;
    }
    //  URI resolution (scheme, host, port)

    /**
     * Updates the request URI with forwarded scheme, host, and port.
     */
    private function resolveUri(ServerRequestInterface $request): ServerRequestInterface
    {
        $uri = $request->getUri();

        $scheme = $this->resolveScheme($request);

        if ($scheme !== null) {
            $uri = $uri->withScheme($scheme);
        }

        $host = $this->resolveHost($request);

        if ($host !== null) {
            $uri = $uri->withHost($host);
        }

        $port = $this->resolvePort($request, $uri);

        // PSR-7: null removes the port component
        $uri = $uri->withPort($port);

        if ($uri !== $request->getUri()) {
            $request = $request->withUri($uri);
        }

        return $request;
    }

    /**
     * Resolves the original scheme from forwarding headers.
     *
     * Reads Forwarded `proto` directive (RFC 7239) or X-Forwarded-Proto.
     * When both formats are enabled (TrustedHeaders::All), RFC 7239
     * takes precedence - consistent with parseIpChain() behavior.
     */
    private function resolveScheme(ServerRequestInterface $request): ?string
    {
        if ($this->supportsForwarded()) {
            $header = $request->getHeaderLine('Forwarded');

            if ($header !== '') {
                $firstElement = trim(explode(',', $header)[0]);
                $proto = $this->extractForwardedDirective($firstElement, 'proto');

                if ($proto !== null) {
                    $scheme = strtolower($proto);

                    if ($scheme === 'http' || $scheme === 'https') {
                        return $scheme;
                    }
                }
            }
        }

        if ($this->supportsXForwarded()) {
            $proto = $request->getHeaderLine('X-Forwarded-Proto');

            if ($proto !== '') {
                $scheme = strtolower(trim(explode(',', $proto)[0]));

                if ($scheme === 'http' || $scheme === 'https') {
                    return $scheme;
                }
            }
        }

        return null;
    }

    /**
     * Resolves the original host from forwarding headers.
     *
     * Reads Forwarded `host` directive (RFC 7239) or X-Forwarded-Host.
     * RFC 7239 takes precedence when both formats are enabled.
     */
    private function resolveHost(ServerRequestInterface $request): ?string
    {
        if ($this->supportsForwarded()) {
            $header = $request->getHeaderLine('Forwarded');

            if ($header !== '') {
                $firstElement = trim(explode(',', $header)[0]);
                $host = $this->extractForwardedDirective($firstElement, 'host');

                if ($host !== null) {
                    $host = strtolower($this->stripPortFromHost($host));

                    if ($host !== '' && $this->isValidHost($host)) {
                        return $host;
                    }
                }
            }
        }

        if ($this->supportsXForwarded()) {
            $host = $request->getHeaderLine('X-Forwarded-Host');

            if ($host !== '') {
                $host = strtolower(trim(explode(',', $host)[0]));
                $host = $this->stripPortFromHost($host);

                if ($host !== '' && $this->isValidHost($host)) {
                    return $host;
                }
            }
        }

        return null;
    }

    /**
     * Resolves the original port from forwarding headers.
     *
     * Returns null when the port is the standard port for the current scheme
     * (per PSR-7: null means "use the standard port for the scheme").
     */
    private function resolvePort(ServerRequestInterface $request, UriInterface $uri): ?int
    {
        $port = null;

        if ($this->supportsForwarded()) {
            $header = $request->getHeaderLine('Forwarded');

            if ($header !== '') {
                $firstElement = trim(explode(',', $header)[0]);
                $host = $this->extractForwardedDirective($firstElement, 'host');

                if ($host !== null) {
                    $port = $this->extractPortFromHost($host);
                }
            }
        }

        if ($port === null && $this->supportsXForwarded()) {
            // X-Forwarded-Port takes precedence over port embedded in X-Forwarded-Host
            $portHeader = $request->getHeaderLine('X-Forwarded-Port');

            if ($portHeader !== '') {
                $portValue = (int) trim(explode(',', $portHeader)[0]);

                if ($portValue > 0 && $portValue <= 65535) {
                    $port = $portValue;
                }
            }

            if ($port === null) {
                $host = $request->getHeaderLine('X-Forwarded-Host');

                if ($host !== '') {
                    $port = $this->extractPortFromHost(trim(explode(',', $host)[0]));
                }
            }
        }

        if ($port === null) {
            return null;
        }

        // Return null for standard ports (PSR-7 convention)
        $scheme = $uri->getScheme();

        if (($scheme === 'http' && $port === 80) || ($scheme === 'https' && $port === 443)) {
            return null;
        }

        return $port;
    }


    /**
     * Extracts a directive value from a single Forwarded element.
     *
     * Per RFC 7239 §4, a forwarded-element is a semicolon-separated list
     * of forwarded-pairs: `for=192.0.2.43;proto=https;by=203.0.113.60`
     *
     * Directive names are case-insensitive per RFC 7239 §7.1.
     * Values may be tokens or quoted-strings (RFC 7230 §3.2.6).
     */
    private function extractForwardedDirective(string $element, string $directive): ?string
    {
        $directive = strtolower($directive);

        // Split by semicolon to get individual directives
        $pairs = explode(';', $element);

        foreach ($pairs as $pair) {
            $pair = trim($pair);
            $eqPos = strpos($pair, '=');

            if ($eqPos === false) {
                continue;
            }

            $name = strtolower(trim(substr($pair, 0, $eqPos)));

            if ($name !== $directive) {
                continue;
            }

            $value = trim(substr($pair, $eqPos + 1));

            // Handle quoted-string (RFC 7230 §3.2.6)
            if (str_starts_with($value, '"') && str_ends_with($value, '"') && strlen($value) >= 2) {
                $value = substr($value, 1, -1);
            }

            return $value;
        }

        return null;
    }

    /**
     * Normalizes a `for` directive value from the Forwarded header.
     *
     * Per RFC 7239 §6:
     * - IPv4: `for=192.0.2.43` or `for=192.0.2.43:47011`
     * - IPv6: `for="[2001:db8::1]"` or `for="[2001:db8::1]:47011"`
     * - Obfuscated: `for=_hidden` (skipped - not a real IP)
     * - Unknown: `for=unknown` (skipped)
     *
     * Returns the bare IP address without port or brackets.
     */
    private function normalizeForwardedValue(string $value): string
    {
        $value = trim($value);

        // Skip obfuscated identifiers and "unknown"
        if ($value === '' || $value[0] === '_' || strtolower($value) === 'unknown') {
            return '';
        }

        // IPv6 in brackets: [2001:db8::1] or [2001:db8::1]:port
        if (str_starts_with($value, '[')) {
            $closeBracket = strpos($value, ']');

            if ($closeBracket === false) {
                return '';
            }

            return substr($value, 1, $closeBracket - 1);
        }

        // IPv4 with port: 192.0.2.43:47011
        // Only strip port if it looks like IPv4 (contains a dot, not a colon before the port separator)
        if (str_contains($value, '.') && str_contains($value, ':')) {
            return substr($value, 0, (int) strrpos($value, ':'));
        }

        return $value;
    }


    /**
     * Removes all forwarding headers from the request.
     *
     * This prevents downstream application code from accidentally reading
     * raw (potentially spoofed) forwarding headers. The resolved values are
     * available via the request attributes and the modified URI.
     */
    private function stripForwardedHeaders(ServerRequestInterface $request): ServerRequestInterface
    {
        foreach (self::FORWARDED_HEADERS as $header) {
            $request = $request->withoutHeader($header);
        }

        return $request;
    }


    /**
     * Checks whether the given IP belongs to a trusted proxy.
     *
     * Matches against explicitly configured IPs/CIDRs and, when enabled,
     * RFC 1918 (IPv4) and RFC 4193 (IPv6) private address ranges.
     */
    private function isTrustedProxy(string $ip): bool
    {
        $ip = $this->normalizeIp($ip);

        if ($ip === '' || !filter_var($ip, FILTER_VALIDATE_IP)) {
            return false;
        }

        foreach ($this->config->effectiveProxies() as $entry) {
            if (str_contains($entry, '/')) {
                if ($this->ipInCidr($ip, $entry)) {
                    return true;
                }
            } elseif ($this->normalizeIp($entry) === $ip) {
                return true;
            }
        }

        return false;
    }

    /**
     * Checks whether an IP address falls within a CIDR range.
     *
     * Uses binary comparison of the network portion via inet_pton().
     * Supports both IPv4 and IPv6.
     */
    private function ipInCidr(string $ip, string $cidr): bool
    {
        [$range, $prefix] = explode('/', $cidr, 2);

        $range = $this->normalizeIp($range);
        $prefixLen = (int) $prefix;

        $ipBin = inet_pton($ip);
        $rangeBin = inet_pton($range);

        if ($ipBin === false || $rangeBin === false) {
            return false;
        }

        // IPv4 and IPv6 addresses have different binary lengths
        if (strlen($ipBin) !== strlen($rangeBin)) {
            return false;
        }

        // Build the bitmask: $prefixLen bits set to 1, rest to 0
        $byteLen = strlen($ipBin);
        $mask = str_repeat("\xff", intdiv($prefixLen, 8));

        $remainingBits = $prefixLen % 8;

        if ($remainingBits > 0) {
            $mask .= chr(0xff << (8 - $remainingBits) & 0xff);
        }

        $mask = str_pad($mask, $byteLen, "\x00");

        return ($ipBin & $mask) === ($rangeBin & $mask);
    }


    /**
     * Normalizes an IP address for consistent comparison.
     *
     * - Strips square brackets from IPv6 notation: `[::1]` -> `::1`
     * - Converts IPv4-mapped IPv6 addresses to IPv4: `::ffff:192.0.2.1` -> `192.0.2.1`
     * - Trims whitespace
     */
    private function normalizeIp(string $ip): string
    {
        $ip = trim($ip);

        // Strip IPv6 brackets
        if (str_starts_with($ip, '[') && str_ends_with($ip, ']')) {
            $ip = substr($ip, 1, -1);
        }

        // Convert IPv4-mapped IPv6 to IPv4
        // Formats: ::ffff:192.0.2.1, ::ffff:c000:0201, 0:0:0:0:0:ffff:192.0.2.1
        if (stripos($ip, '::ffff:') === 0) {
            $mapped = substr($ip, 7);

            if (filter_var($mapped, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
                return $mapped;
            }
        }

        return $ip;
    }


    /**
     * Strips the port from a host string, preserving IPv6 brackets.
     *
     * Brackets are preserved because PSR-7 UriInterface::withHost()
     * and RFC 3986 §3.2.2 require them for IPv6 literals in URIs.
     *
     * - `[::1]:8080`       -> `[::1]`
     * - `[::1]`            -> `[::1]`
     * - `example.com:8080` -> `example.com`
     * - `example.com`      -> `example.com`
     */
    private function stripPortFromHost(string $host): string
    {
        // IPv6 in brackets: [::1]:8080 -> [::1]
        if (str_starts_with($host, '[')) {
            $closeBracket = strpos($host, ']');

            if ($closeBracket !== false) {
                return substr($host, 0, $closeBracket + 1);
            }

            return $host;
        }

        // IPv4 or hostname with port: example.com:8080
        $colonPos = strrpos($host, ':');

        if ($colonPos !== false) {
            return substr($host, 0, $colonPos);
        }

        return $host;
    }

    /**
     * Extracts the port number from a host string, if present.
     */
    private function extractPortFromHost(string $host): ?int
    {
        // IPv6 with port: [::1]:8080
        if (str_starts_with($host, '[')) {
            $closeBracket = strpos($host, ']');

            if ($closeBracket !== false && isset($host[$closeBracket + 1]) && $host[$closeBracket + 1] === ':') {
                $port = (int) substr($host, $closeBracket + 2);

                return ($port > 0 && $port <= 65535) ? $port : null;
            }

            return null;
        }

        // IPv4 or hostname with port
        $colonPos = strrpos($host, ':');

        if ($colonPos !== false) {
            $port = (int) substr($host, $colonPos + 1);

            return ($port > 0 && $port <= 65535) ? $port : null;
        }

        return null;
    }

    /**
     * Validates a host string (basic check to prevent header injection).
     *
     * Allows alphanumeric hostnames, dots, hyphens, and IPv6 addresses.
     * Rejects newlines, spaces, and other characters that could enable
     * HTTP response splitting or host header attacks.
     */
    private function isValidHost(string $host): bool
    {
        if ($host === '') {
            return false;
        }

        // Reject anything with whitespace, newlines, or control characters
        if (preg_match('/[\s\x00-\x1f\x7f]/', $host)) {
            return false;
        }

        // Bracketed IPv6 literal: [::1]
        // filter_var(FILTER_VALIDATE_IP) does not accept brackets,
        // so we validate the inner address separately.
        if (str_starts_with($host, '[') && str_ends_with($host, ']')) {
            return (bool) filter_var(
                substr($host, 1, -1),
                FILTER_VALIDATE_IP,
                FILTER_FLAG_IPV6,
            );
        }

        return (bool) filter_var($host, FILTER_VALIDATE_DOMAIN, FILTER_FLAG_HOSTNAME)
            || filter_var($host, FILTER_VALIDATE_IP);
    }


    /**
     * Whether the configuration trusts X-Forwarded-* headers.
     */
    private function supportsXForwarded(): bool
    {
        return $this->config->trustedHeaders === TrustedHeaders::XForwarded
            || $this->config->trustedHeaders === TrustedHeaders::All;
    }

    /**
     * Whether the configuration trusts the RFC 7239 Forwarded header.
     */
    private function supportsForwarded(): bool
    {
        return $this->config->trustedHeaders === TrustedHeaders::Forwarded
            || $this->config->trustedHeaders === TrustedHeaders::All;
    }
}
