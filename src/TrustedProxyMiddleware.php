<?php

declare(strict_types=1);

namespace Componenta\Http\Middleware\TrustedProxy;

use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;

final readonly class TrustedProxyMiddleware implements MiddlewareInterface
{
    public const string ATTR_CLIENT_IP = 'client_ip';

    private const array FORWARDED_HEADERS = [
        'Forwarded', 'X-Forwarded-For', 'X-Forwarded-Proto',
        'X-Forwarded-Host', 'X-Forwarded-Port',
    ];

    private TrustedNetworks $networks;

    public function __construct(private TrustedProxyConfiguration $config)
    {
        $this->networks = new TrustedNetworks($config);
    }

    #[\Override]
    public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
    {
        $remote = $request->getServerParams()['REMOTE_ADDR'] ?? null;
        $peer = is_string($remote) ? TrustedNetworks::normalize($remote) : null;
        $client = $peer ?? '';
        if ($peer !== null && $this->networks->contains($peer)) {
            [$client, $metadata] = $this->resolve($request, $peer);
            $request = $this->applyMetadata($request, $metadata);
        }
        $request = $request->withAttribute(self::ATTR_CLIENT_IP, $client);
        foreach (self::FORWARDED_HEADERS as $header) {
            if ($request->hasHeader($header)) {
                $request = $request->withoutHeader($header);
            }
        }
        return $handler->handle($request);
    }

    /** @return array{string, array<string, string>} */
    private function resolve(ServerRequestInterface $request, string $peer): array
    {
        if ($this->config->trustedHeaders !== TrustedHeaders::XForwarded && $request->hasHeader('Forwarded')) {
            $elements = ForwardedParser::parse($request->getHeaderLine('Forwarded'));
            if ($elements === null || $elements === []) {
                return [$peer, []];
            }
            $client = $peer;
            $boundary = count($elements) - 1;
            for ($i = count($elements) - 1; $i >= 0; --$i) {
                $ip = ForwardedParser::nodeIp($elements[$i]['for'] ?? '');
                if ($ip === null) {
                    // An unknown hop is a trust boundary, not a gap to skip.
                    return [$client, []];
                }
                $client = $ip;
                $boundary = $i;
                if (!$this->networks->contains($ip)) {
                    break;
                }
            }
            return [$client, array_intersect_key($elements[$boundary], ['host' => true, 'proto' => true])];
        }
        if ($this->config->trustedHeaders === TrustedHeaders::Forwarded) {
            return [$peer, []];
        }

        $chain = $this->headerList($request, 'X-Forwarded-For');
        if ($chain === null) {
            return [$peer, []];
        }
        $client = $peer;
        $boundary = null;
        for ($i = count($chain) - 1; $i >= 0; --$i) {
            $ip = TrustedNetworks::normalize($chain[$i]);
            if ($ip === null) {
                return [$client, []];
            }
            $client = $ip;
            $boundary = $i;
            if (!$this->networks->contains($ip)) {
                break;
            }
        }

        $metadata = [];
        foreach (['proto' => 'X-Forwarded-Proto', 'host' => 'X-Forwarded-Host', 'port' => 'X-Forwarded-Port'] as $name => $header) {
            $values = $this->headerList($request, $header);
            if ($values === null || $values === []) {
                continue;
            }
            // A singleton must be overwritten by the trusted peer. Multi-hop
            // lists are usable only when aligned with the IP chain.
            if (count($values) === 1) {
                $metadata[$name] = $values[0];
            } elseif ($boundary !== null && count($values) === count($chain)) {
                $metadata[$name] = $values[$boundary];
            }
        }
        return [$client, $metadata];
    }

    /** @return list<string>|null */
    private function headerList(ServerRequestInterface $request, string $name): ?array
    {
        if (!$request->hasHeader($name)) {
            return [];
        }
        $value = $request->getHeaderLine($name);
        if (strlen($value) > ForwardedParser::MAX_HEADER_BYTES) {
            return null;
        }
        $values = array_map(static fn(string $part): string => trim($part, " \t"), explode(',', $value));
        return count($values) <= ForwardedParser::MAX_HOPS ? $values : null;
    }

    /** @param array<string, string> $metadata */
    private function applyMetadata(ServerRequestInterface $request, array $metadata): ServerRequestInterface
    {
        $uri = $request->getUri();
        $port = $uri->getPort();
        $scheme = strtolower($metadata['proto'] ?? '');
        if (in_array($scheme, ['http', 'https'], true)) {
            $uri = $uri->withScheme($scheme);
        }
        if (isset($metadata['host'])) {
            $authority = $this->parseAuthority($metadata['host']);
            if ($authority !== null) {
                [$host, $hostPort] = $authority;
                $uri = $uri->withHost($host);
                // An explicitly forwarded host with no port denotes the
                // default port of the forwarded scheme.
                $port = $hostPort;
            }
        }
        if (isset($metadata['port']) && ForwardedParser::validPort($metadata['port'])) {
            $port = (int) $metadata['port'];
        }
        if ($uri !== $request->getUri() || $port !== $uri->getPort()) {
            $uri = $uri->withPort($port);
            $request = $request->withUri($uri);
        }
        return $request;
    }

    /** @return array{string, ?int}|null */
    private function parseAuthority(string $value): ?array
    {
        if (preg_match('/^(\[[^\]]+\]|[^:\[\]]+)(?::([0-9]+))?$/D', $value, $matches) !== 1) {
            return null;
        }
        $host = strtolower($matches[1]);
        if (str_starts_with($host, '[')) {
            if (filter_var(substr($host, 1, -1), FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) === false) {
                return null;
            }
        } elseif (filter_var($host, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) === false
            && filter_var($host, FILTER_VALIDATE_DOMAIN, FILTER_FLAG_HOSTNAME) === false) {
            return null;
        }
        if (isset($matches[2]) && !ForwardedParser::validPort($matches[2])) {
            return null;
        }
        return [$host, isset($matches[2]) ? (int) $matches[2] : null];
    }
}
