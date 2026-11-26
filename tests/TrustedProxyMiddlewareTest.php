<?php

declare(strict_types=1);

namespace Componenta\Http\Middleware\TrustedProxy\Tests;

use Componenta\Http\Middleware\TrustedProxy\TrustedHeaders;
use Componenta\Http\Middleware\TrustedProxy\TrustedProxyConfiguration;
use Componenta\Http\Middleware\TrustedProxy\TrustedProxyMiddleware;
use Nyholm\Psr7\Factory\Psr17Factory;
use PHPUnit\Framework\TestCase;
use PHPUnit\Framework\Attributes\DataProvider;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;

final class TrustedProxyMiddlewareTest extends TestCase
{
    public function testForwardedUsesOneTrustBoundaryAndUnderstandsQuotedStrings(): void
    {
        $request = $this->processRequest(TrustedHeaders::Forwarded, [
            'Forwarded' => 'for=203.0.113.99;host=untrusted.test, for=192.0.2.10;host="public.test:8443";proto=https;ext="a,b;c", for=10.0.0.2;host=internal.test',
        ]);
        self::assertSame('192.0.2.10', $request->getAttribute('client_ip'));
        self::assertSame('https://public.test:8443/', (string) $request->getUri());
        self::assertFalse($request->hasHeader('Forwarded'));
    }

    public function testUnknownHopDoesNotExposeEarlierClaims(): void
    {
        $request = $this->processRequest(TrustedHeaders::Forwarded, [
            'Forwarded' => 'for=203.0.113.99;host=untrusted.test, for=unknown',
        ]);
        self::assertSame('10.0.0.1', $request->getAttribute('client_ip'));
        self::assertSame('http://internal.test:8080/', (string) $request->getUri());
    }

    public function testNonstandardForwardedPortExtensionIsIgnored(): void
    {
        $request = $this->processRequest(TrustedHeaders::Forwarded, [
            'Forwarded' => 'for=192.0.2.10;host="public.test:8443";proto=https;port=4444',
        ]);
        self::assertSame(8443, $request->getUri()->getPort());
    }

    public function testMissingPortPreservesOriginalUri(): void
    {
        $request = $this->processRequest(TrustedHeaders::XForwarded, ['X-Forwarded-For' => '192.0.2.10']);
        self::assertSame(8080, $request->getUri()->getPort());
    }

    public function testAllDoesNotFallBackToOtherFamilyForMissingFields(): void
    {
        $request = $this->processRequest(TrustedHeaders::All, [
            'Forwarded' => 'for=192.0.2.10',
            'X-Forwarded-Host' => 'untrusted.test',
        ]);
        self::assertSame('internal.test', $request->getUri()->getHost());
    }

    public function testUntrustedPeerCannotSupplyForwardingHeaders(): void
    {
        $request = $this->processRequest(TrustedHeaders::All, ['Forwarded' => 'for=192.0.2.10;host=untrusted.test'], '203.0.113.10');
        self::assertSame('203.0.113.10', $request->getAttribute('client_ip'));
        self::assertSame('internal.test', $request->getUri()->getHost());
        self::assertFalse($request->hasHeader('Forwarded'));
    }

    public function testEquivalentIpv6AddressIsTrusted(): void
    {
        $request = $this->processRequest(TrustedHeaders::XForwarded, ['X-Forwarded-For' => '192.0.2.10'], '2001:0db8:0:0:0:0:0:1');
        self::assertSame('192.0.2.10', $request->getAttribute('client_ip'));
    }

    public function testMappedPeerMatchesTrustedIpv4Network(): void
    {
        $request = $this->processRequest(TrustedHeaders::XForwarded, ['X-Forwarded-For' => '192.0.2.10'], '::ffff:a00:1');
        self::assertSame('192.0.2.10', $request->getAttribute('client_ip'));
    }

    public function testMalformedXForwardedHopStopsTrustTraversal(): void
    {
        $request = $this->processRequest(TrustedHeaders::XForwarded, [
            'X-Forwarded-For' => '203.0.113.99, invalid, 10.0.0.2',
            'X-Forwarded-Host' => 'untrusted.test, untrusted.test, internal.test',
        ]);
        self::assertSame('10.0.0.2', $request->getAttribute('client_ip'));
        self::assertSame('internal.test', $request->getUri()->getHost());
    }

    public function testOverlongChainIsIgnored(): void
    {
        $request = $this->processRequest(TrustedHeaders::XForwarded, [
            'X-Forwarded-For' => implode(',', array_fill(0, 129, '192.0.2.10')),
            'X-Forwarded-Host' => 'untrusted.test',
        ]);
        self::assertSame('10.0.0.1', $request->getAttribute('client_ip'));
        self::assertSame('internal.test', $request->getUri()->getHost());
    }

    public function testMisalignedMetadataIsIgnored(): void
    {
        $request = $this->processRequest(TrustedHeaders::XForwarded, [
            'X-Forwarded-For' => '192.0.2.10, 10.0.0.2',
            'X-Forwarded-Host' => 'untrusted.test, public.test, internal.test',
        ]);
        self::assertSame('192.0.2.10', $request->getAttribute('client_ip'));
        self::assertSame('internal.test', $request->getUri()->getHost());
    }

    public function testMalformedPortIsNotPartiallyParsed(): void
    {
        $request = $this->processRequest(TrustedHeaders::XForwarded, ['X-Forwarded-Port' => '443junk']);
        self::assertSame(8080, $request->getUri()->getPort());
    }

    public function testXForwardedListsAreAlignedAtTrustBoundary(): void
    {
        $request = $this->processRequest(TrustedHeaders::XForwarded, [
            'X-Forwarded-For' => '203.0.113.99, 192.0.2.10, 10.0.0.2',
            'X-Forwarded-Host' => 'untrusted.test, public.test, internal.test',
            'X-Forwarded-Proto' => 'http, https, http',
        ]);
        self::assertSame('192.0.2.10', $request->getAttribute('client_ip'));
        self::assertSame('https://public.test/', (string) $request->getUri());
    }

    public static function invalidForwarded(): iterable
    {
        yield 'missing value' => ['for='];
        yield 'missing equals' => ['for=192.0.2.10;broken'];
        yield 'duplicate directive' => ['for=192.0.2.10;FOR=203.0.113.99'];
        yield 'invalid directive name' => ['for=192.0.2.10;bad name=value'];
        yield 'unclosed quote' => ['for=192.0.2.10;ext="a,b'];
        yield 'unescaped internal quote' => ['for=192.0.2.10;ext="a"b"c"'];
        yield 'malformed value' => ['for=192.0.2.10;ext=not a token'];
        yield 'invalid bracketed address' => ['for="[192.0.2.10]"'];
        yield 'invalid ipv6 port' => ['for="[2001:db8::10]:0"'];
        yield 'invalid ipv4 port' => ['for="192.0.2.10:65536"'];
        yield 'invalid node' => ['for=_hidden'];
        yield 'obfuscated node' => ['for=unknown'];
        yield 'missing node' => ['host=public.test'];
        yield 'empty element' => ['for=192.0.2.10,'];
    }

    #[DataProvider('invalidForwarded')]
    public function testMalformedForwardedCannotSelectHostOrFallbackToOtherFamily(string $header): void
    {
        $request = $this->processRequest(TrustedHeaders::All, [
            'Forwarded' => $header,
            'X-Forwarded-For' => '192.0.2.99',
            'X-Forwarded-Host' => 'untrusted.test',
        ]);
        self::assertSame('10.0.0.1', $request->getAttribute('client_ip'));
        self::assertSame('http://internal.test:8080/', (string) $request->getUri());
        self::assertFalse($request->hasHeader('Forwarded'));
        self::assertFalse($request->hasHeader('X-Forwarded-For'));
        self::assertFalse($request->hasHeader('X-Forwarded-Host'));
    }

    public function testForwardedDirectiveNamesAreCaseInsensitiveAndQuotedPairsAreDecoded(): void
    {
        $request = $this->processRequest(TrustedHeaders::Forwarded, [
            'Forwarded' => 'FOR="192.0.2.10:65535";HOST="[2001:db8::10]:1";PROTO=HTTPS;ext="a\"b,;=c";empty=""',
        ]);
        self::assertSame('192.0.2.10', $request->getAttribute('client_ip'));
        self::assertSame('https://[2001:db8::10]:1/', (string) $request->getUri());
        self::assertSame('[2001:db8::10]:1', $request->getHeaderLine('Host'));
    }

    public function testForwardedSizeAndHopLimitsAreInclusive(): void
    {
        $prefix = 'for=192.0.2.10;ext="';
        $allowed = $prefix . str_repeat('a', 16384 - strlen($prefix) - 1) . '"';
        self::assertSame(16384, strlen($allowed));
        self::assertSame('192.0.2.10', $this->processRequest(TrustedHeaders::Forwarded, ['Forwarded' => $allowed])->getAttribute('client_ip'));
        $denied = substr($allowed, 0, -1) . 'a"';
        self::assertSame('10.0.0.1', $this->processRequest(TrustedHeaders::Forwarded, ['Forwarded' => $denied])->getAttribute('client_ip'));
        foreach ([128 => '192.0.2.10', 129 => '10.0.0.1'] as $count => $expected) {
            $header = implode(',', array_fill(0, $count, 'for=192.0.2.10'));
            self::assertSame($expected, $this->processRequest(TrustedHeaders::Forwarded, ['Forwarded' => $header])->getAttribute('client_ip'));
        }
    }

    public function testXForwardedSizeAndHopLimitsAreInclusive(): void
    {
        $prefix = '192.0.2.10,';
        $suffix = '10.0.0.2';
        $allowed = $prefix . str_repeat(' ', 16384 - strlen($prefix) - strlen($suffix)) . $suffix;
        self::assertSame('192.0.2.10', $this->processRequest(TrustedHeaders::XForwarded, ['X-Forwarded-For' => $allowed])->getAttribute('client_ip'));
        self::assertSame('10.0.0.1', $this->processRequest(TrustedHeaders::XForwarded, ['X-Forwarded-For' => $allowed . ' ' . $suffix])->getAttribute('client_ip'));
        self::assertSame('192.0.2.10', $this->processRequest(TrustedHeaders::XForwarded, [
            'X-Forwarded-For' => implode(',', array_fill(0, 128, '192.0.2.10')),
        ])->getAttribute('client_ip'));
    }

    public static function networks(): iterable
    {
        yield 'ipv4 partial byte inside' => [['192.0.2.0/31'], '192.0.2.1', true];
        yield 'ipv4 partial byte outside' => [['192.0.2.0/31'], '192.0.2.2', false];
        yield 'ipv6 partial byte inside' => [['2001:db8::/33'], '2001:db8:7fff::1', true];
        yield 'ipv6 partial byte outside' => [['2001:db8::/33'], '2001:db8:8000::1', false];
        yield 'ipv6 mapped network' => [['::ffff:c000:200/120'], '192.0.2.1', true];
        yield 'ipv6 mapped network outside' => [['::ffff:c000:200/120'], '192.0.3.1', false];
        yield 'IPv4 zero mask' => [['0.0.0.0/0'], '203.0.113.1', true];
        yield 'IPv6 exact' => [['2001:db8::1/128'], '2001:db8::2', false];
        yield 'distinct family' => [['2001:db8::/32'], '192.0.2.1', false];
        yield 'no proxies' => [[], '10.0.0.1', false];
    }

    #[DataProvider('networks')]
    public function testNetworkBoundaryUsesBinaryPrefix(array $networks, string $peer, bool $trusted): void
    {
        $request = $this->processRequest(TrustedHeaders::XForwarded, [
            'X-Forwarded-For' => '198.51.100.10',
            'X-Forwarded-Host' => 'public.test',
        ], $peer, new TrustedProxyConfiguration($networks));
        self::assertSame($trusted ? '198.51.100.10' : $peer, $request->getAttribute('client_ip'));
        self::assertSame($trusted ? 'public.test' : 'internal.test', $request->getUri()->getHost());
    }

    public static function invalidNetworks(): iterable
    {
        foreach ([null, 42, [], 'invalid', 'bad/24', '192.0.2.0/33', '192.0.2.0/-1', '192.0.2.0/01', '192.0.2.0/24x', '2001:db8::/129', '192.0.2.0/'] as $entry) {
            yield [$entry];
        }
    }

    #[DataProvider('invalidNetworks')]
    public function testInvalidConfigurationFailsBeforeProcessing(mixed $entry): void
    {
        $this->expectException(\InvalidArgumentException::class);
        new TrustedProxyConfiguration([$entry]);
    }

    public function testPrivateRangesAreOptInAndAllTrustedChainUsesEarliestNode(): void
    {
        $request = $this->processRequest(TrustedHeaders::All, [
            'X-Forwarded-For' => '10.0.0.2, 10.0.0.3',
            'X-Forwarded-Host' => 'public.test',
            'X-Forwarded-Proto' => 'HTTPS',
            'X-Forwarded-Port' => '443',
        ], '10.0.0.1', new TrustedProxyConfiguration(trustedHeaders: TrustedHeaders::All, trustPrivateNetworks: true));
        self::assertSame('10.0.0.2', $request->getAttribute('client_ip'));
        self::assertSame('https://public.test/', (string) $request->getUri());
        foreach (['X-Forwarded-For', 'X-Forwarded-Host', 'X-Forwarded-Proto', 'X-Forwarded-Port'] as $header) {
            self::assertFalse($request->hasHeader($header));
        }
    }

    public static function invalidAuthorities(): iterable
    {
        foreach (['user@public.test', 'public.test:0', 'public.test:65536', 'public.test:443x', '[192.0.2.1]', '[2001:db8::1]junk', 'bad host', ''] as $authority) {
            yield [$authority];
        }
    }

    #[DataProvider('invalidAuthorities')]
    public function testInvalidAuthorityDoesNotChangeUri(string $authority): void
    {
        $request = $this->processRequest(TrustedHeaders::XForwarded, [
            'X-Forwarded-Host' => $authority,
            'X-Forwarded-Proto' => 'ftp',
        ]);
        self::assertSame('http://internal.test:8080/', (string) $request->getUri());
    }

    /** @param array<string, string> $headers */
    private function processRequest(TrustedHeaders $format, array $headers, string $peer = '10.0.0.1', ?TrustedProxyConfiguration $config = null): ServerRequestInterface
    {
        $factory = new Psr17Factory();
        $request = $factory->createServerRequest('GET', 'http://internal.test:8080/', ['REMOTE_ADDR' => $peer]);
        foreach ($headers as $name => $value) {
            $request = $request->withHeader($name, $value);
        }
        $handler = new class implements RequestHandlerInterface {
            public ?ServerRequestInterface $request = null;
            public function handle(ServerRequestInterface $request): ResponseInterface
            {
                $this->request = $request;
                return (new Psr17Factory())->createResponse(204);
            }
        };
        $middleware = new TrustedProxyMiddleware($config ?? new TrustedProxyConfiguration(['10.0.0.0/8', '2001:db8::1'], $format));
        self::assertSame(204, $middleware->process($request, $handler)->getStatusCode());
        self::assertNotNull($handler->request);
        return $handler->request;
    }
}
