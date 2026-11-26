<?php

declare(strict_types=1);

namespace Componenta\Http\Middleware\TrustedProxy\Tests;

use Componenta\Http\Middleware\TrustedProxy\TrustedHeaders;
use Componenta\Http\Middleware\TrustedProxy\TrustedProxyConfiguration;
use Componenta\Http\Middleware\TrustedProxy\TrustedProxyMiddleware;
use Nyholm\Psr7\Factory\Psr17Factory;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;

final class TrustedProxyMiddlewareTest extends TestCase
{
    public function testForwardedUsesOneTrustBoundaryAndUnderstandsQuotedStrings(): void
    {
        $request = $this->run(TrustedHeaders::Forwarded, [
            'Forwarded' => 'for=203.0.113.99;host=untrusted.test, for=192.0.2.10;host="public.test:8443";proto=https;ext="a,b;c", for=10.0.0.2;host=internal.test',
        ]);
        self::assertSame('192.0.2.10', $request->getAttribute('client_ip'));
        self::assertSame('https://public.test:8443/', (string) $request->getUri());
        self::assertFalse($request->hasHeader('Forwarded'));
    }

    public function testUnknownHopDoesNotExposeEarlierClaims(): void
    {
        $request = $this->run(TrustedHeaders::Forwarded, [
            'Forwarded' => 'for=203.0.113.99;host=untrusted.test, for=unknown',
        ]);
        self::assertSame('10.0.0.1', $request->getAttribute('client_ip'));
        self::assertSame('http://internal.test:8080/', (string) $request->getUri());
    }

    public function testMissingPortPreservesOriginalUri(): void
    {
        $request = $this->run(TrustedHeaders::XForwarded, ['X-Forwarded-For' => '192.0.2.10']);
        self::assertSame(8080, $request->getUri()->getPort());
    }

    public function testAllDoesNotFallBackToOtherFamilyForMissingFields(): void
    {
        $request = $this->run(TrustedHeaders::All, [
            'Forwarded' => 'for=192.0.2.10',
            'X-Forwarded-Host' => 'untrusted.test',
        ]);
        self::assertSame('internal.test', $request->getUri()->getHost());
    }

    public function testUntrustedPeerCannotSupplyForwardingHeaders(): void
    {
        $request = $this->run(TrustedHeaders::All, ['Forwarded' => 'for=192.0.2.10;host=untrusted.test'], '203.0.113.10');
        self::assertSame('203.0.113.10', $request->getAttribute('client_ip'));
        self::assertSame('internal.test', $request->getUri()->getHost());
        self::assertFalse($request->hasHeader('Forwarded'));
    }

    public function testEquivalentIpv6AddressIsTrusted(): void
    {
        $request = $this->run(TrustedHeaders::XForwarded, ['X-Forwarded-For' => '192.0.2.10'], '2001:0db8:0:0:0:0:0:1');
        self::assertSame('192.0.2.10', $request->getAttribute('client_ip'));
    }

    public function testMalformedPortIsNotPartiallyParsed(): void
    {
        $request = $this->run(TrustedHeaders::XForwarded, ['X-Forwarded-Port' => '443junk']);
        self::assertSame(8080, $request->getUri()->getPort());
    }

    public function testXForwardedListsAreAlignedAtTrustBoundary(): void
    {
        $request = $this->run(TrustedHeaders::XForwarded, [
            'X-Forwarded-For' => '203.0.113.99, 192.0.2.10, 10.0.0.2',
            'X-Forwarded-Host' => 'untrusted.test, public.test, internal.test',
            'X-Forwarded-Proto' => 'http, https, http',
        ]);
        self::assertSame('192.0.2.10', $request->getAttribute('client_ip'));
        self::assertSame('https://public.test/', (string) $request->getUri());
    }

    /** @param array<string, string> $headers */
    private function run(TrustedHeaders $format, array $headers, string $peer = '10.0.0.1'): ServerRequestInterface
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
        $middleware = new TrustedProxyMiddleware(new TrustedProxyConfiguration(['10.0.0.0/8', '2001:db8::1'], $format));
        self::assertSame(204, $middleware->process($request, $handler)->getStatusCode());
        self::assertNotNull($handler->request);
        return $handler->request;
    }
}
