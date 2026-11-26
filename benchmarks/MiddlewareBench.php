<?php

declare(strict_types=1);

namespace Componenta\Http\Middleware\TrustedProxy\Benchmarks;

use Componenta\Http\Middleware\TrustedProxy\TrustedHeaders;
use Componenta\Http\Middleware\TrustedProxy\TrustedProxyConfiguration;
use Componenta\Http\Middleware\TrustedProxy\TrustedProxyMiddleware;
use Nyholm\Psr7\Factory\Psr17Factory;
use PhpBench\Attributes as Bench;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;

#[Bench\BeforeMethods('setUp')]
#[Bench\Iterations(5)]
#[Bench\Revs(1000)]
final class TrustedProxyBench
{
    private TrustedProxyMiddleware $xff;
    private TrustedProxyMiddleware $forwarded;
    private ServerRequestInterface $direct;
    private ServerRequestInterface $chain;
    private ServerRequestInterface $rfc;
    private RequestHandlerInterface $handler;

    public function setUp(): void
    {
        $factory = new Psr17Factory();
        $this->xff = new TrustedProxyMiddleware(new TrustedProxyConfiguration(['10.0.0.0/8', '2001:db8::/32']));
        $this->forwarded = new TrustedProxyMiddleware(new TrustedProxyConfiguration(['10.0.0.0/8', '2001:db8::/32'], TrustedHeaders::Forwarded));
        $this->direct = $factory->createServerRequest('GET', 'https://api.example.test/', ['REMOTE_ADDR' => '192.0.2.10']);
        $this->chain = $factory->createServerRequest('GET', 'http://internal.test/', ['REMOTE_ADDR' => '10.0.0.1'])
            ->withHeader('X-Forwarded-For', '192.0.2.10, 10.0.0.2, 10.0.0.3')
            ->withHeader('X-Forwarded-Host', 'api.example.test, internal.test, internal.test')
            ->withHeader('X-Forwarded-Proto', 'https, http, http');
        $this->rfc = $factory->createServerRequest('GET', 'http://internal.test/', ['REMOTE_ADDR' => '10.0.0.1'])
            ->withHeader('Forwarded', 'for="[2001:db8:ffff::1]";host="api.example.test:8443";proto=https, for=10.0.0.2, for=10.0.0.3');
        $this->handler = new class($factory->createResponse(204)) implements RequestHandlerInterface {
            public function __construct(private readonly ResponseInterface $response) {}
            public function handle(ServerRequestInterface $request): ResponseInterface { return $this->response; }
        };
    }

    public function benchDirect(): void { $this->xff->process($this->direct, $this->handler); }
    public function benchXForwardedChain(): void { $this->xff->process($this->chain, $this->handler); }
    public function benchRfc7239Chain(): void { $this->forwarded->process($this->rfc, $this->handler); }
}
