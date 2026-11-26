# Componenta HTTP Trusted Proxy Middleware

PSR-15 middleware for resolving client IP, scheme, host, and port from trusted proxy headers. It is useful when the application runs behind a reverse proxy or load balancer.

## Installation

```bash
composer require componenta/http-trusted-proxy-middleware
```

This package has no config provider. Create the configuration and middleware explicitly.

## Quick Start

```php
use Componenta\Http\Middleware\TrustedProxy\TrustedHeaders;
use Componenta\Http\Middleware\TrustedProxy\TrustedProxyConfiguration;
use Componenta\Http\Middleware\TrustedProxy\TrustedProxyMiddleware;

$middleware = new TrustedProxyMiddleware(new TrustedProxyConfiguration(
    trustedProxies: ['10.0.0.0/8', '127.0.0.1'],
    trustedHeaders: TrustedHeaders::XForwarded,
    trustPrivateNetworks: false,
));
```

## Runtime Behavior

When the remote address is trusted, the middleware reads forwarding headers, resolves the original client IP, and updates the request URI scheme, host, and port. It writes the resolved client IP to the `client_ip` request attribute.

When the remote address is not trusted, forwarding headers are ignored and stripped from the downstream request. Forwarding headers are also stripped after a trusted proxy request is resolved, so application code should read the modified URI and `client_ip` attribute instead of raw headers.

`TrustedHeaders` supports `XForwarded`, `Forwarded`, and `All`.

`trustPrivateNetworks: true` also trusts common private and loopback ranges. Leave it disabled unless the deployment topology makes those ranges trusted.

## Related Packages

`componenta/http-throttle-middleware` uses `client_ip` when it is available.

## Forwarding trust contract

The immediate peer must be explicitly trusted and must sanitize incoming forwarding headers. Configure trusted proxy addresses narrowly. In `Forwarded` mode the client and URI metadata come from the same element at the trust boundary; unknown or malformed hops stop the walk. In `All` mode, a present `Forwarded` header selects that family exclusively, even if malformed. For `X-Forwarded-*`, singleton URI headers must be overwritten by the immediate trusted proxy; multi-value URI headers must align with the `X-Forwarded-For` chain. Misaligned lists are ignored. Only HTTP(S) schemes and valid authorities are accepted. Header values are bounded to 16 KiB and chains to 128 hops. Missing URI metadata preserves the original URI. Validate the application's allowed host separately.

Run regression tests with `composer test`.
