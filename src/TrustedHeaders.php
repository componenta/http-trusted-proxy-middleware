<?php

declare(strict_types=1);

namespace Componenta\Http\Middleware\TrustedProxy;

/**
 * Specifies which forwarding header format to trust.
 *
 * @see RFC 7239 - Forwarded HTTP Extension (standardized)
 */
enum TrustedHeaders: string
{
    /** De facto standard: X-Forwarded-For, X-Forwarded-Proto, X-Forwarded-Host, X-Forwarded-Port. */
    case XForwarded = 'x-forwarded';

    /** RFC 7239 Forwarded header with for/proto/host/by directives. */
    case Forwarded = 'forwarded';

    /** Both formats; RFC 7239 takes precedence when present. */
    case All = 'all';
}
