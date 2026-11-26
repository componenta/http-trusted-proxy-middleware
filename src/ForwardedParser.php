<?php

declare(strict_types=1);

namespace Componenta\Http\Middleware\TrustedProxy;

/** @internal */
final class ForwardedParser
{
    public const int MAX_HEADER_BYTES = 16384;
    public const int MAX_HOPS = 128;

    /** @return list<array<string, string>>|null */
    public static function parse(string $header): ?array
    {
        if (strlen($header) > self::MAX_HEADER_BYTES) {
            return null;
        }
        $elements = self::split($header, ',');
        if ($elements === null || count($elements) > self::MAX_HOPS) {
            return null;
        }
        $result = [];
        foreach ($elements as $element) {
            $pairs = self::split($element, ';');
            if ($pairs === null) {
                return null;
            }
            $directives = [];
            foreach ($pairs as $pair) {
                $parts = explode('=', trim($pair, " \t"), 2);
                if (count($parts) !== 2 || !self::isToken($parts[0])) {
                    return null;
                }
                $name = strtolower($parts[0]);
                if (isset($directives[$name])) {
                    return null;
                }
                $value = self::decodeValue($parts[1]);
                if ($value === null) {
                    return null;
                }
                $directives[$name] = $value;
            }
            $result[] = $directives;
        }
        return $result;
    }

    /** @return list<string>|null */
    private static function split(string $value, string $separator): ?array
    {
        $result = [];
        $quoted = false;
        $start = 0;
        $length = strlen($value);
        for ($i = 0; $i < $length; ++$i) {
            $char = $value[$i];
            if ($quoted && $char === '\\') {
                if (++$i >= $length) {
                    return null;
                }
                continue;
            }
            if ($char === '"') {
                $quoted = !$quoted;
            } elseif (!$quoted && $char === $separator) {
                $result[] = substr($value, $start, $i - $start);
                $start = $i + 1;
            }
        }
        if ($quoted) {
            return null;
        }
        $result[] = substr($value, $start);
        return $result;
    }

    private static function isToken(string $value): bool
    {
        return preg_match("@^[!#$%&'*+.^_\x60|~0-9A-Za-z-]+$@D", $value) === 1;
    }

    private static function decodeValue(string $value): ?string
    {
        if (self::isToken($value)) {
            return $value;
        }
        if (strlen($value) < 2 || $value[0] !== '"' || !str_ends_with($value, '"')) {
            return null;
        }
        $inner = substr($value, 1, -1);
        $decoded = '';
        $length = strlen($inner);
        for ($i = 0; $i < $length; ++$i) {
            $char = $inner[$i];
            if ($char === '\\') {
                if (++$i >= $length) {
                    return null;
                }
                $char = $inner[$i];
            } elseif ($char === '"') {
                return null;
            }
            $ord = ord($char);
            if (($ord < 32 && $ord !== 9) || $ord === 127) {
                return null;
            }
            $decoded .= $char;
        }
        return $decoded;
    }

    public static function nodeIp(string $node): ?string
    {
        if (preg_match('/^\[([^\]]+)\](?::([0-9]+|_[A-Za-z0-9._-]+))?$/D', $node, $parts) === 1) {
            if (isset($parts[2]) && ctype_digit($parts[2]) && !self::validPort($parts[2])) {
                return null;
            }
            if (filter_var($parts[1], FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) === false) {
                return null;
            }
            return TrustedNetworks::normalize($parts[1]);
        }
        if (preg_match('/^([0-9.]+):([0-9]+|_[A-Za-z0-9._-]+)$/D', $node, $parts) === 1) {
            if (ctype_digit($parts[2]) && !self::validPort($parts[2])) {
                return null;
            }
            $node = $parts[1];
        }
        return filter_var($node, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) !== false
            ? TrustedNetworks::normalize($node)
            : null;
    }

    public static function validPort(string $value): bool
    {
        return preg_match('/^[0-9]{1,5}$/D', $value) === 1 && (int) $value >= 1 && (int) $value <= 65535;
    }
}
