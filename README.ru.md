# Componenta HTTP Trusted Proxy Middleware

PSR-15 промежуточный обработчик для восстановления клиентского IP, схемы, хоста и порта из заголовков доверенных прокси. Он полезен, когда приложение работает за обратным прокси или балансировщиком нагрузки.

## Граница пакета

Пакет только нормализует данные запроса, пришедшего через доверенный прокси. Ограничение частоты запросов, CORS, CSRF и аутентификация подключаются отдельными пакетами.

## Установка

```bash
composer require componenta/http-trusted-proxy-middleware
```

У пакета нет провайдера конфигурации. Создавайте конфигурацию и промежуточный обработчик явно.

## Быстрый старт

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

## Поведение

Если удаленный адрес доверенный, обработчик читает forwarding-заголовки, вычисляет исходный клиентский IP и обновляет URI запроса: схему, хост и порт. Найденный клиентский IP записывается в атрибут запроса `client_ip`.

Если удаленный адрес не доверенный, forwarding-заголовки игнорируются и удаляются из запроса перед передачей дальше. После обработки доверенного прокси эти заголовки тоже удаляются, поэтому код приложения должен читать измененный URI и атрибут `client_ip`, а не сырые заголовки.

`TrustedHeaders` поддерживает `XForwarded`, `Forwarded` и `All`.

`trustPrivateNetworks: true` дополнительно доверяет распространенным приватным и loopback-диапазонам. Оставляйте этот режим выключенным, если топология развертывания явно не делает эти диапазоны доверенными.

## Связанные пакеты

`componenta/http-throttle-middleware` использует `client_ip`, когда этот атрибут доступен.
