<?php

namespace Stk\Psr\Http\Middleware;

use Exception;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;
use Stk\Service\CsrfInterface;
use Tuupola\Http\Factory\ResponseFactory;

class Csrf implements MiddlewareInterface
{
    const COOKIE_LIFETIME = 86400 * 365; // approx 1 year
    const STATUS_CODE     = 403;

    /** @var string the cookie which carries the csrf token */
    protected string $cookiename = 'XSRF-TOKEN';

    /** @var string the header which must be sent back by the clients for validation */
    protected string $headername = 'X-XSRF-TOKEN';

    /** @var int lifetime of csrf token cookie */
    protected int $cookieLifetime = self::COOKIE_LIFETIME;

    /** @var bool set secure (https) option to cookie */
    protected bool $cookieSecure = true;

    /** @var int http status code if validation failed */
    protected int $statusCode = self::STATUS_CODE;

    /** @var array|string[] excluded http methods */
    protected array $excluded = ['GET', 'HEAD', 'OPTIONS'];

    /** @var CsrfInterface */
    protected CsrfInterface $service;

    public function __construct(CsrfInterface $csrfService, array $config = [])
    {
        $this->service = $csrfService;

        if (isset($config['cookiename'])) {
            $this->cookiename = $config['cookiename'];
        }

        if (isset($config['cookie-lifetime'])) {
            $this->cookieLifetime = (int) $config['cookie-lifetime'];
        }

        if (isset($config['cookie-secure'])) {
            $this->cookieSecure = (bool) $config['cookie-secure'];
        }

        if (isset($config['headername'])) {
            $this->headername = $config['headername'];
        }

        if (isset($config['status-code'])) {
            $this->statusCode = (int) $config['status-code'];
        }

        if (isset($config['excluded']) && is_array($config['excluded'])) {
            $this->excluded = array_map(fn($m) => strtoupper($m), $config['excluded']);
        }
    }

    /**
     * @param ServerRequestInterface $request
     * @param ResponseInterface $response
     * @param callable $next
     *
     * @return ResponseInterface
     * @throws Exception
     */
    public function __invoke(
        ServerRequestInterface $request,
        ResponseInterface $response,
        callable $next
    ): ResponseInterface {
        if ($next == null) {
            return $response;
        }

        $myResponse = $this->handle($request);
        if ($myResponse !== null) {
            return $response->withStatus($myResponse->getStatusCode());
        }

        return $next($request, $response);
    }

    /**
     * @inheritDoc
     */
    public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
    {
        $response = $this->handle($request);
        if ($response !== null) {
            return $response;
        }

        return $handler->handle($request);
    }

    /**
     * @param ServerRequestInterface $request
     *
     * @return ResponseInterface|null
     * @throws Exception
     */
    protected function handle(ServerRequestInterface $request): ?ResponseInterface
    {
        // check for a csrf token or create one if none
        if ($this->service->hasToken() === false) {
            $this->sendNewToken();
        } else {
            // exclude certain methods
            if (in_array(strtoupper($request->getMethod()), $this->excluded)) {
                return null;
            }
            // validate token
            $csrfToken = $request->getHeaderLine($this->headername);

            if ($this->service->validateToken($csrfToken) === false) {
                $this->sendNewToken();

                return (new ResponseFactory)->createResponse($this->statusCode);
            }
        }

        return null;
    }

    protected function sendNewToken(): void
    {
        // create a single session token which never expires
        $token = $this->service->newToken(0, true);

        // set cookie, will be read by clients and send back as header
        $this->setCookie($token);
    }

    protected function setCookie(string $token): void
    {
        // csrf token cookie must not be http-only
        // csrf token cookie ist sent via http and https to cover dev and prod env
        setcookie($this->cookiename, $token, time() + $this->cookieLifetime, '/', "", $this->cookieSecure, false);
    }
}
