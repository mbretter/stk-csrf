<?php

namespace Stk\Psr\Http\Middleware;

use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;
use Stk\Service\CsrfInterface;
use Tuupola\Http\Factory\ResponseFactory;

class Csrf implements MiddlewareInterface
{
    /** @var string the cookie which carries the csrf token */
    protected $cookiename = 'XSRF-TOKEN';

    /** @var string the header which must be sent back by the clients for validation */
    protected $headername = 'X-XSRF-TOKEN';

    /** @var int lifetime of csrf token cookie */
    protected $cookieLifetime = 86400 * 3650; // approx 1 year

    /** @var CsrfInterface */
    protected $service;

    public function __construct(CsrfInterface $csrfService, $config = [])
    {
        $this->service = $csrfService;

        if (isset($config['cookiename'])) {
            $this->cookiename = $config['cookiename'];
        }

        if (isset($config['headername'])) {
            $this->headername = $config['headername'];
        }

        if (isset($config['cookieLifetime'])) {
            $this->cookieLifetime = (int)$config['cookie-lifetime'];
        }
    }

    /**
     * @param ServerRequestInterface $request
     * @param ResponseInterface $response
     * @param callable $next
     *
     * @return ResponseInterface
     */
    public function __invoke(ServerRequestInterface $request, ResponseInterface $response, callable $next): ResponseInterface
    {
        if (!$next) {
            return $response;
        }

        $myResponse = $this->handle($request);
        if ($myResponse !== null) {
            $response = $response->withStatus($myResponse->getStatusCode());
        }

        return $next($request, $response);
    }

    /**
     * @inheritDoc
     */
    public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
    {
        $response = $handler->handle($request);
        if ($response === null) {
            $response = $handler->handle($request);
        }

        return $response;
    }

    protected function handle(ServerRequestInterface $request): ResponseInterface
    {
        // check for a csrf token or create one if none
        if ($this->service->hasToken() === false) {
            // create a single session token which never expires
            $token = $this->service->newToken(0, true);

            // set cookie, will be read by clients and send back as header
            $this->setCookie($token);
        } else {
            // validate token
            $csrfToken = $request->getHeaderLine($this->headername);

            if ($this->service->validateToken($csrfToken) === false) {
                return (new ResponseFactory)->createResponse(403);
            }
        }

        return null;
    }

    protected function setCookie($token)
    {
        // csrf token cookie must not be http-only
        // csrf token cookie ist sent via http and https to cover dev and prod env
        setcookie($this->cookiename, $token, time() + $this->cookieLifetime, '/', "", true, false);
    }
}
