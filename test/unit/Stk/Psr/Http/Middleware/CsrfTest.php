<?php

namespace StkTest\Psr\Http\Middleware;

use phpmock\phpunit\PHPMock;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Message\StreamInterface;
use Psr\Http\Server\RequestHandlerInterface;
use Stk\Psr\Http\Middleware\Csrf;
use Stk\Service\Csrf as CsrfService;

class CsrfTest extends TestCase
{
    use PHPMock;

    protected Csrf $middleware;

    /** @var MockObject|ServerRequestInterface */
    protected $service;

    /** @var MockObject|ServerRequestInterface */
    protected $request;

    /** @var MockObject|RequestHandlerInterface */
    protected $requestHandler;

    /** @var MockObject|ResponseInterface */
    protected $responseHandler;

    /** @var MockObject|ResponseInterface */
    protected $response;

    /** @var MockObject|StreamInterface */
    protected $body;

    protected ?string $language;

    protected array $languages;

    protected function setUp(): void
    {
        $this->request = $this->createMock(ServerRequestInterface::class);
        $this->body    = $this->createMock(StreamInterface::class);

        $this->responseHandler = $this->createMock(RequestHandlerInterface::class);
        $this->response        = $this->createMock(ResponseInterface::class);
        $this->response->method('getBody')->willReturn($this->body);
        $this->requestHandler = $this->createMock(RequestHandlerInterface::class);
        $this->requestHandler->method('handle')->willReturn($this->response);

        $this->service    = $this->createMock(CsrfService::class);
        $this->middleware = new Csrf($this->service);
    }

    public function testProcessEmptyStorage()
    {
        $this->service->method('hasToken')->willReturn(false);
        $timeMock = $this->getFunctionMock('Stk\Psr\Http\Middleware', 'time');
        $timeMock->expects($this->once())->willReturn(0);
        $setcookieMock = $this->getFunctionMock('Stk\Psr\Http\Middleware', 'setcookie');
        $setcookieMock->expects($this->once())->with('XSRF-TOKEN', $this->isType('string'), Csrf::COOKIE_LIFETIME, '/',
            "", true, false);
        $this->middleware->process($this->request, $this->requestHandler);
    }

    public function testProcessWithInvalidToken()
    {
        $this->request->method('getHeaderLine')->willReturn("");
        $this->request->method('getMethod')->willReturn("post");
        $this->service->method('hasToken')->willReturn(true);
        $this->service->method('validateToken')->with("")->willReturn(false);
        $setcookieMock = $this->getFunctionMock('Stk\Psr\Http\Middleware', 'setcookie');
        $setcookieMock->expects($this->once());
        $response = $this->middleware->process($this->request, $this->requestHandler);
        $this->assertEquals(Csrf::STATUS_CODE, $response->getStatusCode());
    }

    public function testProcessWithValidToken()
    {
        $this->request->method('getHeaderLine')->willReturn("sometoken");
        $this->service->method('hasToken')->willReturn(true);
        $this->service->method('validateToken')->with("sometoken")->willReturn(true);

        $response = $this->middleware->process($this->request, $this->requestHandler);
        $this->assertSame($response, $this->response);
    }

    public function testProcessExcludedMethod()
    {
        $this->request->expects($this->never())->method('getHeaderLine');
        $this->request->method('getMethod')->willReturn("get");
        $this->service->method('hasToken')->willReturn(true);
        $setcookieMock = $this->getFunctionMock('Stk\Psr\Http\Middleware', 'setcookie');
        $setcookieMock->expects($this->never());

        $response = $this->middleware->process($this->request, $this->requestHandler);
        $this->assertSame($response, $this->response);
    }

    public function testProcessExcludedMethodConfig()
    {
        $middleware = new Csrf($this->service, ['excluded' => ['get']]);
        $this->request->expects($this->never())->method('getHeaderLine');
        $this->request->method('getMethod')->willReturn("get");
        $this->service->method('hasToken')->willReturn(true);
        $this->service->expects($this->never())->method('validateToken');
        $setcookieMock = $this->getFunctionMock('Stk\Psr\Http\Middleware', 'setcookie');
        $setcookieMock->expects($this->never());

        $response = $middleware->process($this->request, $this->requestHandler);
        $this->assertSame($response, $this->response);
    }

    public function testCookieConfig()
    {
        $middleware = new Csrf($this->service,
            ['cookiename' => 'MYCOOKIE', 'cookie-lifetime' => 100, 'cookie-secure' => false]);

        $this->service->method('hasToken')->willReturn(false);
        $timeMock = $this->getFunctionMock('Stk\Psr\Http\Middleware', 'time');
        $timeMock->expects($this->once())->willReturn(0);
        $setcookieMock = $this->getFunctionMock('Stk\Psr\Http\Middleware', 'setcookie');
        $setcookieMock->expects($this->once())->with('MYCOOKIE', $this->isType('string'), 100, '/',
            "", false, false);
        $middleware->process($this->request, $this->requestHandler);
    }

    public function testProcessWithStatusCode()
    {
        $middleware = new Csrf($this->service, ['status-code' => 400, 'headername' => 'HEADERSRC']);

        $this->request->method('getHeaderLine')->with('HEADERSRC')->willReturn("");
        $this->request->method('getMethod')->willReturn("post");
        $this->service->method('hasToken')->willReturn(true);
        $this->service->method('validateToken')->with("")->willReturn(false);
        $setcookieMock = $this->getFunctionMock('Stk\Psr\Http\Middleware', 'setcookie');
        $setcookieMock->expects($this->once());
        $response = $middleware->process($this->request, $this->requestHandler);
        $this->assertEquals(400, $response->getStatusCode());
    }
}
