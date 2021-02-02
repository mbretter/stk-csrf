<?php

namespace StkTest\Service;

use ArrayObject;
use PHPUnit\Framework\TestCase;
use Stk\Service\Csrf;

class CsrfTest extends TestCase
{
    protected Csrf $csrf;

    protected ArrayObject $storage;

    public function setUp(): void
    {
        $this->storage = new ArrayObject([]);
        $this->csrf    = new Csrf($this->storage);
    }

    public function testNewToken()
    {
        $token = $this->csrf->newToken();
        $this->assertIsString($token);
        $this->assertIsArray($this->storage['csrftokens']);
        $this->assertIsArray($this->storage['csrftokens']['session']);
        $this->assertCount(1, $this->storage['csrftokens']['session']);
        $this->assertIsObject($this->storage['csrftokens']['session'][0]);
        $stored = $this->storage['csrftokens']['session'][0];
        $this->assertEquals(1800, $stored->lifetime);
        $this->assertEquals($token, $stored->value);
    }

    public function testNewTokenWithParams()
    {
        $token = $this->csrf->newToken(60, true);
        $this->assertIsString($token);
        $this->assertIsObject($this->storage['csrftokens']['session']);
        $stored = $this->storage['csrftokens']['session'];
        $this->assertEquals(60, $stored->lifetime);
        $this->assertEquals($token, $stored->value);
    }

    public function testHasToken()
    {
        $this->assertFalse($this->csrf->hasToken());
        $this->csrf->newToken(60, true);
        $this->assertTrue($this->csrf->hasToken());
    }

    public function testValidateTokenNone()
    {
        $this->assertFalse($this->csrf->validateToken(""));
        $this->assertFalse($this->csrf->validateToken("foo"));
    }

    public function testValidateToken()
    {
        $token = $this->csrf->newToken(60);
        $this->assertTrue($this->csrf->validateToken($token));
    }

    public function testValidateSingleToken()
    {
        $token = $this->csrf->newToken(60, true);
        $this->assertTrue($this->csrf->validateToken($token));
    }

    public function testValidateTokenNoneExistend()
    {
        $this->csrf->newToken(60, true);
        $this->assertFalse($this->csrf->validateToken("4iHA4QznVn85beNn0auiile836E2xdFRRNoekBO2DqQ"));
    }

    public function testMaxTokens()
    {
        $csrf = new Csrf($this->storage, ['maxtokens' => 2]);
        $csrf->newToken();
        $t2     = $csrf->newToken();
        $t3     = $csrf->newToken();
        $tokens = $this->storage['csrftokens']['session'];
        $this->assertCount(2, $tokens);

        $this->assertEquals([$t2, $t3], array_map(fn($t) => $t->value, $tokens));
    }

    public function testValidateLifetime()
    {
        $csrf  = new Csrf($this->storage, ['tokenlifetime' => 1]);
        $token = $csrf->newToken();
        sleep(2);
        $this->assertFalse($csrf->validateToken($token));
    }

    public function testStorageKey()
    {
        $csrf = new Csrf($this->storage, ['storagekey' => 'foo']);
        $csrf->newToken();
        $this->assertIsArray($this->storage['foo']);
    }


    public function testNamespace()
    {
        $csrf = new Csrf($this->storage, ['namespace' => 'foo']);
        $csrf->newToken();
        $this->assertIsArray($this->storage['csrftokens']['foo']);
    }

}
