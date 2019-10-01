<?php

namespace Stk\Service;

use ArrayAccess;
use DateTime;
use Exception;
use stdClass;

class Csrf implements Injectable, CsrfInterface
{
    protected $storageKey = 'csrftokens';

    /** @var int token lifetime in seconds */
    protected $tokenlifetime = 1800;

    /** @var int|mixed max number of tokens */
    protected $maxtokens = 200;

    /** @var string the default namespace within the storage */
    protected $namespace = 'session';

    /** @var ArrayAccess anything providing this interface */
    protected $storage;

    public function __construct(ArrayAccess $storage, $config = [])
    {
        $this->storage = $storage;

        if (isset($config['tokenlifetime'])) {
            $this->tokenlifetime = $config['tokenlifetime'];
        }

        if (isset($config['maxtokens'])) {
            $this->maxtokens = $config['maxtokens'];
        }

        if (isset($config['storagekey'])) {
            $this->storageKey = $config['storagekey'];
        }

        if (isset($config['namespace']) && strlen($config['namespace'])) {
            $this->namespace = $config['namespace'];
        }
    }

    /**
     * create a token with the giver lifetime in seconds
     *
     * @param null $lifetime
     *
     * @return stdClass
     * @throws Exception
     */
    protected function createToken($lifetime = null)
    {
        $token           = new stdClass();
        $token->value    = $this->base64UrlEncode(random_bytes(32));
        $token->datetime = new DateTime('@' . time()); // just for unit tests, to get reproducable timestamps
        $token->lifetime = $this->tokenlifetime;

        if (is_int($lifetime)) {
            $token->lifetime = $lifetime;
        }

        return $token;
    }

    /**
     * generate and store a new token
     *
     * @param null $lifetime
     * @param bool $single
     *
     * @return string
     * @throws Exception
     */
    public function newToken($lifetime = null, $single = false): string
    {
        $token = $this->createToken($lifetime);

        $this->storeToken($token, $single);

        return $token->value;
    }

    protected function storeToken($token, $single = false)
    {
        $tokens = $this->getTokens();

        if ($single) {
            $tokens[$this->namespace] = $token;
        } else {
            if (!isset($tokens[$this->namespace])) {
                $tokens[$this->namespace] = [];
            }

            if ($this->maxtokens > 0 && count($tokens[$this->namespace]) > $this->maxtokens) {
                array_shift($tokens[$this->namespace]);
            }

            $tokens[$this->namespace][] = $token;
        }

        $this->storage[$this->storageKey] = $tokens;

        return $this;
    }

    /**
     * check whether tokens are available
     *
     * @return bool
     */
    public function hasToken(): bool
    {
        $tokens = $this->getTokens();

        return isset($tokens[$this->namespace]);
    }

    public function validateToken($token): bool
    {
        if (!is_string($token) || !strlen($token)) {
            return false;
        }

        $tokens = $this->getTokens();

        if (!isset($tokens[$this->namespace])) {
            return false;
        }

        if (is_array($tokens[$this->namespace])) {
            $tokens = $tokens[$this->namespace];
        } else {
            $tokens = [$tokens[$this->namespace]];
        }

        foreach ($tokens as $t) {
            if (hash_equals($t->value, $token)) {
                return $this->verifyToken($t);
            }
        }

        return false;
    }

    protected function verifyToken($token)
    {
        if ($token->lifetime > 0) {
            $diff    = (new DateTime)->diff($token->datetime, true);
            $seconds = $diff->days * 86400 + $diff->h * 3600 + $diff->i * 60 + $diff->s;
            if ($seconds > $token->lifetime) {
                return false;
            }
        }

        return true;
    }

    public function base64UrlEncode($data)
    {
        return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
    }

    protected function getTokens()
    {
        if (!isset($this->storage[$this->storageKey])) {
            return [];
        }

        return $this->storage[$this->storageKey];
    }
}

