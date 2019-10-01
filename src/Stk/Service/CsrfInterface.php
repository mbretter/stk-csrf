<?php

namespace Stk\Service;

use Exception;

interface CsrfInterface
{

    /**
     * generate and store a new token
     * 
     * @param null $lifetime null means unlimited lifetime
     * @param bool $single whether to keep a list of tokens or just one
     *
     * @return mixed
     * @throws Exception
     */
    public function newToken($lifetime = null, $single = false): string;

    /**
     * check whether tokens are available
     *
     * @return bool
     */
    public function hasToken(): bool;

    /**
     * @param $token
     *
     * @return mixed
     */
    public function validateToken($token): bool;

}

