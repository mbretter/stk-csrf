<?php

namespace Stk\Service;

use Exception;

interface CsrfInterface
{

    /**
     * generate and store a new token
     *
     * @param int|null $lifetime null means unlimited lifetime
     * @param bool $single whether to keep a list of tokens or just one
     *
     * @return string
     * @throws Exception
     */
    public function newToken(int $lifetime = null, $single = false): string;

    /**
     * check whether tokens are available
     *
     * @return bool
     */
    public function hasToken(): bool;

    /**
     * @param string $token
     *
     * @return bool
     */
    public function validateToken(string $token): bool;
}
