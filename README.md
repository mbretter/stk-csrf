# immutable data objects for php

[![License](https://img.shields.io/badge/license-BSD-blue.svg)](https://opensource.org/licenses/BSD-3-Clause)
[![PHP 7.2](https://img.shields.io/badge/php-7.2-yellow.svg)](http://www.php.net)
[![PHP 7.3](https://img.shields.io/badge/php-7.3-yellow.svg)](http://www.php.net)
[![Build Status](https://travis-ci.org/mbretter/stk-immutable.svg?branch=master)](https://travis-ci.org/mbretter/stk-immutable)
[![Coverage](https://coveralls.io/repos/github/mbretter/stk-immutable/badge.svg?branch=master)](https://coveralls.io/github/mbretter/stk-immutable?branch=master)
[![Latest Stable Version](https://img.shields.io/packagist/v/mbretter/stk-immutable.svg)](https://packagist.org/packages/mbretter/stk-immutable)
[![Total Downloads](https://img.shields.io/packagist/dt/mbretter/stk-immutable.svg)](https://packagist.org/packages/mbretter/stk-immutable)

This library implements the immutable design pattern for objects holding some kind of data.

## Maps

Maps can hold objects (stdClass) and/or arrays, they can be nested, very useful when reading/writing from/to 
noSQL databases like MongoDB.

```php
use Stk\Immutable\Map;

$a = new Map((object)['x' => 'foo', 'y' => 'bar']);
$b = $a->set('x', 'whatever');
```

Calling the set method on the object $a does not modify it, a clone with the modifications is returned instead, 
the original Map will never be modified.

Comparing two Maps is easy, there is no need for writing complicated and resource consuming comparision functions, 
simply use the identical operator:

```php
if ($a === $b) {
    ...
}
```
