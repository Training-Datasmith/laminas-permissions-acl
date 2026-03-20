<?php

declare (strict_types=1);
namespace Laminas\Permissions\Acl\Assertion\Exception;

use InvalidArgumentException;
use Laminas\Permissions\Acl\Exception\Exception_Interface;
class Invalid_Assertion_Exception extends InvalidArgumentException implements Exception_Interface
{
}