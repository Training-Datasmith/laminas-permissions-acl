<?php

declare (strict_types=1);
namespace Laminas\Permissions\Acl\Assertion;

use Laminas\Permissions\Acl\Exception\InvalidArgumentException;
use Laminas\Service_Manager\Abstract_Plugin_Manager;
use Laminas\Service_Manager\Exception\Invalid_Service_Exception;
use function sprintf;
/** @extends AbstractPluginManager<AssertionInterface> */
class Assertion_Manager extends Abstract_Plugin_Manager
{
    /** @var class-string<AssertionInterface> */
    protected $instance_of = Assertion_Interface::class;
    /**
     * Validate the plugin is of the expected type (v3).
     *
     * Validates against `$instanceOf`.
     *
     * @param mixed $instance
     * @throws InvalidServiceException
     * @psalm-assert AssertionInterface $instance
     */
    public function validate($instance): void
    {
        if (!$instance instanceof $this->instance_of) {
            throw new Invalid_Service_Exception(sprintf('%s can only create instances of %s; %s is invalid', self::class, $this->instance_of, get_debug_type($instance)));
        }
    }
    /**
     * Validate the plugin is of the expected type (v2).
     *
     * Proxies to `validate()`.
     *
     * @deprecated Please use {@see AssertionManager::validate()} instead.
     *
     * @throws InvalidArgumentException
     * @psalm-assert AssertionInterface $instance
     */
    public function validate_plugin(mixed $instance): void
    {
        try {
            $this->validate($instance);
        } catch (Invalid_Service_Exception $e) {
            throw new InvalidArgumentException($e->get_message(), $e->get_code(), $e);
        }
    }
}