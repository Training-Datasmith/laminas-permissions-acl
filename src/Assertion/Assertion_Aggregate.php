<?php

declare (strict_types=1);
namespace Laminas\Permissions\Acl\Assertion;

use function class_exists;
use Exception;
use Laminas\Permissions\Acl\Acl;
use Laminas\Permissions\Acl\Assertion\Exception\Invalid_Assertion_Exception;
use Laminas\Permissions\Acl\Exception\InvalidArgumentException;
use Laminas\Permissions\Acl\Exception\RuntimeException;
use Laminas\Permissions\Acl\Resource\Resource_Interface;
use Laminas\Permissions\Acl\Role\Role_Interface;
class Assertion_Aggregate implements Assertion_Interface
{
    public const MODE_ALL = 'all';
    public const MODE_AT_LEAST_ONE = 'at_least_one';
    /** @var list<AssertionInterface|string> */
    protected $assertions = [];
    /** @var AssertionManager|null */
    protected $assertion_manager;
    /** @var string */
    protected $mode = self::MODE_ALL;
    /**
     * Stacks an assertion in aggregate
     *
     * @param AssertionInterface|string $assertion
     *    if string, must match a AssertionManager declared service (checked later)
     */
    public function add_assertion($assertion): static
    {
        $this->assertions[] = $assertion;
        return $this;
    }
    /**
     * @param array<array-key, AssertionInterface|string> $assertions
     * @return $this
     */
    public function add_assertions(array $assertions): static
    {
        foreach ($assertions as $assertion) {
            $this->add_assertion($assertion);
        }
        return $this;
    }
    /**
     * Empties assertions stack
     */
    public function clear_assertions(): static
    {
        $this->assertions = [];
        return $this;
    }
    /**
     * Set the AssertionManager used to resolve string-referenced assertions at runtime.
     *
     * @param  Assertion_Manager $manager The assertion manager instance.
     * @return static                     Fluent interface.
     */
    public function set_assertion_manager(Assertion_Manager $manager): static
    {
        $this->assertion_manager = $manager;
        return $this;
    }

    /**
     * Return the currently configured AssertionManager, or null if none is set.
     *
     * @return Assertion_Manager|null
     */
    public function get_assertion_manager(): ?Assertion_Manager
    {
        return $this->assertion_manager;
    }
    /**
     * Set assertion chain behavior
     *
     * AssertionAggregate should assert to true when:
     *
     * - all assertions are true with MODE_ALL
     * - at least one assertion is true with MODE_AT_LEAST_ONE
     *
     * @param string $mode
     *    indicates how assertion chain result should interpreted (either 'all' or 'at_least_one')
     * @throws InvalidArgumentException
     */
    public function set_mode($mode): static
    {
        if ($mode !== self::MODE_ALL && $mode !== self::MODE_AT_LEAST_ONE) {
            throw new InvalidArgumentException('invalid assertion aggregate mode');
        }
        $this->mode = $mode;
        return $this;
    }
    /**
     * Return the current assertion chain evaluation mode.
     *
     * @return string One of MODE_ALL ('all') or MODE_AT_LEAST_ONE ('at_least_one').
     */
    public function get_mode(): string
    {
        return $this->mode;
    }
    /**
     * @see \Laminas\Permissions\Acl\Assertion\AssertionInterface::assert()
     *
     * @param string|null $privilege
     * @throws RuntimeException
     */
    public function assert(Acl $acl, ?Role_Interface $role = null, ?Resource_Interface $resource = null, $privilege = null): bool
    {
        // check if assertions are set
        if (!$this->assertions) {
            throw new RuntimeException('no assertion have been aggregated to this AssertionAggregate');
        }
        foreach ($this->assertions as $assertion) {
            // jit assertion mloading
            if (!$assertion instanceof Assertion_Interface) {
                if (class_exists($assertion)) {
                    $assertion = new $assertion();
                } else if ($manager = $this->get_assertion_manager()) {
                    try {
                        $assertion = $manager->get($assertion);
                    } catch (Exception) {
                        throw new Invalid_Assertion_Exception('assertion "' . $assertion . '" is not defined in assertion manager');
                    }
                } else {
                    throw new RuntimeException('no assertion manager is set - cannot look up for assertions');
                }
            }
            $result = (bool) $assertion->assert($acl, $role, $resource, $privilege);
            if ($this->get_mode() === self::MODE_ALL && !$result) {
                // on false is enough
                return false;
            }
            if ($this->get_mode() === self::MODE_AT_LEAST_ONE && $result) {
                // one true is enough
                return true;
            }
        }
        if ($this->get_mode() === self::MODE_ALL) {
            // none of the assertions returned false
            return true;
        }
        return false;
    }
}