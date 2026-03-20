<?php

declare (strict_types=1);
namespace Laminas\Permissions\Acl\Assertion;

use function array_flip;
use function array_intersect_key;
use function assert;
use function count;
use function explode;
use function in_array;
use function is_array;
use function is_object;
use function is_string;
use Laminas\Permissions\Acl\Acl;
use Laminas\Permissions\Acl\Assertion\Exception\Invalid_Assertion_Exception;
use Laminas\Permissions\Acl\Exception\RuntimeException;
use Laminas\Permissions\Acl\Resource\Resource_Interface;
use Laminas\Permissions\Acl\Role\Role_Interface;
use function method_exists;
use function preg_match;
use function property_exists;
use ReflectionProperty;
use function sprintf;
use function str_contains;
use function str_replace;
use function strtolower;
use function ucwords;
/**
 * Create an assertion based on expression rules.
 *
 * Each of the constructor, fromProperties, and fromArray methods allow you to
 * define expression rules, and these include the left hand side, operator, and
 * right hand side of the expression.
 *
 * The left and right hand sides of the expression are the values to compare.
 * These values can be either an exact value to match, or an array with the key
 * OPERAND_CONTEXT_PROPERTY pointing to one of two value types.
 *
 * First, it can be a string value matching one of "acl", "privilege", "role",
 * or "resource", with the latter two values being the most common. In those
 * cases, the matching value passed to `assert()` will be used in the
 * comparison.
 *
 * Second, it can be a dot-separated property path string of the format
 * "object.property", representing the associated object (role, resource, acl,
 * or privilege) and its property to test against.  The property may refer to a
 * public property, or a public `get` or `is` method (following
 * canonicalization of the property by replacing underscore separated values
 * with camelCase values).
 */
final class Expression_Assertion implements Assertion_Interface
{
    public const OPERAND_CONTEXT_PROPERTY = '__context';
    public const OPERATOR_EQ = '=';
    public const OPERATOR_NEQ = '!=';
    public const OPERATOR_LT = '<';
    public const OPERATOR_LTE = '<=';
    public const OPERATOR_GT = '>';
    public const OPERATOR_GTE = '>=';
    public const OPERATOR_IN = 'in';
    public const OPERATOR_NIN = '!in';
    public const OPERATOR_REGEX = 'regex';
    public const OPERATOR_NREGEX = '!regex';
    public const OPERATOR_SAME = '===';
    public const OPERATOR_NSAME = '!==';
    /** @var list<string> */
    private static array $valid_operators = [self::OPERATOR_EQ, self::OPERATOR_NEQ, self::OPERATOR_LT, self::OPERATOR_LTE, self::OPERATOR_GT, self::OPERATOR_GTE, self::OPERATOR_IN, self::OPERATOR_NIN, self::OPERATOR_REGEX, self::OPERATOR_NREGEX, self::OPERATOR_SAME, self::OPERATOR_NSAME];
    /**
     * Constructor
     *
     * Note that the constructor is marked private; use `fromProperties()` or
     * `fromArray()` to create an instance.
     *
     * @param mixed|array $left See the class description for valid values.
     * @param string $operator One of the OPERATOR constants (or their values)
     * @param mixed|array $right See the class description for valid values.
     */
    private function __construct(private $left, private $operator, private $right)
    {
    }
    /**
     * @param mixed|array $left See the class description for valid values.
     * @param string $operator One of the OPERATOR constants (or their values)
     * @param mixed|array $right See the class description for valid values.
     * @throws InvalidAssertionException If either operand is invalid.
     * @throws InvalidAssertionException If the operator is not supported.
     */
    public static function from_properties($left, $operator, $right): self
    {
        $operator = strtolower($operator);
        self::validate_operand($left);
        self::validate_operator($operator);
        self::validate_operand($right);
        return new self($left, $operator, $right);
    }
    /**
     * @param array $expression Must contain the following keys:
     *     - left: the left-hand side of the expression
     *     - operator: the operator to use for the comparison
     *     - right: the right-hand side of the expression
     *     See the class description for valid values for the left and right
     *     hand side values.
     * @return self
     * @throws InvalidAssertionException If missing one of the required keys.
     * @throws InvalidAssertionException If either operand is invalid.
     * @throws InvalidAssertionException If the operator is not supported.
     */
    public static function from_array(array $expression)
    {
        $required = ['left', 'operator', 'right'];
        if (count(array_intersect_key($expression, array_flip($required))) < count($required)) {
            throw new Invalid_Assertion_Exception("Expression assertion requires 'left', 'operator' and 'right' to be supplied");
        }
        return self::from_properties($expression['left'], $expression['operator'], $expression['right']);
    }
    /**
     * @param mixed|array $operand
     * @throws InvalidAssertionException If the operand is invalid.
     */
    private static function validate_operand($operand): void
    {
        if (is_array($operand) && isset($operand[self::OPERAND_CONTEXT_PROPERTY])) {
            if (!is_string($operand[self::OPERAND_CONTEXT_PROPERTY])) {
                throw new Invalid_Assertion_Exception('Expression assertion context operand must be string');
            }
        }
    }
    /**
     * @param string $operator
     * @throws InvalidAssertionException If the operator is not supported.
     */
    private static function validate_operator($operator): void
    {
        if (!in_array($operator, self::$valid_operators, true)) {
            throw new Invalid_Assertion_Exception('Provided expression assertion operator is not supported');
        }
    }
    /**
     * {@inheritDoc}
     */
    public function assert(Acl $acl, ?Role_Interface $role = null, ?Resource_Interface $resource = null, $privilege = null)
    {
        return $this->evaluate(['acl' => $acl, 'role' => $role, 'resource' => $resource, 'privilege' => $privilege]);
    }
    /**
     * @param array $context Contains the acl, privilege, role, and resource
     *     being tested currently.
     * @return bool
     */
    private function evaluate(array $context)
    {
        $left = $this->get_left_value($context);
        $right = $this->get_right_value($context);
        return static::evaluate_expression($left, $this->operator, $right);
    }
    /**
     * @param array $context Contains the acl, privilege, role, and resource
     *     being tested currently.
     * @return mixed
     */
    private function get_left_value(array $context)
    {
        return $this->resolve_operand_value($this->left, $context);
    }
    /**
     * @param array $context Contains the acl, privilege, role, and resource
     *     being tested currently.
     * @return mixed
     */
    private function get_right_value(array $context)
    {
        return $this->resolve_operand_value($this->right, $context);
    }
    /**
     * @param mixed|array $operand
     * @param array $context Contains the acl, privilege, role, and resource
     *     being tested currently.
     * @return mixed
     * @throws RuntimeException If object cannot be resolved in context.
     * @throws RuntimeException If property cannot be resolved.
     */
    private function resolve_operand_value($operand, array $context)
    {
        if (!is_array($operand) || !isset($operand[self::OPERAND_CONTEXT_PROPERTY])) {
            return $operand;
        }
        $context_property = $operand[self::OPERAND_CONTEXT_PROPERTY];
        assert(is_string($context_property));
        if (str_contains($context_property, '.')) {
            // property path?
            $parts = explode('.', $context_property, 2);
            assert(count($parts) >= 2);
            [$object_name, $object_field] = $parts;
            return $this->get_object_field_value($context, $object_name, $object_field);
        }
        if (!isset($context[$context_property])) {
            throw new RuntimeException(sprintf("'%s' is not available in the assertion context", $context_property));
        }
        return $context[$context_property];
    }
    /**
     * @param array $context Contains the acl, privilege, role, and resource
     *     being tested currently.
     * @param string $objectName Name of object in context to use.
     * @return mixed
     * @throws RuntimeException If object cannot be resolved in context.
     * @throws RuntimeException If property cannot be resolved.
     */
    private function get_object_field_value(array $context, string $object_name, string $field)
    {
        if (!isset($context[$object_name])) {
            throw new RuntimeException(sprintf("'%s' is not available in the assertion context", $object_name));
        }
        $object = $context[$object_name];
        $accessors = ['get', 'is'];
        $field_accessor = !str_contains($field, '_') ? $field : str_replace(' ', '', ucwords(str_replace('_', ' ', $field)));
        foreach ($accessors as $accessor) {
            $accessor .= $field_accessor;
            if (is_object($object) && method_exists($object, $accessor)) {
                return $object->{$accessor}();
            }
        }
        if (!is_object($object) || !$this->property_exists($object, $field)) {
            throw new RuntimeException(sprintf("'%s' property cannot be resolved on the '%s' object", $field, $object_name));
        }
        return $object->{$field};
    }
    /**
     * @param string $operator
     * @return bool|void
     * @throws RuntimeException If operand is not supported.
     */
    private static function evaluate_expression(mixed $left, $operator, mixed $right)
    {
        // phpcs:disable SlevomatCodingStandard.Operators.DisallowEqualOperators
        switch ($operator) {
            case self::OPERATOR_EQ:
                return $left == $right;
            case self::OPERATOR_NEQ:
                return $left != $right;
            case self::OPERATOR_LT:
                return $left < $right;
            case self::OPERATOR_LTE:
                return $left <= $right;
            case self::OPERATOR_GT:
                return $left > $right;
            case self::OPERATOR_GTE:
                return $left >= $right;
            case self::OPERATOR_IN:
                return in_array($left, $right);
            case self::OPERATOR_NIN:
                return !in_array($left, $right);
            case self::OPERATOR_REGEX:
                return (bool) preg_match($right, (string) $left);
            case self::OPERATOR_NREGEX:
                return !(bool) preg_match($right, (string) $left);
            case self::OPERATOR_SAME:
                return $left === $right;
            case self::OPERATOR_NSAME:
                return $left !== $right;
        }
        // phpcs:enable SlevomatCodingStandard.Operators.DisallowEqualOperators
    }
    /**
     * @param string $property
     * @return bool
     */
    private function property_exists(object $object, $property)
    {
        if (!property_exists($object, $property)) {
            return false;
        }
        $r = new ReflectionProperty($object, $property);
        return $r->is_public();
    }
}