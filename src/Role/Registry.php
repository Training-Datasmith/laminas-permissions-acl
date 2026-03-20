<?php

declare (strict_types=1);
namespace Laminas\Permissions\Acl\Role;

use function is_array;
use Laminas\Permissions\Acl\Exception;
use function sprintf;
use Traversable;
class Registry
{
    /**
     * Internal Role registry data storage
     *
     * @var array<string, RoleInterface>
     */
    protected $roles = [];
    /**
     * Adds a Role having an identifier unique to the registry
     *
     * The $parents parameter may be a reference to, or the string identifier for,
     * a Role existing in the registry, or $parents may be passed as an array of
     * these - mixing string identifiers and objects is ok - to indicate the Roles
     * from which the newly added Role will directly inherit.
     *
     * In order to resolve potential ambiguities with conflicting rules inherited
     * from different parents, the most recently added parent takes precedence over
     * parents that were previously added. In other words, the first parent added
     * will have the least priority, and the last parent added will have the
     * highest priority.
     *
     * @param  RoleInterface|string|array|Traversable $parents
     * @throws Exception\InvalidArgumentException
     * @return $this Provides a fluent interface
     */
    public function add(Role_Interface $role, $parents = null): static
    {
        $role_id = $role->get_role_id();
        if ($this->has($role_id)) {
            throw new Exception\InvalidArgumentException(sprintf('Role id "%s" already exists in the registry', $role_id));
        }
        $role_parents = [];
        if (null !== $parents) {
            if (!is_array($parents) && !$parents instanceof Traversable) {
                $parents = [$parents];
            }
            foreach ($parents as $parent) {
                try {
                    if ($parent instanceof Role_Interface) {
                        $role_parent_id = $parent->get_role_id();
                    } else {
                        $role_parent_id = $parent;
                    }
                    $role_parent = $this->get($role_parent_id);
                } catch (\Exception $e) {
                    throw new Exception\InvalidArgumentException(sprintf('Parent Role id "%s" does not exist', $role_parent_id), 0, $e);
                }
                $role_parents[$role_parent_id] = $role_parent;
                $this->roles[$role_parent_id]['children'][$role_id] = $role;
            }
        }
        $this->roles[$role_id] = ['instance' => $role, 'parents' => $role_parents, 'children' => []];
        return $this;
    }
    /**
     * Returns the identified Role
     *
     * The $role parameter can either be a Role or a Role identifier.
     *
     * @param  RoleInterface|string $role
     * @throws Exception\InvalidArgumentException
     * @return RoleInterface
     */
    public function get($role)
    {
        if ($role instanceof Role_Interface) {
            $role_id = $role->get_role_id();
        } else {
            $role_id = (string) $role;
        }
        if (!$this->has($role)) {
            throw new Exception\InvalidArgumentException("Role '{$role_id}' not found");
        }
        return $this->roles[$role_id]['instance'];
    }
    /**
     * Returns true if and only if the Role exists in the registry
     *
     * The $role parameter can either be a Role or a Role identifier.
     *
     * @param  RoleInterface|string $role
     */
    public function has($role): bool
    {
        if ($role instanceof Role_Interface) {
            $role_id = $role->get_role_id();
        } else {
            $role_id = (string) $role;
        }
        return isset($this->roles[$role_id]);
    }
    /**
     * Returns an array of an existing Role's parents
     *
     * The array keys are the identifiers of the parent Roles, and the values are
     * the parent Role instances. The parent Roles are ordered in this array by
     * ascending priority. The highest priority parent Role, last in the array,
     * corresponds with the parent Role most recently added.
     *
     * If the Role does not have any parents, then an empty array is returned.
     *
     * @param  RoleInterface|string $role
     * @return array
     */
    public function get_parents($role)
    {
        $role_id = $this->get($role)->get_role_id();
        return $this->roles[$role_id]['parents'];
    }
    /**
     * Returns true if and only if $role inherits from $inherit
     *
     * Both parameters may be either a Role or a Role identifier. If
     * $onlyParents is true, then $role must inherit directly from
     * $inherit in order to return true. By default, this method looks
     * through the entire inheritance DAG to determine whether $role
     * inherits from $inherit through its ancestor Roles.
     *
     * @param  RoleInterface|string  $role
     * @param  RoleInterface|string  $inherit
     * @param  bool                    $onlyParents
     * @throws Exception\InvalidArgumentException
     * @return bool
     */
    public function inherits($role, $inherit, $only_parents = false)
    {
        try {
            $role_id = $this->get($role)->get_role_id();
            $inherit_id = $this->get($inherit)->get_role_id();
        } catch (Exception\Exception_Interface $e) {
            throw new Exception\InvalidArgumentException($e->get_message(), $e->get_code(), $e);
        }
        $inherits = isset($this->roles[$role_id]['parents'][$inherit_id]);
        if ($inherits || $only_parents) {
            return $inherits;
        }
        foreach ($this->roles[$role_id]['parents'] as $parent_id => $parent) {
            if ($this->inherits($parent_id, $inherit_id)) {
                return true;
            }
        }
        return false;
    }
    /**
     * Removes the Role from the registry
     *
     * The $role parameter can either be a Role or a Role identifier.
     *
     * @param  RoleInterface|string $role
     * @throws Exception\InvalidArgumentException
     * @return Registry Provides a fluent interface
     */
    public function remove($role): static
    {
        try {
            $role_id = $this->get($role)->get_role_id();
        } catch (Exception\Exception_Interface $e) {
            throw new Exception\InvalidArgumentException($e->get_message(), $e->get_code(), $e);
        }
        foreach ($this->roles[$role_id]['children'] as $child_id => $child) {
            unset($this->roles[$child_id]['parents'][$role_id]);
        }
        foreach ($this->roles[$role_id]['parents'] as $parent_id => $parent) {
            unset($this->roles[$parent_id]['children'][$role_id]);
        }
        unset($this->roles[$role_id]);
        return $this;
    }
    /**
     * Removes all Roles from the registry
     *
     * @return Registry Provides a fluent interface
     */
    public function remove_all(): static
    {
        $this->roles = [];
        return $this;
    }
    /**
     * Get all roles in the registry
     *
     * @return array
     */
    public function get_roles()
    {
        return $this->roles;
    }
}