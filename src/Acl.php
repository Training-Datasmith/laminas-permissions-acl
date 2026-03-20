<?php

declare (strict_types=1);
namespace Laminas\Permissions\Acl;

use function array_key_exists;
use function array_keys;
use function array_pop;
use function is_array;
use function is_string;
use Laminas\Permissions\Acl\Assertion\Assertion_Interface;
use Laminas\Permissions\Acl\Exception\Exception_Interface;
use Laminas\Permissions\Acl\Exception\InvalidArgumentException;
use Laminas\Permissions\Acl\Exception\RuntimeException;
use Laminas\Permissions\Acl\Resource\Resource_Interface;
use function sprintf;
use function strtoupper;
use Throwable;
class Acl implements Acl_Interface
{
    /**
     * Rule type: allow
     */
    public const TYPE_ALLOW = 'TYPE_ALLOW';
    /**
     * Rule type: deny
     */
    public const TYPE_DENY = 'TYPE_DENY';
    /**
     * Rule operation: add
     */
    public const OP_ADD = 'OP_ADD';
    /**
     * Rule operation: remove
     */
    public const OP_REMOVE = 'OP_REMOVE';
    /**
     * Role registry
     *
     * @var Role\Registry|null
     */
    protected $role_registry;
    /**
     * Resource tree
     *
     * @var array
     */
    protected $resources = [];
    /**
     * Resources by resourceId plus a null element
     * Used to speed up setRule()
     *
     * @var array<int|string, ResourceInterface|null>
     */
    private array $resources_by_id = [null];
    /** @var Role\RoleInterface|null */
    protected $is_allowed_role;
    /** @var ResourceInterface|null */
    protected $is_allowed_resource;
    /** @var string|null */
    protected $is_allowed_privilege;
    /**
     * ACL rules; whitelist (deny everything to all) by default
     *
     * @var array
     */
    protected $rules = ['allResources' => ['allRoles' => ['allPrivileges' => ['type' => self::TYPE_DENY, 'assert' => null], 'byPrivilegeId' => []], 'byRoleId' => []], 'byResourceId' => []];
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
     * @param  Role\RoleInterface|string       $role
     * @param  Role\RoleInterface|string|array $parents
     * @throws InvalidArgumentException
     * @return Acl Provides a fluent interface
     */
    public function add_role($role, $parents = null): static
    {
        if (is_string($role)) {
            $role = new Role\Generic_Role($role);
        } elseif (!$role instanceof Role\Role_Interface) {
            throw new InvalidArgumentException('addRole() expects $role to be of type Laminas\Permissions\Acl\Role\RoleInterface');
        }
        $this->get_role_registry()->add($role, $parents);
        return $this;
    }
    /**
     * Returns the identified Role
     *
     * The $role parameter can either be a Role or Role identifier.
     *
     * @param  Role\RoleInterface|string $role
     * @return Role\RoleInterface
     */
    public function get_role($role)
    {
        return $this->get_role_registry()->get($role);
    }
    /**
     * Returns true if and only if the Role exists in the registry
     *
     * The $role parameter can either be a Role or a Role identifier.
     *
     * @param  Role\RoleInterface|string $role
     * @return bool
     */
    public function has_role($role)
    {
        return $this->get_role_registry()->has($role);
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
     * @param  Role\RoleInterface|string    $role
     * @param  Role\RoleInterface|string    $inherit
     * @param  bool                      $onlyParents
     * @return bool
     */
    public function inherits_role($role, $inherit, $only_parents = false)
    {
        return $this->get_role_registry()->inherits($role, $inherit, $only_parents);
    }
    /**
     * Removes the Role from the registry
     *
     * The $role parameter can either be a Role or a Role identifier.
     *
     * @param  Role\RoleInterface|string $role
     * @return Acl Provides a fluent interface
     */
    public function remove_role($role): static
    {
        $this->get_role_registry()->remove($role);
        if ($role instanceof Role\Role_Interface) {
            $role_id = $role->get_role_id();
        } else {
            $role_id = $role;
        }
        foreach ($this->rules['allResources']['byRoleId'] as $role_id_current => $rules) {
            if ($role_id === $role_id_current) {
                unset($this->rules['allResources']['byRoleId'][$role_id_current]);
            }
        }
        foreach ($this->rules['byResourceId'] as $resource_id_current => $visitor) {
            if (array_key_exists('byRoleId', $visitor)) {
                foreach ($visitor['byRoleId'] as $role_id_current => $rules) {
                    if ($role_id === $role_id_current) {
                        unset($this->rules['byResourceId'][$resource_id_current]['byRoleId'][$role_id_current]);
                    }
                }
            }
        }
        return $this;
    }
    /**
     * Removes all Roles from the registry
     *
     * @return Acl Provides a fluent interface
     */
    public function remove_role_all(): static
    {
        $this->get_role_registry()->remove_all();
        foreach ($this->rules['allResources']['byRoleId'] as $role_id_current => $rules) {
            unset($this->rules['allResources']['byRoleId'][$role_id_current]);
        }
        foreach ($this->rules['byResourceId'] as $resource_id_current => $visitor) {
            foreach ($visitor['byRoleId'] as $role_id_current => $rules) {
                unset($this->rules['byResourceId'][$resource_id_current]['byRoleId'][$role_id_current]);
            }
        }
        return $this;
    }
    /**
     * Adds a Resource having an identifier unique to the ACL
     *
     * The $parent parameter may be a reference to, or the string identifier for,
     * the existing Resource from which the newly added Resource will inherit.
     *
     * @param  ResourceInterface|string $resource
     * @param  ResourceInterface|string $parent
     * @throws InvalidArgumentException
     * @return Acl Provides a fluent interface
     */
    public function add_resource($resource, $parent = null): static
    {
        if (is_string($resource)) {
            $resource = new Resource\Generic_Resource($resource);
        } elseif (!$resource instanceof Resource_Interface) {
            throw new InvalidArgumentException('addResource() expects $resource to be of type Laminas\Permissions\Acl\Resource\ResourceInterface');
        }
        $resource_id = $resource->get_resource_id();
        if ($this->has_resource($resource_id)) {
            throw new InvalidArgumentException("Resource id '{$resource_id}' already exists in the ACL");
        }
        $resource_parent = null;
        if (null !== $parent) {
            try {
                if ($parent instanceof Resource_Interface) {
                    $resource_parent_id = $parent->get_resource_id();
                } else {
                    $resource_parent_id = $parent;
                }
                $resource_parent = $this->get_resource($resource_parent_id);
            } catch (Throwable $e) {
                throw new InvalidArgumentException(sprintf('Parent Resource id "%s" does not exist', $resource_parent_id), 0, $e);
            }
            $this->resources[$resource_parent_id]['children'][$resource_id] = $resource;
        }
        $this->resources[$resource_id] = ['instance' => $resource, 'parent' => $resource_parent, 'children' => []];
        $this->resources_by_id[$resource_id] = $resource;
        return $this;
    }
    /**
     * Returns the identified Resource
     *
     * The $resource parameter can either be a Resource or a Resource identifier.
     *
     * @param  ResourceInterface|string $resource
     * @throws InvalidArgumentException
     * @return ResourceInterface
     */
    public function get_resource($resource)
    {
        if ($resource instanceof Resource_Interface) {
            $resource_id = $resource->get_resource_id();
        } else {
            $resource_id = (string) $resource;
        }
        if (!$this->has_resource($resource)) {
            throw new InvalidArgumentException("Resource '{$resource_id}' not found");
        }
        return $this->resources[$resource_id]['instance'];
    }
    /**
     * Returns true if and only if the Resource exists in the ACL
     *
     * The $resource parameter can either be a Resource or a Resource identifier.
     *
     * @param  ResourceInterface|string $resource
     */
    public function has_resource($resource): bool
    {
        if ($resource instanceof Resource_Interface) {
            $resource_id = $resource->get_resource_id();
        } else {
            $resource_id = (string) $resource;
        }
        return isset($this->resources[$resource_id]);
    }
    /**
     * Returns true if and only if $resource inherits from $inherit
     *
     * Both parameters may be either a Resource or a Resource identifier. If
     * $onlyParent is true, then $resource must inherit directly from
     * $inherit in order to return true. By default, this method looks
     * through the entire inheritance tree to determine whether $resource
     * inherits from $inherit through its ancestor Resources.
     *
     * @param  ResourceInterface|string $resource
     * @param  ResourceInterface|string $inherit
     * @param  bool                              $onlyParent
     * @throws InvalidArgumentException
     */
    public function inherits_resource($resource, $inherit, $only_parent = false): bool
    {
        try {
            $resource_id = $this->get_resource($resource)->get_resource_id();
            $inherit_id = $this->get_resource($inherit)->get_resource_id();
        } catch (Exception_Interface $e) {
            throw new InvalidArgumentException($e->get_message(), $e->get_code(), $e);
        }
        if (null !== $this->resources[$resource_id]['parent']) {
            $parent_id = $this->resources[$resource_id]['parent']->get_resource_id();
            if ($inherit_id === $parent_id) {
                return true;
            }
            if ($only_parent) {
                return false;
            }
        } else {
            return false;
        }
        while (null !== $this->resources[$parent_id]['parent']) {
            $parent_id = $this->resources[$parent_id]['parent']->get_resource_id();
            if ($inherit_id === $parent_id) {
                return true;
            }
        }
        return false;
    }
    /**
     * Removes a Resource and all of its children
     *
     * The $resource parameter can either be a Resource or a Resource identifier.
     *
     * @param  ResourceInterface|string $resource
     * @throws InvalidArgumentException
     * @return Acl Provides a fluent interface
     */
    public function remove_resource($resource): static
    {
        try {
            $resource_id = $this->get_resource($resource)->get_resource_id();
        } catch (Exception_Interface $e) {
            throw new InvalidArgumentException($e->get_message(), $e->get_code(), $e);
        }
        $resources_removed = [$resource_id];
        if (null !== $resource_parent = $this->resources[$resource_id]['parent']) {
            unset($this->resources[$resource_parent->get_resource_id()]['children'][$resource_id]);
        }
        foreach ($this->resources[$resource_id]['children'] as $child_id => $child) {
            $this->remove_resource($child_id);
            $resources_removed[] = $child_id;
        }
        foreach ($resources_removed as $resource_id_removed) {
            foreach ($this->rules['byResourceId'] as $resource_id_current => $rules) {
                if ($resource_id_removed === $resource_id_current) {
                    unset($this->rules['byResourceId'][$resource_id_current]);
                }
            }
        }
        unset($this->resources[$resource_id]);
        return $this;
    }
    /**
     * Removes all Resources
     *
     * @return Acl Provides a fluent interface
     */
    public function remove_resource_all(): static
    {
        foreach ($this->resources as $resource_id => $resource) {
            unset($this->rules['byResourceId'][$resource_id]);
        }
        $this->resources = [];
        $this->resources_by_id = [null];
        return $this;
    }
    /**
     * Adds an "allow" rule to the ACL
     *
     * @param  Role\RoleInterface|string|array|null         $roles
     * @param  ResourceInterface|string|array|null $resources
     * @param  string|array|null                            $privileges
     * @return Acl Provides a fluent interface
     */
    public function allow($roles = null, $resources = null, $privileges = null, ?Assertion_Interface $assert = null)
    {
        return $this->set_rule(self::OP_ADD, self::TYPE_ALLOW, $roles, $resources, $privileges, $assert);
    }
    /**
     * Adds a "deny" rule to the ACL
     *
     * @param  Role\RoleInterface|string|array|null         $roles
     * @param  ResourceInterface|string|array|null $resources
     * @param  string|array|null                            $privileges
     * @return Acl Provides a fluent interface
     */
    public function deny($roles = null, $resources = null, $privileges = null, ?Assertion_Interface $assert = null)
    {
        return $this->set_rule(self::OP_ADD, self::TYPE_DENY, $roles, $resources, $privileges, $assert);
    }
    /**
     * Removes "allow" permissions from the ACL
     *
     * @param  Role\RoleInterface|string|array|null         $roles
     * @param  ResourceInterface|string|array|null $resources
     * @param  string|array|null                            $privileges
     * @return Acl Provides a fluent interface
     */
    public function remove_allow($roles = null, $resources = null, $privileges = null)
    {
        return $this->set_rule(self::OP_REMOVE, self::TYPE_ALLOW, $roles, $resources, $privileges);
    }
    /**
     * Removes "deny" restrictions from the ACL
     *
     * @param  Role\RoleInterface|string|array|null         $roles
     * @param  ResourceInterface|string|array|null $resources
     * @param  string|array|null                            $privileges
     * @return Acl Provides a fluent interface
     */
    public function remove_deny($roles = null, $resources = null, $privileges = null)
    {
        return $this->set_rule(self::OP_REMOVE, self::TYPE_DENY, $roles, $resources, $privileges);
    }
    /**
     * Performs operations on ACL rules
     *
     * The $operation parameter may be either OP_ADD or OP_REMOVE, depending on whether the
     * user wants to add or remove a rule, respectively:
     *
     * OP_ADD specifics:
     *
     *      A rule is added that would allow one or more Roles access to [certain $privileges
     *      upon] the specified Resource(s).
     *
     * OP_REMOVE specifics:
     *
     *      The rule is removed only in the context of the given Roles, Resources, and privileges.
     *      Existing rules to which the remove operation does not apply would remain in the
     *      ACL.
     *
     * The $type parameter may be either TYPE_ALLOW or TYPE_DENY, depending on whether the
     * rule is intended to allow or deny permission, respectively.
     *
     * The $roles and $resources parameters may be references to, or the string identifiers for,
     * existing Resources/Roles, or they may be passed as arrays of these - mixing string identifiers
     * and objects is ok - to indicate the Resources and Roles to which the rule applies. If either
     * $roles or $resources is null, then the rule applies to all Roles or all Resources, respectively.
     * Both may be null in order to work with the default rule of the ACL.
     *
     * The $privileges parameter may be used to further specify that the rule applies only
     * to certain privileges upon the Resource(s) in question. This may be specified to be a single
     * privilege with a string, and multiple privileges may be specified as an array of strings.
     *
     * If $assert is provided, then its assert() method must return true in order for
     * the rule to apply. If $assert is provided with $roles, $resources, and $privileges all
     * equal to null, then a rule having a type of:
     *
     *      TYPE_ALLOW will imply a type of TYPE_DENY, and
     *
     *      TYPE_DENY will imply a type of TYPE_ALLOW
     *
     * when the rule's assertion fails. This is because the ACL needs to provide expected
     * behavior when an assertion upon the default ACL rule fails.
     *
     * @param  string                                        $operation
     * @param  string                                        $type
     * @param  Role\RoleInterface|string|array|null          $roles
     * @param  ResourceInterface|string|array|null  $resources
     * @param  string|array|null                             $privileges
     * @throws InvalidArgumentException
     * @return Acl Provides a fluent interface
     */
    public function set_rule($operation, $type, $roles = null, $resources = null, $privileges = null, ?Assertion_Interface $assert = null): static
    {
        // ensure that the rule type is valid; normalize input to uppercase
        $type = strtoupper($type);
        if (self::TYPE_ALLOW !== $type && self::TYPE_DENY !== $type) {
            throw new InvalidArgumentException(sprintf('Unsupported rule type; must be either "%s" or "%s"', self::TYPE_ALLOW, self::TYPE_DENY));
        }
        // ensure that all specified Roles exist; normalize input to array of Role objects or null
        if (!is_array($roles)) {
            $roles = [$roles];
        } elseif (!$roles) {
            $roles = [null];
        }
        $roles_temp = $roles;
        $roles = [];
        foreach ($roles_temp as $role) {
            if (null !== $role) {
                $roles[] = $this->get_role_registry()->get($role);
            } else {
                $roles[] = null;
            }
        }
        unset($roles_temp);
        /** var array<int|string, ResourceInterface|null> */
        $resources_to_apply_rules = [];
        if (null === $resources && $this->resources) {
            $resources_to_apply_rules = $this->resources_by_id;
        } else {
            // ensure that all specified Resources exist; normalize input to array of Resource objects or null
            if (!is_array($resources)) {
                $resources = [$resources];
            } elseif (!$resources) {
                $resources = [null];
            }
            foreach ($resources as $resource) {
                if (null !== $resource) {
                    $resource_obj = $this->get_resource($resource);
                    $resource_id = $resource_obj->get_resource_id();
                    $this->get_child_resources_into_reference($resource_obj, $resources_to_apply_rules);
                    $resources_to_apply_rules[$resource_id] = $resource_obj;
                } else {
                    $resources_to_apply_rules[] = null;
                }
            }
            unset($resources);
        }
        // normalize privileges to array
        if (null === $privileges) {
            $privileges = [];
        } elseif (!is_array($privileges)) {
            $privileges = [$privileges];
        }
        switch ($operation) {
            // add to the rules
            case self::OP_ADD:
                foreach ($resources_to_apply_rules as $resource) {
                    foreach ($roles as $role) {
                        $rules =& $this->get_rules($resource, $role, true);
                        if (!$privileges) {
                            $rules['allPrivileges']['type'] = $type;
                            $rules['allPrivileges']['assert'] = $assert;
                            if (!isset($rules['byPrivilegeId'])) {
                                $rules['byPrivilegeId'] = [];
                            }
                        } else {
                            foreach ($privileges as $privilege) {
                                $rules['byPrivilegeId'][$privilege]['type'] = $type;
                                $rules['byPrivilegeId'][$privilege]['assert'] = $assert;
                            }
                        }
                    }
                }
                break;
            // remove from the rules
            case self::OP_REMOVE:
                foreach ($resources_to_apply_rules as $resource) {
                    foreach ($roles as $role) {
                        $rules =& $this->get_rules($resource, $role);
                        if (null === $rules) {
                            continue;
                        }
                        if (!$privileges) {
                            if (null === $resource && null === $role) {
                                if ($type === $rules['allPrivileges']['type']) {
                                    $rules = ['allPrivileges' => ['type' => self::TYPE_DENY, 'assert' => null], 'byPrivilegeId' => []];
                                }
                                continue;
                            }
                            if (isset($rules['allPrivileges']['type']) && $type === $rules['allPrivileges']['type']) {
                                unset($rules['allPrivileges']);
                            }
                        } else {
                            foreach ($privileges as $privilege) {
                                if (isset($rules['byPrivilegeId'][$privilege]) && $type === $rules['byPrivilegeId'][$privilege]['type']) {
                                    unset($rules['byPrivilegeId'][$privilege]);
                                }
                            }
                        }
                    }
                }
                break;
            default:
                throw new InvalidArgumentException(sprintf('Unsupported operation; must be either "%s" or "%s"', self::OP_ADD, self::OP_REMOVE));
        }
        return $this;
    }
    /**
     * Returns all child resources from the given resource.
     *
     * @param array<int|string, ResourceInterface|null> $return
     * @return array<int|string, ResourceInterface|null>
     */
    private function get_child_resources_into_reference(Resource_Interface $resource, array &$return = []): array
    {
        $id = $resource->get_resource_id();
        $children = $this->resources[$id]['children'];
        foreach ($children as $child) {
            $this->get_child_resources_into_reference($child, $return);
            $return[$child->get_resource_id()] = $child;
        }
        return $return;
    }
    /**
     * Returns all child resources from the given resource.
     *
     * @deprecated
     *
     * @see getChildResourcesIntoReference()
     *
     * @return array<int|string, ResourceInterface|null>
     */
    protected function get_child_resources(Resource_Interface $resource)
    {
        return $this->get_child_resources_into_reference($resource);
    }
    /**
     * Returns true if and only if the Role has access to the Resource
     *
     * The $role and $resource parameters may be references to, or the string identifiers for,
     * an existing Resource and Role combination.
     *
     * If either $role or $resource is null, then the query applies to all Roles or all Resources,
     * respectively. Both may be null to query whether the ACL has a "blacklist" rule
     * (allow everything to all). By default, Laminas\Permissions\Acl creates a "whitelist" rule (deny
     * everything to all), and this method would return false unless this default has
     * been overridden (i.e., by executing $acl->allow()).
     *
     * If a $privilege is not provided, then this method returns false if and only if the
     * Role is denied access to at least one privilege upon the Resource. In other words, this
     * method returns true if and only if the Role is allowed all privileges on the Resource.
     *
     * This method checks Role inheritance using a depth-first traversal of the Role registry.
     * The highest priority parent (i.e., the parent most recently added) is checked first,
     * and its respective parents are checked similarly before the lower-priority parents of
     * the Role are checked.
     *
     * @param  Role\RoleInterface|string            $role
     * @param  ResourceInterface|string    $resource
     * @param  string                               $privilege
     * @return bool
     */
    public function is_allowed($role = null, $resource = null, $privilege = null)
    {
        // reset role & resource to null
        $this->is_allowed_role = null;
        $this->is_allowed_resource = null;
        $this->is_allowed_privilege = null;
        if (null !== $role) {
            // keep track of originally called role
            $this->is_allowed_role = $role;
            $role = $this->get_role_registry()->get($role);
            if (!$this->is_allowed_role instanceof Role\Role_Interface) {
                $this->is_allowed_role = $role;
            }
        }
        if (null !== $resource) {
            // keep track of originally called resource
            $this->is_allowed_resource = $resource;
            $resource = $this->get_resource($resource);
            if (!$this->is_allowed_resource instanceof Resource_Interface) {
                $this->is_allowed_resource = $resource;
            }
        }
        if (null === $privilege) {
            // query on all privileges
            do {
                // depth-first search on $role if it is not 'allRoles' pseudo-parent
                if (null !== $role && null !== $result = $this->role_dfs_all_privileges($role, $resource)) {
                    return $result;
                }
                // look for rule on 'allRoles' pseudo-parent
                if (null !== $rules = $this->get_rules($resource)) {
                    foreach ($rules['byPrivilegeId'] as $privilege => $rule) {
                        if (self::TYPE_DENY === $this->get_rule_type($resource, null, $privilege)) {
                            return false;
                        }
                    }
                    $rule_type_all_privileges = $this->get_rule_type($resource);
                    if (null !== $rule_type_all_privileges) {
                        return self::TYPE_ALLOW === $rule_type_all_privileges;
                    }
                }
                // try next Resource
                $resource = $this->resources[$resource->get_resource_id()]['parent'];
            } while (true);
            // loop terminates at 'allResources' pseudo-parent
        } else {
            $this->is_allowed_privilege = $privilege;
            // query on one privilege
            do {
                // depth-first search on $role if it is not 'allRoles' pseudo-parent
                if (null !== $role && null !== $result = $this->role_dfs_one_privilege($role, $resource, $privilege)) {
                    return $result;
                }
                // look for rule on 'allRoles' pseudo-parent
                if (null !== $rule_type = $this->get_rule_type($resource, null, $privilege)) {
                    return self::TYPE_ALLOW === $rule_type;
                }
                // look for rule on 'allRoles' pseudo-parent
                if (null !== $rule_type_all_privileges = $this->get_rule_type($resource)) {
                    $result = self::TYPE_ALLOW === $rule_type_all_privileges;
                    if ($result || null === $resource) {
                        return $result;
                    }
                }
                // try next Resource
                $resource = $this->resources[$resource->get_resource_id()]['parent'];
            } while (true);
            // loop terminates at 'allResources' pseudo-parent
        }
    }
    /**
     * Returns the Role registry for this ACL
     *
     * If no Role registry has been created yet, a new default Role registry
     * is created and returned.
     *
     * @return Role\Registry
     */
    protected function get_role_registry()
    {
        if (null === $this->role_registry) {
            $this->role_registry = new Role\Registry();
        }
        return $this->role_registry;
    }
    /**
     * Performs a depth-first search of the Role DAG, starting at $role, in order to find a rule
     * allowing/denying $role access to all privileges upon $resource
     *
     * This method returns true if a rule is found and allows access. If a rule exists and denies access,
     * then this method returns false. If no applicable rule is found, then this method returns null.
     *
     * @return bool|null
     */
    protected function role_dfs_all_privileges(Role\Role_Interface $role, ?Resource_Interface $resource = null)
    {
        $dfs = ['visited' => [], 'stack' => []];
        if (null !== $result = $this->role_dfs_visit_all_privileges($role, $resource, $dfs)) {
            return $result;
        }
        // This comment is needed due to a strange php-cs-fixer bug
        while (null !== $role = array_pop($dfs['stack'])) {
            if (!isset($dfs['visited'][$role->get_role_id()])) {
                if (null !== $result = $this->role_dfs_visit_all_privileges($role, $resource, $dfs)) {
                    return $result;
                }
            }
        }
    }
    /**
     * Visits an $role in order to look for a rule allowing/denying $role access to all privileges upon $resource
     *
     * This method returns true if a rule is found and allows access. If a rule exists and denies access,
     * then this method returns false. If no applicable rule is found, then this method returns null.
     *
     * This method is used by the internal depth-first search algorithm and may modify the DFS data structure.
     *
     * @param  array &$dfs
     * @return bool|void
     * @throws RuntimeException
     */
    protected function role_dfs_visit_all_privileges(Role\Role_Interface $role, ?Resource_Interface $resource = null, &$dfs = null)
    {
        if (null === $dfs) {
            throw new RuntimeException('$dfs parameter may not be null');
        }
        if (null !== $rules = $this->get_rules($resource, $role)) {
            foreach ($rules['byPrivilegeId'] as $privilege => $rule) {
                if (self::TYPE_DENY === $rule_type_one_privilege = $this->get_rule_type($resource, $role, $privilege)) {
                    return false;
                }
            }
            if (null !== $rule_type_all_privileges = $this->get_rule_type($resource, $role)) {
                return self::TYPE_ALLOW === $rule_type_all_privileges;
            }
        }
        $dfs['visited'][$role->get_role_id()] = true;
        foreach ($this->get_role_registry()->get_parents($role) as $role_parent) {
            $dfs['stack'][] = $role_parent;
        }
    }
    /**
     * Performs a depth-first search of the Role DAG, starting at $role, in order to find a rule
     * allowing/denying $role access to a $privilege upon $resource
     *
     * This method returns true if a rule is found and allows access. If a rule exists and denies access,
     * then this method returns false. If no applicable rule is found, then this method returns null.
     *
     * @param  string|null                     $privilege
     * @return bool|void
     * @throws RuntimeException
     */
    protected function role_dfs_one_privilege(Role\Role_Interface $role, ?Resource_Interface $resource = null, $privilege = null)
    {
        if (null === $privilege) {
            throw new RuntimeException('$privilege parameter may not be null');
        }
        $dfs = ['visited' => [], 'stack' => []];
        if (null !== $result = $this->role_dfs_visit_one_privilege($role, $resource, $privilege, $dfs)) {
            return $result;
        }
        // This comment is needed due to a strange php-cs-fixer bug
        while (null !== $role = array_pop($dfs['stack'])) {
            if (!isset($dfs['visited'][$role->get_role_id()])) {
                if (null !== $result = $this->role_dfs_visit_one_privilege($role, $resource, $privilege, $dfs)) {
                    return $result;
                }
            }
        }
    }
    /**
     * Visits an $role in order to look for a rule allowing/denying $role access to a $privilege upon $resource
     *
     * This method returns true if a rule is found and allows access. If a rule exists and denies access,
     * then this method returns false. If no applicable rule is found, then this method returns null.
     *
     * This method is used by the internal depth-first search algorithm and may modify the DFS data structure.
     *
     * @param  string|null                     $privilege
     * @param  array                           $dfs
     * @return bool|void
     * @throws RuntimeException
     */
    protected function role_dfs_visit_one_privilege(Role\Role_Interface $role, ?Resource_Interface $resource = null, $privilege = null, &$dfs = null)
    {
        if (null === $privilege) {
            throw new RuntimeException('$privilege parameter may not be null');
        }
        if (null === $dfs) {
            throw new RuntimeException('$dfs parameter may not be null');
        }
        if (null !== $rule_type_one_privilege = $this->get_rule_type($resource, $role, $privilege)) {
            return self::TYPE_ALLOW === $rule_type_one_privilege;
        }
        if (null !== $rule_type_all_privileges = $this->get_rule_type($resource, $role)) {
            return self::TYPE_ALLOW === $rule_type_all_privileges;
        }
        $dfs['visited'][$role->get_role_id()] = true;
        foreach ($this->get_role_registry()->get_parents($role) as $role_parent) {
            $dfs['stack'][] = $role_parent;
        }
    }
    /**
     * Returns the rule type associated with the specified Resource, Role, and privilege
     * combination.
     *
     * If a rule does not exist or its attached assertion fails, which means that
     * the rule is not applicable, then this method returns null. Otherwise, the
     * rule type applies and is returned as either TYPE_ALLOW or TYPE_DENY.
     *
     * If $resource or $role is null, then this means that the rule must apply to
     * all Resources or Roles, respectively.
     *
     * If $privilege is null, then the rule must apply to all privileges.
     *
     * If all three parameters are null, then the default ACL rule type is returned,
     * based on whether its assertion method passes.
     *
     * @param  null|string                      $privilege
     * @return string|null
     */
    protected function get_rule_type(?Resource_Interface $resource = null, ?Role\Role_Interface $role = null, $privilege = null)
    {
        // Pull all rules for the specified $resource and $role
        if (null === $rules = $this->get_rules($resource, $role)) {
            // No rules discovered
            return null;
        }
        // Follow $privilege
        $rule = null;
        if (null === $privilege && isset($rules['allPrivileges'])) {
            // No privilege specified, but allPrivileges rule exists
            $rule = $rules['allPrivileges'];
        }
        if (null !== $privilege && isset($rules['byPrivilegeId'][$privilege])) {
            // Privilege specified, and found in ruleset
            $rule = $rules['byPrivilegeId'][$privilege];
        }
        if (null === $rule) {
            // No rule identified
            return null;
        }
        // Was a custom assertion supplied? Use it to retrieve the rule type.
        if ($rule['assert']) {
            /** @var AssertionInterface $assertion */
            $assertion = $rule['assert'];
            $assertion_value = $assertion->assert($this, $this->is_allowed_role instanceof Role\Role_Interface ? $this->is_allowed_role : $role, $this->is_allowed_resource instanceof Resource_Interface ? $this->is_allowed_resource : $resource, $this->is_allowed_privilege);
        } else {
            $assertion_value = true;
        }
        if ($assertion_value) {
            return $rule['type'];
        }
        if (null !== $resource || null !== $role || null !== $privilege) {
            return null;
        }
        if (self::TYPE_ALLOW === $rule['type']) {
            return self::TYPE_DENY;
        }
        return self::TYPE_ALLOW;
    }
    /**
     * Returns the rules associated with a Resource and a Role, or null if no such rules exist
     *
     * If either $resource or $role is null, this means that the rules returned are for all Resources or all Roles,
     * respectively. Both can be null to return the default rule set for all Resources and all Roles.
     *
     * If the $create parameter is true, then a rule set is first created and then returned to the caller.
     *
     * @param  bool $create
     * @return array|null
     */
    protected function &get_rules(?Resource_Interface $resource = null, ?Role\Role_Interface $role = null, $create = false)
    {
        // create a reference to null
        $null = null;
        $null_ref =& $null;
        // follow $resource
        do {
            if (null === $resource) {
                $visitor =& $this->rules['allResources'];
                break;
            }
            $resource_id = $resource->get_resource_id();
            if (!isset($this->rules['byResourceId'][$resource_id])) {
                if (!$create) {
                    return $null_ref;
                }
                $this->rules['byResourceId'][$resource_id] = [];
            }
            $visitor =& $this->rules['byResourceId'][$resource_id];
        } while (false);
        // follow $role
        if (null === $role) {
            if (!isset($visitor['allRoles'])) {
                if (!$create) {
                    return $null_ref;
                }
                $visitor['allRoles']['byPrivilegeId'] = [];
            }
            return $visitor['allRoles'];
        }
        $role_id = $role->get_role_id();
        if (!isset($visitor['byRoleId'][$role_id])) {
            if (!$create) {
                return $null_ref;
            }
            $visitor['byRoleId'][$role_id]['byPrivilegeId'] = [];
        }
        return $visitor['byRoleId'][$role_id];
    }
    /**
     * @return array of registered roles
     */
    public function get_roles(): array
    {
        return array_keys($this->get_role_registry()->get_roles());
    }
    /**
     * @return array of registered resources
     */
    public function get_resources(): array
    {
        return array_keys($this->resources);
    }
}