<?php

declare (strict_types=1);
namespace Laminas\Permissions\Acl\Role;

use Stringable;
class Generic_Role implements Role_Interface, Stringable
{
    /**
     * Unique id of Role
     */
    protected string $role_id;
    /**
     * Sets the Role identifier
     *
     * @param string $roleId
     */
    public function __construct($role_id)
    {
        $this->role_id = (string) $role_id;
    }
    /**
     * Defined by RoleInterface; returns the Role identifier
     *
     * @return string
     */
    public function get_role_id()
    {
        return $this->role_id;
    }
    /**
     * Defined by RoleInterface; returns the Role identifier
     * Proxies to getRoleId()
     */
    public function __toString(): string
    {
        return $this->get_role_id();
    }
}