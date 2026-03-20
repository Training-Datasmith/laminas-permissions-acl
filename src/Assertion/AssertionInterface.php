<?php

declare (strict_types=1);
namespace Laminas\Permissions\Acl\Assertion;

use Laminas\Permissions\Acl\Acl;
use Laminas\Permissions\Acl\Resource\Resource_Interface;
use Laminas\Permissions\Acl\Role\Role_Interface;
interface Assertion_Interface
{
    /**
     * Returns true if and only if the assertion conditions are met
     *
     * This method is passed the ACL, Role, Resource, and privilege to which the authorization query applies. If the
     * $role, $resource, or $privilege parameters are null, it means that the query applies to all Roles, Resources, or
     * privileges, respectively.
     *
     * @param  string|null $privilege
     * @return bool
     */
    public function assert(Acl $acl, ?Role_Interface $role = null, ?Resource_Interface $resource = null, $privilege = null);
}