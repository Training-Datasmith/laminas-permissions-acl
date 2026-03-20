<?php

declare (strict_types=1);
namespace Laminas\Permissions\Acl\Assertion;

use Laminas\Permissions\Acl\Acl;
use Laminas\Permissions\Acl\Proprietary_Interface;
use Laminas\Permissions\Acl\Resource\Resource_Interface;
use Laminas\Permissions\Acl\Role\Role_Interface;
/**
 * Makes sure that some Resource is owned by certain Role.
 */
class Ownership_Assertion implements Assertion_Interface
{
    /** @inheritDoc */
    public function assert(Acl $acl, ?Role_Interface $role = null, ?Resource_Interface $resource = null, $privilege = null)
    {
        //Assert passes if role or resource is not proprietary
        if (!$role instanceof Proprietary_Interface || !$resource instanceof Proprietary_Interface) {
            return true;
        }
        //Assert passes if resources does not have an owner
        if ($resource->get_owner_id() === null) {
            return true;
        }
        return $resource->get_owner_id() === $role->get_owner_id();
    }
}