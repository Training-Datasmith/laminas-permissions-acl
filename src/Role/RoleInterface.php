<?php

declare (strict_types=1);
namespace Laminas\Permissions\Acl\Role;

interface Role_Interface
{
    /**
     * Returns the string identifier of the Role
     *
     * @return string
     */
    public function get_role_id();
}