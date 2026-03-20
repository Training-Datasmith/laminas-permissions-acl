<?php

declare (strict_types=1);
namespace Laminas\Permissions\Acl\Resource;

interface Resource_Interface
{
    /**
     * Returns the string identifier of the Resource
     *
     * @return string
     */
    public function get_resource_id();
}