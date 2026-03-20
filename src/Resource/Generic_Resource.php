<?php

declare (strict_types=1);
namespace Laminas\Permissions\Acl\Resource;

use Stringable;
class Generic_Resource implements Resource_Interface, Stringable
{
    /**
     * Unique id of Resource
     */
    protected string $resource_id;
    /**
     * Sets the Resource identifier
     *
     * @param  string $resourceId
     */
    public function __construct($resource_id)
    {
        $this->resource_id = (string) $resource_id;
    }
    /**
     * Defined by ResourceInterface; returns the Resource identifier
     *
     * @return string
     */
    public function get_resource_id()
    {
        return $this->resource_id;
    }
    /**
     * Defined by ResourceInterface; returns the Resource identifier
     * Proxies to getResourceId()
     */
    public function __toString(): string
    {
        return $this->get_resource_id();
    }
}