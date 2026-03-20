<?php

declare (strict_types=1);
namespace Laminas\Permissions\Acl;

/**
 * Applicable to Resources and Roles.
 *
 * Provides information about the owner of some object. Used in conjunction
 * with the Ownership assertion.
 */
interface Proprietary_Interface
{
    /**
     * @return mixed
     */
    public function get_owner_id();
}