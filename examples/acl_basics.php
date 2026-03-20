<?php

declare(strict_types=1);

/**
 * Example: role/resource access control with laminas-permissions-acl.
 *
 * Run from the laminas-permissions-acl project root:
 *   php examples/acl_basics.php
 */

require __DIR__ . '/../vendor/autoload.php';

use Laminas\Permissions\Acl\Acl;
use Laminas\Permissions\Acl\Role\Generic_Role as Role;
use Laminas\Permissions\Acl\Resource\Generic_Resource as Resource;

$acl = new Acl();

// --- Define roles (with inheritance) ---
$acl->add_role(new Role('guest'));
$acl->add_role(new Role('member'), 'guest');   // member inherits guest
$acl->add_role(new Role('admin'),  'member');  // admin inherits member

// --- Define resources ---
$acl->add_resource(new Resource('article'));
$acl->add_resource(new Resource('comment'));
$acl->add_resource(new Resource('admin_panel'));

// --- Grant / deny rules ---
$acl->allow('guest',  'article',     'read');
$acl->allow('member', 'article',     ['create', 'edit']);
$acl->allow('member', 'comment',     ['create', 'delete']);
$acl->allow('admin',  null,          null);     // admin can do everything
$acl->deny ('member', 'admin_panel', null);     // members cannot access admin panel

// --- Check access ---
$checks = [
    ['guest',  'article',     'read'],
    ['guest',  'article',     'create'],
    ['member', 'article',     'edit'],
    ['member', 'admin_panel', 'view'],
    ['admin',  'admin_panel', 'view'],
    ['admin',  'article',     'delete'],
];

foreach ($checks as [$role, $resource, $privilege]) {
    $allowed = $acl->is_allowed($role, $resource, $privilege);
    printf("%-8s %-12s %-10s => %s\n", $role, $resource, $privilege, $allowed ? 'ALLOW' : 'DENY');
}

// --- Dynamic assertion ---
$acl->allow('member', 'article', 'publish', new \Laminas\Permissions\Acl\Assertion\Callback_Assertion(
    static function ($acl, $role, $resource, $privilege): bool {
        // Only allow publishing on Mondays (for demonstration)
        return (int) date('N') === 1;
    }
));

echo "\nDynamic assertion (publish on " . date('l') . "): ";
echo $acl->is_allowed('member', 'article', 'publish') ? "ALLOW\n" : "DENY\n";
