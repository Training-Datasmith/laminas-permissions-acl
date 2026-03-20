# Architecture: laminas-permissions-acl

## Purpose
A PHP Access Control List (ACL) library. Models roles, resources, and privileges and answers allow/deny queries, supporting role inheritance, resource inheritance, and dynamic assertions.

## Directory Structure
```
src/
  Acl.php                          # Main ACL container — addRole, addResource, allow, deny, isAllowed
  Acl_Interface.php                # Contract for ACL implementations
  Role/
    Role_Interface.php             # A named principal (user, group, etc.)
    Generic_Role.php               # Default string-identified role
    Registry.php                   # Stores the role inheritance graph
  Resource/
    Resource_Interface.php         # A named object being protected
    Generic_Resource.php           # Default string-identified resource
  Assertion/
    Assertion_Interface.php        # assert(Acl, role, resource, privilege): bool
    Assertion_Aggregate.php        # Combines multiple assertions (AND / OR)
    Assertion_Manager.php          # Plugin manager for lazy assertion instantiation
    Callback_Assertion.php         # Wraps a callable as an assertion
    Expression_Assertion.php       # Evaluates a string expression (for config-driven ACLs)
    Ownership_Assertion.php        # Checks resource ownership
  Proprietary_Interface.php        # Marks resources that have an owner
  Exception/                       # Typed exceptions
```

## Key Design Decisions
- **Inheritance via role/resource trees** — roles can inherit from multiple parent roles; resources can inherit from parent resources. Allow/deny rules propagate up the inheritance chains.
- **Rule precedence** — deny rules override allow rules at the same level. More specific rules (resource + privilege) override broader rules (resource-level, then global).
- **Dynamic assertions** — the `assert` parameter on `allow()`/`deny()` accepts an `Assertion_Interface` implementation. The assertion is called at `isAllowed()` time with the actual role, resource, and privilege, enabling context-sensitive access decisions.
- **Null wildcard** — passing `null` for role, resource, or privilege means "all roles", "all resources", or "all privileges" respectively.

## Extension Points
- Implement `Assertion_Interface` for dynamic, runtime-evaluated access rules.
- Implement `Role_Interface` / `Resource_Interface` to use domain objects directly rather than string identifiers.
- Use `Assertion_Aggregate` to compose AND/OR logic from multiple assertions.

## Dependency Flow
```
Acl::allow($role, $resource, $privilege, $assertion?)
  └─ stores rule in internal rule tree

Acl::isAllowed($role, $resource, $privilege)
  └─ traverse role inheritance chain
       └─ traverse resource inheritance chain
            └─ match deny/allow rule
                 └─ if assertion present: Assertion_Interface::assert() → bool
```
