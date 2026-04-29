## ADDED Requirements

### Requirement: Tenant CRUD API
The system SHALL provide REST endpoints for managing tenants under `/admin/tenants`.

#### Scenario: List tenants with pagination
- **WHEN** `GET /admin/tenants?page=1&pageSize=20` is called
- **THEN** the system SHALL return a paginated list of tenants with `data`, `pagination.page`, `pagination.pageSize`, and `pagination.total`

#### Scenario: Create tenant
- **WHEN** `POST /admin/tenants` is called with `code`, `name`, and `hostname`
- **THEN** the system SHALL create a new tenant and return the tenant detail with a generated UUID

#### Scenario: Get tenant detail
- **WHEN** `GET /admin/tenants/:id` is called with a valid tenant UUID
- **THEN** the system SHALL return the full tenant detail

#### Scenario: Update tenant
- **WHEN** `PUT /admin/tenants/:id` is called with updated fields
- **THEN** the system SHALL update the tenant and return the updated detail

#### Scenario: Delete tenant (soft delete)
- **WHEN** `DELETE /admin/tenants/:id` is called
- **THEN** the system SHALL set the tenant's status to disabled (soft delete)

### Requirement: User management API
The system SHALL provide REST endpoints for managing users under `/admin/users`.

#### Scenario: List users with pagination and search
- **WHEN** `GET /admin/users?page=1&pageSize=20&search=alice` is called
- **THEN** the system SHALL return a paginated list of users matching the search term

#### Scenario: Create user
- **WHEN** `POST /admin/users` is called with `username` and optional `display_name`, `email`, `phone`
- **THEN** the system SHALL create a new user and return the user detail with a generated UUID

#### Scenario: Get user detail
- **WHEN** `GET /admin/users/:id` is called with a valid user UUID
- **THEN** the system SHALL return the full user detail

#### Scenario: Update user
- **WHEN** `PUT /admin/users/:id` is called with updated fields
- **THEN** the system SHALL update the user and return the updated detail

#### Scenario: Disable user (soft delete)
- **WHEN** `DELETE /admin/users/:id` is called
- **THEN** the system SHALL set the user's status to disabled

### Requirement: User-tenant association API
The system SHALL provide endpoints to manage which tenants a user belongs to.

#### Scenario: List user's tenants
- **WHEN** `GET /admin/users/:id/tenants?page=1&pageSize=20` is called
- **THEN** the system SHALL return a paginated list of tenants the user belongs to

#### Scenario: Add user to tenant
- **WHEN** `POST /admin/users/:id/tenants/:tenantId` is called
- **THEN** the system SHALL create a `tenant_users` record associating the user with the tenant

#### Scenario: Remove user from tenant
- **WHEN** `DELETE /admin/users/:id/tenants/:tenantId` is called
- **THEN** the system SHALL remove the `tenant_users` association

### Requirement: Role management API (tenant-scoped)
The system SHALL provide REST endpoints for managing roles scoped to a tenant under `/admin/tenants/:tenantId/roles`.

#### Scenario: List roles in tenant
- **WHEN** `GET /admin/tenants/:tenantId/roles?page=1&pageSize=20` is called
- **THEN** the system SHALL return a paginated list of roles in the specified tenant

#### Scenario: Create role
- **WHEN** `POST /admin/tenants/:tenantId/roles` is called with `code`, `name`, and optional `description`
- **THEN** the system SHALL create a new role scoped to the tenant

#### Scenario: Update role
- **WHEN** `PUT /admin/tenants/:tenantId/roles/:id` is called
- **THEN** the system SHALL update the role

#### Scenario: Delete role
- **WHEN** `DELETE /admin/tenants/:tenantId/roles/:id` is called
- **THEN** the system SHALL delete the role and its associated `role_permissions` and `user_roles` entries

#### Scenario: Get role's permissions
- **WHEN** `GET /admin/tenants/:tenantId/roles/:id/permissions?page=1&pageSize=20` is called
- **THEN** the system SHALL return a paginated list of permissions assigned to the role

#### Scenario: Set role's permissions (full replace)
- **WHEN** `PUT /admin/tenants/:tenantId/roles/:id/permissions` is called with an array of permission UUIDs
- **THEN** the system SHALL replace all `role_permissions` for this role with the provided set and reload Casbin policies

### Requirement: User role assignment API (tenant-scoped)
The system SHALL provide endpoints to manage user-role assignments within a tenant.

#### Scenario: Get user's roles in tenant
- **WHEN** `GET /admin/tenants/:tenantId/users/:userId/roles?page=1&pageSize=20` is called
- **THEN** the system SHALL return a paginated list of roles the user holds in the specified tenant

#### Scenario: Set user's roles (full replace)
- **WHEN** `PUT /admin/tenants/:tenantId/users/:userId/roles` is called with an array of role UUIDs
- **THEN** the system SHALL replace all `user_roles` for this user in this tenant with the provided set and reload Casbin policies

### Requirement: Permission management API (tenant-scoped)
The system SHALL provide REST endpoints for managing permissions scoped to a tenant under `/admin/tenants/:tenantId/permissions`.

#### Scenario: List permissions in tenant
- **WHEN** `GET /admin/tenants/:tenantId/permissions?page=1&pageSize=20` is called
- **THEN** the system SHALL return a paginated list of permissions in the specified tenant

#### Scenario: Create permission
- **WHEN** `POST /admin/tenants/:tenantId/permissions` is called with `code`, `name`, `resource`, `action`, and optional `description`
- **THEN** the system SHALL create a new permission scoped to the tenant

#### Scenario: Update permission
- **WHEN** `PUT /admin/tenants/:tenantId/permissions/:id` is called
- **THEN** the system SHALL update the permission and reload Casbin policies

#### Scenario: Delete permission
- **WHEN** `DELETE /admin/tenants/:tenantId/permissions/:id` is called
- **THEN** the system SHALL delete the permission and its associated `role_permissions` entries, then reload Casbin policies

### Requirement: Pagination on all list endpoints
All list/query endpoints SHALL support offset pagination with `page` and `pageSize` query parameters, defaulting to page 1 and pageSize 20 (max 100).

#### Scenario: Default pagination
- **WHEN** a list endpoint is called without pagination params
- **THEN** the system SHALL return page 1 with pageSize 20

#### Scenario: Page size capped
- **WHEN** a list endpoint is called with `pageSize=500`
- **THEN** the system SHALL cap the page size to 100

### Requirement: Admin API protected by RBAC
All admin endpoints SHALL be protected by the same RBAC enforcement. `system_admin` role can manage all resources. `tenant_admin` can only manage resources within their assigned tenant.

#### Scenario: System admin can access all tenants
- **WHEN** a user with `system_admin` role calls any admin endpoint
- **THEN** the system SHALL allow access

#### Scenario: Tenant admin restricted to own tenant
- **WHEN** a user with `tenant_admin` role in tenant A calls `GET /admin/tenants/:tenantB/roles`
- **THEN** the system SHALL return HTTP 403 Forbidden

#### Scenario: Unauthenticated admin access denied
- **WHEN** an unauthenticated request targets any `/admin/*` endpoint
- **THEN** the system SHALL return HTTP 401 Unauthorized

### Requirement: Consistent error responses
Admin API errors SHALL use a consistent JSON structure with `error.code` and `error.message`.

#### Scenario: Validation error
- **WHEN** a required field is missing in a POST/PUT request
- **THEN** the system SHALL return HTTP 400 with `{"error": {"code": "INVALID_INPUT", "message": "..."}}`

#### Scenario: Resource not found
- **WHEN** a UUID in the path does not match any entity
- **THEN** the system SHALL return HTTP 404 with `{"error": {"code": "NOT_FOUND", "message": "..."}}`

### Requirement: API uses UUID in path parameters
All API path parameters (`:id`, `:tenantId`, `:userId`) SHALL accept UUID values. Integer IDs SHALL never be exposed in API requests or responses.

#### Scenario: Create returns UUID
- **WHEN** a new entity is created via the API
- **THEN** the response SHALL include the entity's `uuid` field, not its internal integer `id`

#### Scenario: Lookup by UUID
- **WHEN** an API call includes a UUID path parameter
- **THEN** the system SHALL resolve the UUID to the internal integer ID for database operations
