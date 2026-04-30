## ADDED Requirements

### Requirement: Role list page with pagination
The application SHALL provide a role list page at `/roles` accessible only to TenantAdmin, displaying roles in the active tenant.

#### Scenario: Role list loads for active tenant
- **WHEN** a TenantAdmin navigates to `/roles`
- **THEN** the system SHALL fetch `GET /admin/tenants/:tenantId/roles?page=1&pageSize=20` and display results with columns: Name, Code, Description, Created At, Actions

### Requirement: Create role
The application SHALL provide a create role modal from the role list page.

#### Scenario: Create role via modal
- **WHEN** the TenantAdmin clicks "Create" and fills in code (required), name (required), description (optional)
- **THEN** the system SHALL send `POST /admin/tenants/:tenantId/roles` and refresh the table

### Requirement: Edit role
The application SHALL provide an edit role modal from each row's action menu.

#### Scenario: Edit role via modal
- **WHEN** the TenantAdmin clicks "Edit" on a role row
- **THEN** the system SHALL open a modal pre-filled with the role's data, allow editing, and send `PUT /admin/tenants/:tenantId/roles/:id` on submit

### Requirement: Delete role
The application SHALL allow TenantAdmin to delete a role with confirmation.

#### Scenario: Delete role with confirmation
- **WHEN** the TenantAdmin clicks "Delete" on a role row
- **THEN** the system SHALL show a confirmation dialog warning that associated user-role and role-permission assignments will be removed, and on confirm send `DELETE /admin/tenants/:tenantId/roles/:id`

### Requirement: Role permission assignment
The application SHALL provide a permission assignment interface for each role, accessible at `/roles/:id/permissions`.

#### Scenario: View role's current permissions
- **WHEN** the TenantAdmin navigates to `/roles/:id/permissions`
- **THEN** the system SHALL fetch `GET /admin/tenants/:tenantId/roles/:id/permissions` and `GET /admin/tenants/:tenantId/permissions` to display a Transfer component with available permissions on the left and assigned permissions on the right

#### Scenario: Update role permissions
- **WHEN** the TenantAdmin moves permissions between the Transfer lists and clicks "Save"
- **THEN** the system SHALL send `PUT /admin/tenants/:tenantId/roles/:id/permissions` with the array of selected permission UUIDs

#### Scenario: Permission display shows resource and action
- **WHEN** permissions are shown in the Transfer component
- **THEN** each permission item SHALL display its name, resource path, and action (HTTP method)
