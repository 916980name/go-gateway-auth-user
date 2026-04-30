## ADDED Requirements

### Requirement: Permission list page with pagination
The application SHALL provide a permission list page at `/permissions` accessible only to TenantAdmin, displaying permissions in the active tenant.

#### Scenario: Permission list loads for active tenant
- **WHEN** a TenantAdmin navigates to `/permissions`
- **THEN** the system SHALL fetch `GET /admin/tenants/:tenantId/permissions?page=1&pageSize=20` and display results with columns: Name, Code, Resource, Action, Description, Created At, Actions

### Requirement: Create permission
The application SHALL provide a create permission modal from the permission list page.

#### Scenario: Create permission via modal
- **WHEN** the TenantAdmin clicks "Create" and fills in code (required), name (required), resource (required), action (required), description (optional)
- **THEN** the system SHALL send `POST /admin/tenants/:tenantId/permissions` and refresh the table

#### Scenario: Action field uses select with HTTP methods
- **WHEN** the create/edit form is displayed
- **THEN** the action field SHALL be a select dropdown with options: GET, POST, PUT, DELETE, PATCH, and a custom input option for non-standard actions

#### Scenario: Resource field shows path pattern hint
- **WHEN** the create/edit form is displayed
- **THEN** the resource field SHALL show a placeholder hint like `/api/users/*` to indicate path pattern format

### Requirement: Edit permission
The application SHALL provide an edit permission modal from each row's action menu.

#### Scenario: Edit permission via modal
- **WHEN** the TenantAdmin clicks "Edit" on a permission row
- **THEN** the system SHALL open a modal pre-filled with the permission's data, allow editing, and send `PUT /admin/tenants/:tenantId/permissions/:id` on submit

### Requirement: Delete permission
The application SHALL allow TenantAdmin to delete a permission with confirmation.

#### Scenario: Delete permission with confirmation
- **WHEN** the TenantAdmin clicks "Delete" on a permission row
- **THEN** the system SHALL show a confirmation dialog warning that associated role-permission assignments will be removed, and on confirm send `DELETE /admin/tenants/:tenantId/permissions/:id`
