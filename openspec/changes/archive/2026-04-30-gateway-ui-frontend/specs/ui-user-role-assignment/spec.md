## ADDED Requirements

### Requirement: User-role assignment page
The application SHALL provide a user-role assignment page at `/user-roles` accessible only to TenantAdmin, allowing management of which roles are assigned to which users within the active tenant.

#### Scenario: User-role page displays user list
- **WHEN** a TenantAdmin navigates to `/user-roles`
- **THEN** the system SHALL fetch the user list and display a table with columns: Username, Display Name, Current Roles, Actions

#### Scenario: View user's current roles
- **WHEN** the TenantAdmin clicks "Manage Roles" on a user row
- **THEN** the system SHALL fetch `GET /admin/tenants/:tenantId/users/:userId/roles` and `GET /admin/tenants/:tenantId/roles` to display a Transfer or checkbox group with available roles and assigned roles

### Requirement: Assign roles to user
The application SHALL allow TenantAdmin to set the complete role assignment for a user in the active tenant.

#### Scenario: Update user roles via Transfer component
- **WHEN** the TenantAdmin moves roles between available and assigned lists and clicks "Save"
- **THEN** the system SHALL send `PUT /admin/tenants/:tenantId/users/:userId/roles` with the array of selected role UUIDs

#### Scenario: Role assignment is full replace
- **WHEN** the TenantAdmin saves role assignments
- **THEN** the system SHALL replace all existing role assignments for the user in this tenant with the selected set (not append)

#### Scenario: Success feedback after assignment
- **WHEN** the role assignment API call succeeds
- **THEN** the system SHALL show a success notification and refresh the user's displayed role list
