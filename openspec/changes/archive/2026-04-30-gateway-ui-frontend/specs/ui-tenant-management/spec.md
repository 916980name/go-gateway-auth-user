## ADDED Requirements

### Requirement: Tenant list page with pagination and search
The application SHALL provide a tenant list page at `/tenants` accessible only to SuperAdmin, displaying tenants in an Ant Design Table with server-side pagination.

#### Scenario: Tenant list loads with default pagination
- **WHEN** a SuperAdmin navigates to `/tenants`
- **THEN** the system SHALL fetch `GET /admin/tenants?page=1&pageSize=20` and display the results in a table with columns: Name, Code, Status, Created At, Actions

#### Scenario: Pagination controls work
- **WHEN** the SuperAdmin clicks page 2 in the pagination
- **THEN** the system SHALL fetch `GET /admin/tenants?page=2&pageSize=20` and update the table

### Requirement: Create tenant
The application SHALL provide a create tenant modal accessible from the tenant list page.

#### Scenario: Create tenant via modal
- **WHEN** the SuperAdmin clicks the "Create" button and fills in the form with code, name
- **THEN** the system SHALL send `POST /admin/tenants` with the form data, close the modal on success, and refresh the table

#### Scenario: Validation on create
- **WHEN** the SuperAdmin submits the create form with an empty code or name
- **THEN** the form SHALL show inline validation errors

### Requirement: Edit tenant
The application SHALL provide an edit tenant modal accessible from each row's action menu.

#### Scenario: Edit tenant via modal
- **WHEN** the SuperAdmin clicks "Edit" on a tenant row
- **THEN** the system SHALL open a modal pre-filled with the tenant's current data, allow editing, and send `PUT /admin/tenants/:id` on submit

### Requirement: Disable tenant (soft delete)
The application SHALL allow SuperAdmin to disable a tenant with confirmation.

#### Scenario: Disable tenant with confirmation
- **WHEN** the SuperAdmin clicks "Disable" on a tenant row
- **THEN** the system SHALL show a confirmation dialog, and on confirm send `DELETE /admin/tenants/:id`, then refresh the table

### Requirement: Tenant domain management
The application SHALL provide a sub-panel (drawer or sub-page) to manage domains for a specific tenant.

#### Scenario: View tenant domains
- **WHEN** the SuperAdmin clicks "Domains" on a tenant row
- **THEN** the system SHALL open a drawer showing the tenant's domains fetched from `GET /admin/tenants/:id/domains`

#### Scenario: Add domain to tenant
- **WHEN** the SuperAdmin enters a domain pattern and clicks "Add"
- **THEN** the system SHALL send `POST /admin/tenants/:id/domains` with the pattern and refresh the domain list

#### Scenario: Remove domain from tenant
- **WHEN** the SuperAdmin clicks "Delete" on a domain entry
- **THEN** the system SHALL send `DELETE /admin/tenants/:id/domains/:domainId` with confirmation and refresh the list
