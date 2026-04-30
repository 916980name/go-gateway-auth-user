## ADDED Requirements

### Requirement: Tenant admin list page
The application SHALL provide a tenant admin management page at `/tenant-admins` accessible only to SuperAdmin, listing all users who hold the `tenant_admin` role in any tenant.

#### Scenario: List tenant admins
- **WHEN** a SuperAdmin navigates to `/tenant-admins`
- **THEN** the system SHALL display a table of tenant admin accounts showing: Username, Display Name, Tenant Name, Status, Created At

### Requirement: Dedicated tenant admin creation wizard
The application SHALL provide a step-by-step wizard at `/tenant-admins/create` to create a tenant admin account.

#### Scenario: Step 1 — Select tenant
- **WHEN** the SuperAdmin starts the wizard
- **THEN** the system SHALL display a tenant selector dropdown populated from `GET /admin/tenants` and a "Next" button

#### Scenario: Step 2 — Create account
- **WHEN** the SuperAdmin selects a tenant and clicks "Next"
- **THEN** the system SHALL display a form with fields: username (required), password (required), display name (optional), email (optional), phone (optional)

#### Scenario: Step 3 — Confirmation
- **WHEN** the SuperAdmin fills in the account form and clicks "Create"
- **THEN** the system SHALL:
  1. Send `POST /admin/users` to create the user with a password credential
  2. Send `PUT /admin/tenants/:tenantId/users/:userId/roles` with the `tenant_admin` role UUID
  3. Display a success message showing the created username and assigned tenant
  4. Provide a "Close" button to return to the tenant admin list

#### Scenario: Creation failure shows error
- **WHEN** the user creation or role assignment API call fails
- **THEN** the wizard SHALL display the error message and remain on the current step for retry

#### Scenario: Form validation
- **WHEN** the SuperAdmin submits step 2 with empty username or password
- **THEN** the form SHALL show inline validation errors and NOT proceed
