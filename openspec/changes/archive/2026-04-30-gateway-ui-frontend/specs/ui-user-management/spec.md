## ADDED Requirements

### Requirement: User list page with pagination and search
The application SHALL provide a user list page at `/users` accessible only to TenantAdmin, displaying users in the active tenant with server-side pagination and search.

#### Scenario: User list loads for active tenant
- **WHEN** a TenantAdmin navigates to `/users`
- **THEN** the system SHALL fetch `GET /admin/users?page=1&pageSize=20` and display results with columns: Username, Display Name, Email, Phone, Status, Created At, Actions

#### Scenario: Search users by keyword
- **WHEN** the TenantAdmin types a search term in the search input
- **THEN** the system SHALL debounce the input and fetch `GET /admin/users?page=1&pageSize=20&search=<term>` to filter results

### Requirement: Create user
The application SHALL provide a create user modal from the user list page.

#### Scenario: Create user via modal
- **WHEN** the TenantAdmin clicks "Create" and fills in username (required), password (required), display name, email, phone
- **THEN** the system SHALL send `POST /admin/users` with the form data, close the modal on success, and refresh the table

### Requirement: Edit user
The application SHALL provide an edit user modal from each row's action menu.

#### Scenario: Edit user via modal
- **WHEN** the TenantAdmin clicks "Edit" on a user row
- **THEN** the system SHALL open a modal pre-filled with the user's current data (excluding password), allow editing, and send `PUT /admin/users/:id` on submit

### Requirement: Disable user
The application SHALL allow TenantAdmin to disable a user with confirmation.

#### Scenario: Disable user with confirmation
- **WHEN** the TenantAdmin clicks "Disable" on a user row
- **THEN** the system SHALL show a confirmation dialog, and on confirm send `DELETE /admin/users/:id`, then refresh the table

### Requirement: User credential management
The application SHALL provide a drawer to manage credentials for a specific user.

#### Scenario: View user credentials
- **WHEN** the TenantAdmin clicks "Credentials" on a user row
- **THEN** the system SHALL open a drawer showing the user's credentials fetched from `GET /admin/users/:id/credentials` with columns: Provider Type, Identifier, Status, Created At

#### Scenario: Add credential to user
- **WHEN** the TenantAdmin clicks "Add Credential" in the drawer and fills in provider type, credential value
- **THEN** the system SHALL send `POST /admin/users/:id/credentials` and refresh the credential list

#### Scenario: Delete credential from user
- **WHEN** the TenantAdmin clicks "Delete" on a credential entry
- **THEN** the system SHALL send `DELETE /admin/users/:id/credentials/:credId` with confirmation and refresh the list
