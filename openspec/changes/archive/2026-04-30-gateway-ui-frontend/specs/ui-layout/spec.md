## ADDED Requirements

### Requirement: Admin layout with sidebar and top bar
The application SHALL provide an admin layout with a collapsible sidebar for navigation and a top bar for global controls.

#### Scenario: Layout renders for authenticated users
- **WHEN** an authenticated user accesses any page except `/login`
- **THEN** the system SHALL render the sidebar, top bar, and content area

#### Scenario: Sidebar is collapsible
- **WHEN** the user clicks the collapse toggle
- **THEN** the sidebar SHALL collapse to icon-only mode and expand back on subsequent clicks

### Requirement: Role-based sidebar navigation
The sidebar SHALL display different menu items based on the user's role.

#### Scenario: SuperAdmin navigation
- **WHEN** a SuperAdmin is logged in
- **THEN** the sidebar SHALL show: Dashboard, Tenant Management, Tenant Admin Management

#### Scenario: TenantAdmin navigation
- **WHEN** a TenantAdmin is logged in
- **THEN** the sidebar SHALL show: Dashboard, User Management, Role Management, Permission Management, User-Role Assignment

#### Scenario: Active page is highlighted
- **WHEN** the user is on a specific page
- **THEN** the corresponding sidebar menu item SHALL be visually highlighted

### Requirement: Global tenant selector for SuperAdmin
The top bar SHALL display a tenant selector dropdown when the logged-in user is a SuperAdmin.

#### Scenario: SuperAdmin sees tenant dropdown
- **WHEN** a SuperAdmin is logged in
- **THEN** the top bar SHALL display a dropdown listing all tenants, with the currently selected tenant shown

#### Scenario: Switching tenant updates context
- **WHEN** a SuperAdmin selects a different tenant from the dropdown
- **THEN** the active tenant in AuthContext SHALL update and any tenant-scoped page SHALL refresh its data

#### Scenario: Tenant list is fetched from API
- **WHEN** a SuperAdmin logs in
- **THEN** the system SHALL fetch `GET /admin/tenants` to populate the tenant selector

### Requirement: Fixed tenant label for TenantAdmin
The top bar SHALL display the tenant name as a non-interactive label when the logged-in user is a TenantAdmin.

#### Scenario: TenantAdmin sees fixed tenant
- **WHEN** a TenantAdmin is logged in
- **THEN** the top bar SHALL display the tenant name as static text without a dropdown

### Requirement: Language switcher in top bar
The top bar SHALL include a language switcher to toggle between zh-CN and en-US.

#### Scenario: Language toggle changes UI language
- **WHEN** the user clicks the language switcher and selects a different language
- **THEN** all UI text (labels, buttons, messages, menu items) SHALL immediately switch to the selected language

#### Scenario: Language preference persists
- **WHEN** the user selects a language
- **THEN** the preference SHALL be saved to localStorage and restored on next visit

### Requirement: User menu in top bar
The top bar SHALL include a user menu dropdown showing the current username and a logout option.

#### Scenario: User menu displays username
- **WHEN** the user clicks the user avatar or name in the top bar
- **THEN** a dropdown SHALL show the current username and a logout option

#### Scenario: Logout from user menu
- **WHEN** the user clicks the logout option in the dropdown
- **THEN** the system SHALL perform the logout flow (POST /auth/logout, clear context, redirect to /login)
