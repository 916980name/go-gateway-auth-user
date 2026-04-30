## ADDED Requirements

### Requirement: Login page with username and password
The application SHALL provide a login page at `/login` with username and password fields and a submit button.

#### Scenario: Successful login
- **WHEN** a user enters valid credentials and submits the login form
- **THEN** the system SHALL send `POST /auth/login` with `{provider: "password", identifier: <username>, credential: <password>}`, receive a cookie-based JWT, store user info in AuthContext, and redirect to `/dashboard`

#### Scenario: Failed login shows error
- **WHEN** a user enters invalid credentials and submits the login form
- **THEN** the system SHALL display an error message from the backend response without redirecting

#### Scenario: Login form validation
- **WHEN** a user submits the form with empty username or password
- **THEN** the system SHALL show inline validation errors and NOT send the API request

### Requirement: Cookie-based authentication
The application SHALL use cookie-based JWT authentication with `withCredentials: true` on all API requests.

#### Scenario: Cookies are sent automatically
- **WHEN** any API request is made after login
- **THEN** the browser SHALL automatically include the `Authorization` cookie set by the backend

#### Scenario: No token storage in JavaScript
- **WHEN** the user is authenticated
- **THEN** the JWT token SHALL NOT be stored in localStorage, sessionStorage, or JavaScript memory — the HttpOnly cookie is the sole auth mechanism

### Requirement: Auth context provides current user state
The application SHALL provide an AuthContext that exposes the current user's username, role assignments (with tenant UUIDs), and whether the user is a SuperAdmin or TenantAdmin.

#### Scenario: SuperAdmin detected
- **WHEN** the login response indicates the user has the `system_admin` role in the `__system__` tenant
- **THEN** AuthContext SHALL set `isSuperAdmin: true` and populate the tenant list for the selector

#### Scenario: TenantAdmin detected
- **WHEN** the login response indicates the user has `tenant_admin` role in a specific tenant (not `__system__`)
- **THEN** AuthContext SHALL set `isSuperAdmin: false` and fix the active tenant to the user's tenant

### Requirement: Logout clears session
The application SHALL provide a logout action accessible from the user menu.

#### Scenario: Successful logout
- **WHEN** the user clicks the logout option
- **THEN** the system SHALL send `POST /auth/logout`, clear the AuthContext, and redirect to `/login`

### Requirement: Automatic redirect on 401
The application SHALL redirect to `/login` when any API response returns HTTP 401.

#### Scenario: Expired session redirects to login
- **WHEN** an API call returns HTTP 401 (token expired or invalid)
- **THEN** the system SHALL clear the AuthContext and redirect to `/login`

### Requirement: Route protection
Authenticated routes SHALL be protected by an auth guard that redirects unauthenticated users to `/login`.

#### Scenario: Unauthenticated access redirected
- **WHEN** an unauthenticated user navigates to `/dashboard`
- **THEN** the system SHALL redirect to `/login`

#### Scenario: Authenticated user stays on page
- **WHEN** an authenticated user navigates to `/dashboard`
- **THEN** the system SHALL render the dashboard page
