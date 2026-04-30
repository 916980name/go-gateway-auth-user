## ADDED Requirements

### Requirement: Site-level auth mode configuration
Each site in the gateway config SHALL support an `auth` block with a `mode` field. Valid values: `upstream` (delegate to backend, existing behavior) and `gateway` (authenticate directly).

#### Scenario: Upstream mode (default)
- **WHEN** a site has `auth.mode: upstream` or no `auth` block
- **THEN** the gateway SHALL use existing `LoginFilter`/`LogoutFilter` proxy middleware for authentication

#### Scenario: Gateway mode
- **WHEN** a site has `auth.mode: gateway`
- **THEN** the gateway SHALL register direct HTTP handlers for login/logout at the configured paths, bypassing the proxy chain

#### Scenario: Mixed modes in same instance
- **WHEN** one site uses `auth.mode: upstream` and another uses `auth.mode: gateway`
- **THEN** both SHALL work correctly within the same gateway process

### Requirement: Gateway mode provider configuration
When `auth.mode` is `gateway`, the site config SHALL include a `providers` list specifying which credential providers are enabled.

#### Scenario: Password provider configured
- **WHEN** a site has `auth.mode: gateway` with `providers: [{type: password}]`
- **THEN** the gateway SHALL accept password-based login requests for that site

#### Scenario: No providers configured
- **WHEN** a site has `auth.mode: gateway` with an empty `providers` list
- **THEN** the gateway SHALL log a warning and reject all login attempts

### Requirement: Gateway login endpoint
The gateway SHALL expose a login endpoint at the configured `auth.loginPath` that accepts JSON requests with `provider`, `identifier`, and `credential` fields.

#### Scenario: Successful password login
- **WHEN** `POST /auth/login` with `{"provider":"password","identifier":"alice","credential":"mypassword"}` and the credentials are valid
- **THEN** the system SHALL return HTTP 200 with `Authorization` header containing the JWT access token and `Refresh` header containing the refresh token (if configured)

#### Scenario: Login with cookie support
- **WHEN** the site has `cookieEnabled: true` and login succeeds
- **THEN** the system SHALL also set the JWT token as a root-path cookie

#### Scenario: Failed login
- **WHEN** authentication fails (wrong password, user not found, disabled)
- **THEN** the system SHALL return HTTP 401 with a generic error message (no user enumeration)

#### Scenario: Login rate limiting
- **WHEN** the site has a blacklist rate limiter configured
- **THEN** the gateway-mode login handler SHALL apply the same IP-based rate limiting as the existing LoginFilter

### Requirement: Gateway logout endpoint
The gateway SHALL expose a logout endpoint at the configured `auth.logoutPath`.

#### Scenario: Successful logout
- **WHEN** `POST /auth/logout` with a valid JWT token
- **THEN** the system SHALL remove the user's token hash from OnlineCache and return HTTP 200

#### Scenario: Logout clears cookies
- **WHEN** the site has `cookieEnabled: true` and logout is called
- **THEN** the system SHALL expire the access token and refresh token cookies

### Requirement: JWT issuance reuses existing infrastructure
Gateway-mode login SHALL use the same JWT signing (RSA256), token timeout, and OnlineCache mechanisms as upstream-mode login.

#### Scenario: Same JWT format
- **WHEN** a user logs in via gateway mode
- **THEN** the JWT payload SHALL contain the same `dat` claim structure (username, privileges, idKey) as upstream-mode tokens

#### Scenario: OnlineCache token tracking
- **WHEN** a user logs in via gateway mode
- **THEN** the token hash SHALL be stored in OnlineCache with key `online:{username}`, consistent with upstream-mode behavior

#### Scenario: AuthFilter works for both modes
- **WHEN** a JWT was issued by gateway-mode login
- **THEN** the existing `AuthFilter` middleware SHALL validate it identically to upstream-mode tokens

### Requirement: Tenant resolution for gateway login
The gateway login handler SHALL resolve the tenant from the request's domain (Host header) using the domain trie before attempting authentication.

#### Scenario: Known domain
- **WHEN** a login request arrives at `portal.example.com` which maps to tenant `acme`
- **THEN** the authentication SHALL scope to tenant `acme`

#### Scenario: Unknown domain
- **WHEN** a login request arrives at a domain not mapped to any tenant
- **THEN** the system SHALL return HTTP 400 with an error indicating the domain is not recognized
