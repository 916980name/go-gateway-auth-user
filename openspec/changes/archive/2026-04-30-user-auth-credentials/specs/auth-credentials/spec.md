## ADDED Requirements

### Requirement: user_credentials table
The system SHALL provide a `user_credentials` table storing authentication credentials per user per tenant per provider type.

#### Scenario: Table schema
- **WHEN** the user module migration creates the `user_credentials` table
- **THEN** it SHALL have columns: `id` (BIGSERIAL PK), `user_id` (FK users), `tenant_id` (FK tenants), `provider_type` (VARCHAR(32) NOT NULL), `credential` (TEXT nullable), `identifier` (VARCHAR(256) nullable), `metadata` (JSONB nullable), `status` (SMALLINT DEFAULT 1), `created_at`, `updated_at`

#### Scenario: One credential per provider per user per tenant
- **WHEN** a user already has a `password` credential in a tenant
- **THEN** inserting another `password` credential for the same user and tenant SHALL be rejected by `UNIQUE(user_id, tenant_id, provider_type)`

#### Scenario: OAuth identifier uniqueness
- **WHEN** an OAuth credential with `identifier = 'gh-12345'` and `provider_type = 'oauth:github'` exists in a tenant
- **THEN** inserting another credential with the same tenant, provider_type, and identifier SHALL be rejected by the partial unique index `WHERE identifier IS NOT NULL`

### Requirement: CredentialProvider interface
The system SHALL define a `CredentialProvider` interface in `pkg/auth/` with method `Authenticate(ctx, AuthRequest) (*AuthResult, error)` and `Type() string`.

#### Scenario: Provider registration
- **WHEN** the auth module initializes
- **THEN** configured providers SHALL be registered in a `map[string]CredentialProvider` keyed by provider type string

#### Scenario: Unknown provider
- **WHEN** a login request specifies a provider type that is not registered
- **THEN** the system SHALL return an error indicating the provider is not supported

### Requirement: Password credential provider
The system SHALL implement a password provider that verifies bcrypt-hashed passwords stored in `user_credentials`.

#### Scenario: Password authentication with username
- **WHEN** a login request has `provider=password` and `identifier=alice`
- **THEN** the system SHALL query `users` by `username='alice' AND tenant_id=? AND status=1`, then query `user_credentials` by `user_id=? AND tenant_id=? AND provider_type='password' AND status=1`, and compare the credential using bcrypt

#### Scenario: Password authentication with email
- **WHEN** a login request has `provider=password` and `identifier=alice@example.com`
- **THEN** the system SHALL detect the `@` character and query `users` by `email='alice@example.com' AND tenant_id=? AND status=1`

#### Scenario: Password authentication with phone
- **WHEN** a login request has `provider=password` and `identifier=+8613800138000`
- **THEN** the system SHALL detect the `+` prefix or all-digit pattern and query `users` by `phone='+8613800138000' AND tenant_id=? AND status=1`

#### Scenario: Wrong password
- **WHEN** the identifier resolves to a valid user but bcrypt comparison fails
- **THEN** the system SHALL return an authentication error without revealing whether the user exists

#### Scenario: User not found
- **WHEN** the identifier does not match any active user in the tenant
- **THEN** the system SHALL return the same authentication error as a wrong password (no user enumeration)

#### Scenario: Credential disabled
- **WHEN** the user exists but their password credential has `status=0`
- **THEN** the system SHALL return an authentication error

### Requirement: Password hashing with bcrypt
Passwords SHALL be hashed using bcrypt with a cost factor of at least 10 before storage.

#### Scenario: Password stored as bcrypt hash
- **WHEN** a password credential is created for a user
- **THEN** the `credential` column SHALL contain a bcrypt hash, never plaintext

#### Scenario: Password verification uses bcrypt compare
- **WHEN** a password is verified during login
- **THEN** the system SHALL use `bcrypt.CompareHashAndPassword` to compare the input against the stored hash

### Requirement: Credential CRUD via admin API
The system SHALL provide admin API endpoints to manage user credentials (create, list by user, update, delete).

#### Scenario: Create password credential for user
- **WHEN** an admin creates a password credential for a user
- **THEN** the system SHALL hash the provided password with bcrypt and store it in `user_credentials`

#### Scenario: List credentials for user
- **WHEN** an admin queries credentials for a user
- **THEN** the system SHALL return credential records with `credential` field redacted (never expose hashes)

#### Scenario: Delete credential
- **WHEN** an admin deletes a credential
- **THEN** the system SHALL soft-delete (set status=0) the credential record
