## ADDED Requirements

### Requirement: Init super admin command creates user with random password
The system SHALL provide a CLI command `api-gateway init-super-admin <username>` that creates a super administrator user in the `__system__` tenant with a cryptographically random password.

#### Scenario: Create a new super admin
- **WHEN** `api-gateway init-super-admin admin` is executed with a valid config and the database contains the `__system__` tenant
- **THEN** a user with username `admin` SHALL be created (or updated if already exists) in the `__system__` tenant with display name `Super Admin` and status active
- **AND** a password credential SHALL be created for this user with a bcrypt-hashed random password
- **AND** the `system_admin` role SHALL be assigned to this user
- **AND** the username and generated password SHALL be printed to stdout
- **AND** the command SHALL exit with code 0

#### Scenario: Password format
- **WHEN** `api-gateway init-super-admin` generates a password
- **THEN** the password SHALL be at least 16 characters long
- **AND** the password SHALL contain at least one uppercase letter, one lowercase letter, and one digit

#### Scenario: Password not logged
- **WHEN** `api-gateway init-super-admin` runs
- **THEN** the generated password SHALL NOT be written to any log file
- **AND** the bcrypt hash SHALL be stored in the database, not the plaintext password

#### Scenario: Database not migrated
- **WHEN** `api-gateway init-super-admin admin` is executed before `api-gateway migrate`
- **THEN** the command SHALL print an error indicating that the database schema is not ready
- **AND** exit with a non-zero code

#### Scenario: System tenant missing
- **WHEN** `api-gateway init-super-admin admin` is executed but the `__system__` tenant does not exist
- **THEN** the command SHALL print an error indicating the system tenant is missing
- **AND** exit with a non-zero code

### Requirement: Init super admin is idempotent
The command SHALL be safe to run multiple times. If the user already exists, it SHALL update the password and reassign the role.

#### Scenario: Re-run overwrites password
- **WHEN** `api-gateway init-super-admin admin` is executed and the user `admin` already exists in `__system__`
- **THEN** a new password SHALL be generated and the existing password credential SHALL be updated
- **AND** the `system_admin` role SHALL remain assigned (no duplicate assignment)

### Requirement: Init super admin respects config file flag
The system SHALL support the `-c` / `--config` flag on the `init-super-admin` command.

#### Scenario: Custom config path
- **WHEN** `api-gateway init-super-admin admin -c /path/to/config.yaml` is executed
- **THEN** the command SHALL read database configuration from `/path/to/config.yaml`
