CREATE TABLE IF NOT EXISTS tenants (
    id          BIGSERIAL PRIMARY KEY,
    uuid        UUID NOT NULL UNIQUE DEFAULT gen_random_uuid(),
    code        VARCHAR(64) NOT NULL UNIQUE,
    name        VARCHAR(256) NOT NULL,
    status      SMALLINT NOT NULL DEFAULT 1,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS tenant_domains (
    id          BIGSERIAL PRIMARY KEY,
    tenant_id   BIGINT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    pattern     VARCHAR(512) NOT NULL,
    is_wildcard BOOLEAN NOT NULL DEFAULT false,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE(pattern)
);

CREATE INDEX IF NOT EXISTS idx_tenant_domains_tenant_id ON tenant_domains(tenant_id);

CREATE TABLE IF NOT EXISTS users (
    id          BIGSERIAL PRIMARY KEY,
    uuid        UUID NOT NULL UNIQUE DEFAULT gen_random_uuid(),
    tenant_id   BIGINT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    username    VARCHAR(128) NOT NULL,
    display_name VARCHAR(256),
    email       VARCHAR(256),
    phone       VARCHAR(32),
    status      SMALLINT NOT NULL DEFAULT 1,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE(tenant_id, username)
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_users_tenant_email
    ON users(tenant_id, email) WHERE email IS NOT NULL;
CREATE UNIQUE INDEX IF NOT EXISTS idx_users_tenant_phone
    ON users(tenant_id, phone) WHERE phone IS NOT NULL;

CREATE TABLE IF NOT EXISTS user_credentials (
    id              BIGSERIAL PRIMARY KEY,
    user_id         BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    tenant_id       BIGINT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    provider_type   VARCHAR(32) NOT NULL,
    credential      TEXT,
    identifier      VARCHAR(256),
    metadata        JSONB,
    status          SMALLINT NOT NULL DEFAULT 1,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE(user_id, tenant_id, provider_type)
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_credentials_oauth_lookup
    ON user_credentials(tenant_id, provider_type, identifier)
    WHERE identifier IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_user_credentials_user_id ON user_credentials(user_id);
CREATE INDEX IF NOT EXISTS idx_user_credentials_tenant_id ON user_credentials(tenant_id);