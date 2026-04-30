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
