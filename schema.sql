CREATE TABLE IF NOT EXISTS organizations (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    name text NOT NULL CHECK (length(btrim(name)) BETWEEN 1 AND 200),
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS users (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id uuid NOT NULL REFERENCES organizations(id),
    email text NOT NULL,
    display_name text NOT NULL CHECK (length(btrim(display_name)) BETWEEN 1 AND 200),
    password_hash text NOT NULL,
    role text NOT NULL CHECK (role IN ('owner','compliance','viewer')),
    active boolean NOT NULL DEFAULT true,
    created_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (organization_id, email)
);
CREATE UNIQUE INDEX IF NOT EXISTS users_email_ci ON users (lower(email));

CREATE TABLE IF NOT EXISTS sessions (
    token_hash bytea PRIMARY KEY,
    user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    csrf_token text NOT NULL,
    expires_at timestamptz NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS sessions_expires_at ON sessions(expires_at);

CREATE TABLE IF NOT EXISTS deals (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id uuid NOT NULL REFERENCES organizations(id),
    version integer NOT NULL DEFAULT 1,
    status text NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','attention','reviewed')),
    company text NOT NULL, counterparty text NOT NULL, country text NOT NULL,
    registration text NOT NULL, beneficiary text NOT NULL DEFAULT '', contract text NOT NULL,
    direction text NOT NULL CHECK (direction IN ('import','export')), purpose text NOT NULL,
    amount numeric(23,8) NOT NULL CHECK (amount > 0), asset text NOT NULL,
    network text NOT NULL, wallet text NOT NULL DEFAULT '', operator text NOT NULL DEFAULT '',
    created_by uuid NOT NULL REFERENCES users(id),
    created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS deals_organization_created ON deals(organization_id, created_at DESC);

CREATE TABLE IF NOT EXISTS deal_checks (
    organization_id uuid NOT NULL REFERENCES organizations(id),
    deal_id uuid NOT NULL REFERENCES deals(id) ON DELETE CASCADE,
    key text NOT NULL CHECK (key IN ('kyb','sanctions','wallet','funds','legal','documents')),
    status text NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','verified','flagged')),
    evidence text NOT NULL DEFAULT '',
    reviewer_id uuid REFERENCES users(id),
    reviewer_name text NOT NULL DEFAULT '',
    updated_at timestamptz,
    PRIMARY KEY (deal_id, key)
);
CREATE INDEX IF NOT EXISTS deal_checks_tenant ON deal_checks(organization_id, deal_id);

CREATE TABLE IF NOT EXISTS audit_events (
    id bigserial PRIMARY KEY,
    organization_id uuid NOT NULL REFERENCES organizations(id),
    deal_id uuid NOT NULL REFERENCES deals(id) ON DELETE CASCADE,
    actor_id uuid NOT NULL REFERENCES users(id),
    actor_name text NOT NULL,
    action text NOT NULL,
    detail text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS audit_events_deal ON audit_events(organization_id, deal_id, id);

CREATE TABLE IF NOT EXISTS screening_runs (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id uuid NOT NULL REFERENCES organizations(id),
    deal_id uuid NOT NULL REFERENCES deals(id) ON DELETE CASCADE,
    provider text NOT NULL,
    subject text NOT NULL,
    status text NOT NULL CHECK (status IN ('clear','match','error')),
    response_hash text NOT NULL,
    response_json jsonb,
    error_message text NOT NULL DEFAULT '',
    requested_by uuid NOT NULL REFERENCES users(id),
    created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS screening_runs_deal ON screening_runs(organization_id, deal_id, created_at DESC);
