-- TOTP second factor for the admin console (admin + superadmin only; end
-- users are never asked). Brings back what 0004 dropped, now with replay
-- protection (last_step) and single-use recovery codes stored as hashes.
CREATE TABLE IF NOT EXISTS admin_mfa (
    account_id TEXT PRIMARY KEY REFERENCES accounts(id) ON DELETE CASCADE,
    secret     TEXT NOT NULL,
    confirmed  BOOLEAN NOT NULL DEFAULT FALSE,
    last_step  BIGINT NOT NULL DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS admin_mfa_recovery (
    account_id TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    code_hash  TEXT NOT NULL,
    used_at    TIMESTAMPTZ,
    PRIMARY KEY (account_id, code_hash)
);
