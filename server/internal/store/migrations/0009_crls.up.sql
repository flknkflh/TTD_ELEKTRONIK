-- Accepted CRLs. The newest row is the CRL the server serves at
-- /public/ca/crl.pem and checks signatures against, so revocations survive a
-- restart or redeploy (the CRL used to live only in memory). Older rows stay
-- as history. The API accepts only a CRL signed by its CA and newer than the
-- active one, so insertion order is CRL-number order.
CREATE TABLE IF NOT EXISTS crls (
    id          BIGSERIAL PRIMARY KEY,
    crl_number  TEXT NOT NULL UNIQUE,
    this_update TIMESTAMPTZ NOT NULL,
    next_update TIMESTAMPTZ,
    entries     INTEGER NOT NULL DEFAULT 0,
    pem         BYTEA NOT NULL,
    source      TEXT NOT NULL DEFAULT '',
    imported_by TEXT NOT NULL DEFAULT '',
    imported_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
