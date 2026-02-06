CREATE EXTENSION IF NOT EXISTS "pgcrypto";

CREATE TABLE users (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    public_key  BYTEA NOT NULL UNIQUE,
    auth_token  BYTEA NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE blobs (
    hash        BYTEA PRIMARY KEY CHECK (octet_length(hash) = 32),
    data        BYTEA NOT NULL,
    size        INTEGER NOT NULL CHECK (size > 0),
    user_id     UUID NOT NULL REFERENCES users(id),
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE manifests (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id     UUID NOT NULL REFERENCES users(id),
    data        BYTEA NOT NULL,
    merkle_root BYTEA NOT NULL CHECK (octet_length(merkle_root) = 32),
    version     BIGINT NOT NULL DEFAULT 1,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_blobs_user_id ON blobs(user_id);
CREATE INDEX idx_manifests_user_id ON manifests(user_id);
CREATE INDEX idx_manifests_merkle_root ON manifests(merkle_root);
