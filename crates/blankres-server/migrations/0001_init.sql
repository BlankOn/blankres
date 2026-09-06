-- Initial schema. Applied at startup by the server itself; see `db::migrate`.

-- One row per distinct crash signature. `payloads` is what the stage-1 decision reads: once
-- enough cores for a signature are stored, further machines are told not to send one.
CREATE TABLE IF NOT EXISTS signatures (
    hash            TEXT PRIMARY KEY,
    precision       TEXT NOT NULL,
    first_seen      TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen       TIMESTAMPTZ NOT NULL DEFAULT now(),
    events          BIGINT NOT NULL DEFAULT 0,
    payloads        BIGINT NOT NULL DEFAULT 0,
    -- Set by an operator for a bug already fixed: no more payloads, however few are stored.
    suppressed      BOOLEAN NOT NULL DEFAULT FALSE,
    executable      TEXT,
    package         TEXT,
    frames          JSONB
);

-- Every stage-1 event. Small rows, high volume.
CREATE TABLE IF NOT EXISTS events (
    id              UUID PRIMARY KEY,
    signature       TEXT NOT NULL REFERENCES signatures(hash),
    received_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    occurred_at     TIMESTAMPTZ NOT NULL,
    kind            TEXT NOT NULL,
    executable      TEXT NOT NULL,
    signal          INTEGER,
    package         TEXT,
    package_version TEXT,
    distro          TEXT,
    distro_version  TEXT,
    architecture    TEXT,
    kernel_version  TEXT,
    machine_id      TEXT NOT NULL,
    crash_count     INTEGER NOT NULL DEFAULT 1,
    client_version  TEXT,
    core_available  BOOLEAN NOT NULL DEFAULT FALSE,
    core_size       BIGINT,
    payload_wanted  BOOLEAN NOT NULL DEFAULT FALSE
);

CREATE INDEX IF NOT EXISTS events_signature_idx ON events (signature);
CREATE INDEX IF NOT EXISTS events_received_idx ON events (received_at DESC);

-- Capabilities handed out with a `need_payload` directive. Single use and time limited, so a
-- client cannot push an unsolicited core dump.
CREATE TABLE IF NOT EXISTS upload_tokens (
    token_hash      TEXT PRIMARY KEY,
    event_id        UUID NOT NULL REFERENCES events(id),
    signature       TEXT NOT NULL REFERENCES signatures(hash),
    max_bytes       BIGINT NOT NULL,
    expires_at      TIMESTAMPTZ NOT NULL,
    redeemed_at     TIMESTAMPTZ
);

-- Stage-2 payloads that actually arrived.
CREATE TABLE IF NOT EXISTS reports (
    id              UUID PRIMARY KEY,
    event_id        UUID NOT NULL REFERENCES events(id),
    signature       TEXT NOT NULL REFERENCES signatures(hash),
    received_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    total_bytes     BIGINT NOT NULL DEFAULT 0,
    metadata        JSONB NOT NULL,
    -- Attachment name -> {sha256, size}, the blobs written to the object store.
    blobs           JSONB NOT NULL DEFAULT '{}'::jsonb
);

CREATE INDEX IF NOT EXISTS reports_signature_idx ON reports (signature);
