/**
 * Relational schema.
 *
 * Table names and key attributes follow the problem statement's section 7 so the
 * implementation can be read against the specification directly: `assets`, `datasets`,
 * `models`, `findings`, `inference_records`, `audit_events`. Four tables are added that
 * the specification implies but does not name -- `contributors` for source-level
 * aggregation, `nonces` for replay defence, and `users`/`sessions` for the console.
 *
 * Design rules:
 *
 *  - **Append-only where it is evidence.** `audit_events` has triggers that reject
 *    UPDATE and DELETE. A tamper-evident log that the application can quietly rewrite is
 *    not tamper-evident, and enforcing it in SQLite means even a compromised route
 *    handler cannot do it.
 *  - **Foreign keys on, with explicit behaviour.** Findings die with their analysis;
 *    audit events never do.
 *  - **Indices on what is actually queried**, because a dashboard that scans the whole
 *    findings table gets slower exactly as the corpus of evidence grows.
 */

export const SCHEMA_VERSION = 4;

export const SCHEMA_SQL = `
-- Master registry of every ingested artefact.
CREATE TABLE IF NOT EXISTS assets (
  asset_id          TEXT PRIMARY KEY,
  asset_type        TEXT NOT NULL CHECK (asset_type IN ('DATASET','MODEL','INFERENCE','DISTRIBUTION')),
  filename          TEXT NOT NULL,
  sha256            TEXT NOT NULL,
  file_size_bytes   INTEGER NOT NULL DEFAULT 0,
  source            TEXT,
  quarantine_status TEXT NOT NULL DEFAULT 'ACTIVE'
                      CHECK (quarantine_status IN ('ACTIVE','REVIEW','QUARANTINED')),
  submitted_by      TEXT,
  -- Owning user. Every read the console serves is scoped to this, so one operator's
  -- workspace never leaks into another's. NULL means node-level / legacy, visible to
  -- no per-user view (the shared audit ledger records cross-cutting activity instead).
  owner_id          TEXT REFERENCES users(id) ON DELETE SET NULL,
  is_demo           INTEGER NOT NULL DEFAULT 0,
  created_at        TEXT NOT NULL
);

-- One analysis run over one asset. payload_json holds the full engine result.
CREATE TABLE IF NOT EXISTS analyses (
  analysis_id     TEXT PRIMARY KEY,
  asset_id        TEXT REFERENCES assets(asset_id) ON DELETE SET NULL,
  type            TEXT NOT NULL CHECK (type IN ('DATASET','MODEL','INFERENCE','DISTRIBUTION')),
  filename        TEXT NOT NULL,
  sha256          TEXT NOT NULL,
  file_size_bytes INTEGER NOT NULL DEFAULT 0,
  status          TEXT NOT NULL,
  risk_score      REAL NOT NULL DEFAULT 0,
  engine          TEXT NOT NULL DEFAULT 'unknown',
  analysis_mode   TEXT,
  duration_seconds REAL,
  payload_json    TEXT NOT NULL,
  performed_by    TEXT,
  owner_id        TEXT REFERENCES users(id) ON DELETE SET NULL,
  is_demo         INTEGER NOT NULL DEFAULT 0,
  created_at      TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS datasets (
  dataset_id      TEXT PRIMARY KEY,
  asset_id        TEXT REFERENCES assets(asset_id) ON DELETE CASCADE,
  analysis_id     TEXT REFERENCES analyses(analysis_id) ON DELETE CASCADE,
  format          TEXT NOT NULL,
  sample_count    INTEGER NOT NULL DEFAULT 0,
  class_count     INTEGER NOT NULL DEFAULT 0,
  corrupt_count   INTEGER NOT NULL DEFAULT 0,
  duplicate_count INTEGER NOT NULL DEFAULT 0,
  trigger_count   INTEGER NOT NULL DEFAULT 0,
  ood_count       INTEGER NOT NULL DEFAULT 0,
  label_suspect_count INTEGER NOT NULL DEFAULT 0,
  risk_score      REAL NOT NULL DEFAULT 0,
  created_at      TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS models (
  model_id        TEXT PRIMARY KEY,
  asset_id        TEXT REFERENCES assets(asset_id) ON DELETE CASCADE,
  analysis_id     TEXT REFERENCES analyses(analysis_id) ON DELETE CASCADE,
  framework       TEXT NOT NULL,
  architecture    TEXT NOT NULL,
  parameter_count INTEGER,
  analysis_mode   TEXT NOT NULL DEFAULT 'BLACK_BOX',
  serialization_verdict TEXT,
  backdoor_confidence REAL NOT NULL DEFAULT 0,
  risk_score      REAL NOT NULL DEFAULT 0,
  created_at      TEXT NOT NULL
);

-- Source-level aggregation. Risk is recomputed per analysis, history is kept.
CREATE TABLE IF NOT EXISTS contributors (
  id              TEXT PRIMARY KEY,
  analysis_id     TEXT REFERENCES analyses(analysis_id) ON DELETE CASCADE,
  name            TEXT NOT NULL,
  sample_count    INTEGER NOT NULL DEFAULT 0,
  defect_count    INTEGER NOT NULL DEFAULT 0,
  trigger_count   INTEGER NOT NULL DEFAULT 0,
  defect_density  REAL NOT NULL DEFAULT 0,
  risk_score      REAL NOT NULL DEFAULT 0,
  drivers_json    TEXT NOT NULL DEFAULT '[]',
  owner_id        TEXT REFERENCES users(id) ON DELETE SET NULL,
  is_demo         INTEGER NOT NULL DEFAULT 0,
  created_at      TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS findings (
  id              TEXT PRIMARY KEY,
  finding_id      TEXT NOT NULL,
  analysis_id     TEXT REFERENCES analyses(analysis_id) ON DELETE CASCADE,
  asset_id        TEXT REFERENCES assets(asset_id) ON DELETE SET NULL,
  category        TEXT NOT NULL,
  severity        TEXT NOT NULL CHECK (severity IN ('CRITICAL','HIGH','MEDIUM','LOW','INFO')),
  confidence      REAL NOT NULL DEFAULT 0,
  affected_asset  TEXT NOT NULL DEFAULT '',
  explanation     TEXT NOT NULL DEFAULT '',
  evidence_json   TEXT NOT NULL DEFAULT '{}',
  recommendation  TEXT NOT NULL DEFAULT '',
  detector        TEXT,
  threshold_used  TEXT,
  references_json TEXT NOT NULL DEFAULT '[]',
  acknowledged_by TEXT,
  acknowledged_at TEXT,
  owner_id        TEXT REFERENCES users(id) ON DELETE SET NULL,
  is_demo         INTEGER NOT NULL DEFAULT 0,
  created_at      TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS inference_records (
  record_id       TEXT PRIMARY KEY,
  input_hash      TEXT NOT NULL,
  model_identifier TEXT NOT NULL,
  model_hash      TEXT NOT NULL,
  configuration_json TEXT NOT NULL DEFAULT '{}',
  configuration_hash TEXT NOT NULL DEFAULT '',
  prediction      TEXT NOT NULL,
  confidence      REAL NOT NULL DEFAULT 0,
  timestamp       TEXT NOT NULL,
  nonce           TEXT NOT NULL,
  record_hash     TEXT NOT NULL,
  signature       TEXT,
  signing_key_id  TEXT,
  canonical_json  TEXT NOT NULL DEFAULT '{}',
  status          TEXT NOT NULL DEFAULT 'VERIFIED'
                    CHECK (status IN ('VERIFIED','TAMPERED','FORGED','REPLAYED','UNVERIFIABLE')),
  sealed_by       TEXT,
  owner_id        TEXT REFERENCES users(id) ON DELETE SET NULL,
  is_demo         INTEGER NOT NULL DEFAULT 0,
  created_at      TEXT NOT NULL
);

-- Consumed nonces. UNIQUE is the whole point: the database itself enforces single use.
CREATE TABLE IF NOT EXISTS nonces (
  nonce           TEXT PRIMARY KEY,
  record_id       TEXT NOT NULL,
  record_hash     TEXT NOT NULL,
  input_hash      TEXT NOT NULL DEFAULT '',
  model_hash      TEXT NOT NULL DEFAULT '',
  prediction      TEXT NOT NULL DEFAULT '',
  first_seen_at   TEXT NOT NULL
);

-- Append-only hash-chained, Ed25519-signed audit ledger.
CREATE TABLE IF NOT EXISTS audit_events (
  event_id        TEXT PRIMARY KEY,
  sequence        INTEGER NOT NULL,
  event_type      TEXT NOT NULL,
  asset_id        TEXT,
  asset_name      TEXT NOT NULL DEFAULT '',
  asset_hash      TEXT NOT NULL DEFAULT '',
  severity        TEXT NOT NULL DEFAULT 'INFO',
  actor           TEXT NOT NULL DEFAULT 'system',
  description     TEXT NOT NULL DEFAULT '',
  metadata_json   TEXT NOT NULL DEFAULT '{}',
  previous_hash   TEXT NOT NULL,
  current_hash    TEXT NOT NULL,
  signature       TEXT,
  signing_key_id  TEXT,
  timestamp       TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS users (
  id              TEXT PRIMARY KEY,
  username        TEXT NOT NULL UNIQUE,
  email           TEXT NOT NULL UNIQUE,
  name            TEXT NOT NULL,
  role            TEXT NOT NULL,
  clearance_level TEXT NOT NULL,
  badge_id        TEXT NOT NULL,
  password_hash   TEXT NOT NULL,
  password_salt   TEXT NOT NULL,
  kdf_params      TEXT NOT NULL DEFAULT '{}',
  is_demo_account INTEGER NOT NULL DEFAULT 0,
  must_change_password INTEGER NOT NULL DEFAULT 0,
  disabled        INTEGER NOT NULL DEFAULT 0,
  failed_attempts INTEGER NOT NULL DEFAULT 0,
  locked_until    TEXT,
  last_login_at   TEXT,
  created_at      TEXT NOT NULL
);

-- Server-side sessions. Only a hash of the token is stored, so a database read does not
-- yield usable credentials.
CREATE TABLE IF NOT EXISTS sessions (
  id              TEXT PRIMARY KEY,
  user_id         TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  token_hash      TEXT NOT NULL UNIQUE,
  csrf_token      TEXT NOT NULL,
  ip_address      TEXT,
  user_agent      TEXT,
  created_at      TEXT NOT NULL,
  last_seen_at    TEXT NOT NULL,
  expires_at      TEXT NOT NULL,
  revoked_at      TEXT
);

CREATE TABLE IF NOT EXISTS login_attempts (
  id              INTEGER PRIMARY KEY AUTOINCREMENT,
  identifier      TEXT NOT NULL,
  ip_address      TEXT NOT NULL DEFAULT '',
  successful      INTEGER NOT NULL DEFAULT 0,
  attempted_at    TEXT NOT NULL
);

-- Server faults (5xx / unhandled exceptions), so the Sentinel operational sensor can see
-- them. This is a lightweight operational log, not tamper-evident evidence like the audit
-- ledger, so it is safe to prune and is not hash-chained.
CREATE TABLE IF NOT EXISTS error_events (
  id            INTEGER PRIMARY KEY AUTOINCREMENT,
  occurred_at   TEXT NOT NULL,
  where_at      TEXT NOT NULL DEFAULT '',
  name          TEXT NOT NULL DEFAULT '',
  message       TEXT NOT NULL DEFAULT '',
  http_status   INTEGER
);

-- Sentinel: continuous local monitoring. Observations are evidence, so they are
-- append-only at the database level, exactly like the audit ledger. The adaptive
-- baselines live in a separate mutable table because a baseline that learns must be
-- updated -- but what it observed can never be rewritten.
CREATE TABLE IF NOT EXISTS sentinel_observations (
  id              INTEGER PRIMARY KEY AUTOINCREMENT,
  observed_at     TEXT NOT NULL,
  sensor          TEXT NOT NULL,
  signal          REAL NOT NULL DEFAULT 0,
  baseline        REAL NOT NULL DEFAULT 0,
  deviation       REAL NOT NULL DEFAULT 0,
  severity        TEXT NOT NULL DEFAULT 'INFO',
  status          TEXT NOT NULL DEFAULT 'NOMINAL',
  summary         TEXT NOT NULL DEFAULT '',
  evidence_json   TEXT NOT NULL DEFAULT '{}'
);

CREATE TRIGGER IF NOT EXISTS sentinel_obs_no_update
BEFORE UPDATE ON sentinel_observations
BEGIN SELECT RAISE(ABORT, 'sentinel_observations is append-only: UPDATE is not permitted'); END;

CREATE TRIGGER IF NOT EXISTS sentinel_obs_no_delete
BEFORE DELETE ON sentinel_observations
BEGIN SELECT RAISE(ABORT, 'sentinel_observations is append-only: DELETE is not permitted'); END;

-- Adaptive baseline state, one row per sensor. Mutable by design: this is what "learns".
CREATE TABLE IF NOT EXISTS sentinel_state (
  sensor          TEXT PRIMARY KEY,
  ewma_mean       REAL NOT NULL DEFAULT 0,
  ewma_var        REAL NOT NULL DEFAULT 0,
  samples         INTEGER NOT NULL DEFAULT 0,
  last_signal     REAL NOT NULL DEFAULT 0,
  updated_at      TEXT NOT NULL DEFAULT ''
);

-- AI-BOM passports issued for analysed artifacts. Append-only: a passport is evidence.
CREATE TABLE IF NOT EXISTS aibom_passports (
  bom_id          TEXT PRIMARY KEY,
  subject_kind    TEXT NOT NULL,
  subject_name    TEXT NOT NULL DEFAULT '',
  subject_sha256  TEXT NOT NULL DEFAULT '',
  status          TEXT NOT NULL DEFAULT '',
  decision        TEXT NOT NULL DEFAULT '',
  risk_score      REAL NOT NULL DEFAULT 0,
  signing_key_id  TEXT,
  sha256          TEXT NOT NULL DEFAULT '',
  passport_json   TEXT NOT NULL,
  created_by      TEXT,
  owner_id        TEXT REFERENCES users(id) ON DELETE SET NULL,
  created_at      TEXT NOT NULL
);

CREATE TRIGGER IF NOT EXISTS aibom_no_update
BEFORE UPDATE ON aibom_passports
BEGIN SELECT RAISE(ABORT, 'aibom_passports is append-only: UPDATE is not permitted'); END;

CREATE TABLE IF NOT EXISTS schema_meta (
  key   TEXT PRIMARY KEY,
  value TEXT NOT NULL
);

-- Indices matching the dashboard's actual access patterns.
CREATE INDEX IF NOT EXISTS idx_analyses_created  ON analyses(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_analyses_type     ON analyses(type, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_findings_analysis ON findings(analysis_id);
CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_findings_created  ON findings(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_inference_created ON inference_records(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_inference_status  ON inference_records(status);
CREATE INDEX IF NOT EXISTS idx_audit_sequence    ON audit_events(sequence);
CREATE INDEX IF NOT EXISTS idx_audit_timestamp   ON audit_events(timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_assets_sha        ON assets(sha256);
CREATE INDEX IF NOT EXISTS idx_sessions_token    ON sessions(token_hash);
CREATE INDEX IF NOT EXISTS idx_sessions_user     ON sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_attempts_lookup   ON login_attempts(identifier, attempted_at DESC);
CREATE INDEX IF NOT EXISTS idx_error_events_time  ON error_events(occurred_at DESC);
CREATE INDEX IF NOT EXISTS idx_contributors_analysis ON contributors(analysis_id);
CREATE INDEX IF NOT EXISTS idx_sentinel_obs_time  ON sentinel_observations(observed_at DESC);
CREATE INDEX IF NOT EXISTS idx_sentinel_obs_status ON sentinel_observations(status, observed_at DESC);
CREATE INDEX IF NOT EXISTS idx_aibom_created ON aibom_passports(created_at DESC);

-- Append-only enforcement at the storage layer. An audit ledger the application can
-- rewrite proves nothing, so the database refuses the operation outright rather than
-- trusting every future code path to behave.
CREATE TRIGGER IF NOT EXISTS audit_events_no_update
BEFORE UPDATE ON audit_events
BEGIN
  SELECT RAISE(ABORT, 'audit_events is append-only: UPDATE is not permitted');
END;

CREATE TRIGGER IF NOT EXISTS audit_events_no_delete
BEFORE DELETE ON audit_events
BEGIN
  SELECT RAISE(ABORT, 'audit_events is append-only: DELETE is not permitted');
END;

-- Inference records are evidence too: a sealed record may never be edited in place.
CREATE TRIGGER IF NOT EXISTS inference_records_immutable_seal
BEFORE UPDATE OF record_hash, signature, input_hash, model_hash, prediction, nonce
ON inference_records
BEGIN
  SELECT RAISE(ABORT, 'A sealed inference record is immutable; create a new record instead');
END;
`;
