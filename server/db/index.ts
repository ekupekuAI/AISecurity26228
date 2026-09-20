/**
 * SQLite connection, pragmas and migration.
 *
 * Uses Node 22's built-in `node:sqlite`, which keeps the deployment free of a native
 * build step -- relevant when the target is an offline node with no compiler.
 *
 * The pragmas are not boilerplate:
 *  - `foreign_keys=ON` because SQLite ignores foreign keys by default, and a schema whose
 *    constraints are decorative is worse than one without them.
 *  - `journal_mode=WAL` so a long dataset analysis writing findings does not block the
 *    dashboard reading them.
 *  - `synchronous=FULL` because this database is evidence: losing the last transaction to
 *    a power cut would break the audit chain, and WAL's default NORMAL permits exactly
 *    that.
 *  - `busy_timeout` so concurrent writers wait rather than throwing SQLITE_BUSY.
 */

import { DatabaseSync } from 'node:sqlite';
import fs from 'node:fs';
import path from 'node:path';
import { CONFIG } from '../config.js';
import { log } from '../logger.js';
import { SCHEMA_SQL, SCHEMA_VERSION } from './schema.js';
import { bindErrorDb } from './errors.js';

fs.mkdirSync(path.dirname(CONFIG.databasePath), { recursive: true });

export const db = new DatabaseSync(CONFIG.databasePath);

db.exec(`
  PRAGMA foreign_keys = ON;
  PRAGMA journal_mode = WAL;
  PRAGMA synchronous = FULL;
  PRAGMA busy_timeout = 10000;
  PRAGMA temp_store = MEMORY;
  PRAGMA cache_size = -32000;
`);

db.exec(SCHEMA_SQL);

// Give the lightweight error log a handle to this connection. Injected rather than imported
// to avoid a cycle (logger -> errors, db -> errors; errors imports nothing).
bindErrorDb(db);

/**
 * Migrate a database created by an earlier build.
 *
 * The first release used a flatter schema with different column names. Rather than
 * silently reinterpreting old rows -- which would produce an audit chain that cannot be
 * verified -- the old tables are archived under a timestamped name and the new schema
 * starts clean. An unverifiable chain is worse than an empty one.
 */
function migrate(): void {
  const current = db.prepare(`SELECT value FROM schema_meta WHERE key = 'schema_version'`).get() as
    | { value: string }
    | undefined;
  const version = current ? Number.parseInt(current.value, 10) : 0;

  if (version === SCHEMA_VERSION) return;

  if (version > 0 && version < SCHEMA_VERSION) {
    log.warn('database schema is from an earlier build', { found: version, expected: SCHEMA_VERSION });
  }

  if (version === 0) {
    const legacy = db
      .prepare(
        `SELECT name FROM sqlite_master WHERE type='table' AND name IN ('analyses','findings','audit_events')`
      )
      .all() as Array<{ name: string }>;

    // A legacy `analyses` table is identified by its old primary-key column name.
    const hasLegacyShape = legacy.some(({ name }) => {
      const columns = db.prepare(`PRAGMA table_info(${name})`).all() as Array<{ name: string }>;
      return name === 'analyses' && columns.some((c) => c.name === 'id') && !columns.some((c) => c.name === 'analysis_id');
    });

    if (hasLegacyShape) {
      const stamp = new Date().toISOString().replace(/[:.]/g, '').slice(0, 15);
      log.warn('archiving legacy tables; their audit chain cannot be verified under the new format', {
        suffix: stamp,
      });
      for (const table of ['analyses', 'findings', 'audit_events', 'inference_records', 'assets', 'users']) {
        try {
          db.exec(`ALTER TABLE ${table} RENAME TO legacy_${table}_${stamp}`);
        } catch {
          // Table absent or already archived.
        }
      }
      db.exec(SCHEMA_SQL);
    }
  }

  // v4: per-user data isolation. Add an owner column to every evidence table so each
  // operator's workspace is scoped to them. Existing rows keep owner_id = NULL and are
  // visible to no per-user view; the node-wide audit ledger and nonce ledger are unchanged.
  // The owner indexes are built here rather than in SCHEMA_SQL because SCHEMA_SQL runs
  // against the old table shape on an upgrade, before this column exists. Table and column
  // names below are compile-time constants, never request input.
  const ensureColumn = (table: string, column: string, decl = 'TEXT'): void => {
    const columns = db.prepare(`PRAGMA table_info(${table})`).all() as Array<{ name: string }>;
    if (!columns.some((c) => c.name === column)) {
      db.exec(`ALTER TABLE ${table} ADD COLUMN ${column} ${decl}`);
    }
  };
  for (const table of ['assets', 'analyses', 'findings', 'contributors', 'inference_records', 'aibom_passports']) {
    ensureColumn(table, 'owner_id');
  }
  db.exec(`
    CREATE INDEX IF NOT EXISTS idx_analyses_owner     ON analyses(owner_id, created_at DESC);
    CREATE INDEX IF NOT EXISTS idx_findings_owner     ON findings(owner_id, created_at DESC);
    CREATE INDEX IF NOT EXISTS idx_assets_owner       ON assets(owner_id);
    CREATE INDEX IF NOT EXISTS idx_contributors_owner ON contributors(owner_id);
    CREATE INDEX IF NOT EXISTS idx_inference_owner    ON inference_records(owner_id, created_at DESC);
    CREATE INDEX IF NOT EXISTS idx_aibom_owner        ON aibom_passports(owner_id, created_at DESC);
  `);

  db.prepare(
    `INSERT INTO schema_meta (key, value) VALUES ('schema_version', ?)
     ON CONFLICT(key) DO UPDATE SET value = excluded.value`
  ).run(String(SCHEMA_VERSION));
}

migrate();

let transactionDepth = 0;

/**
 * Run `fn` atomically, rolling back on any throw.
 *
 * Re-entrant. SQLite has no nested `BEGIN`, and several operations legitimately compose:
 * `saveAnalysis` writes an asset, an analysis, its findings and its contributors, then
 * appends an audit block -- and `appendAuditEvent` is itself atomic because it reads the
 * chain head and writes the next block. Without re-entrancy that inner call throws
 * "cannot start a transaction within a transaction".
 *
 * Nesting is handled with SAVEPOINTs, so an inner failure rolls back only its own work
 * and the outer transaction can still decide what to do. The outermost level uses
 * BEGIN IMMEDIATE to take the write lock up front rather than discovering a conflict
 * halfway through.
 */
export function transaction<T>(fn: () => T): T {
  const depth = transactionDepth;
  const savepoint = `aia_sp_${depth}`;

  if (depth === 0) {
    db.exec('BEGIN IMMEDIATE');
  } else {
    db.exec(`SAVEPOINT ${savepoint}`);
  }
  transactionDepth += 1;

  try {
    const result = fn();
    transactionDepth -= 1;
    if (depth === 0) {
      db.exec('COMMIT');
    } else {
      db.exec(`RELEASE ${savepoint}`);
    }
    return result;
  } catch (error) {
    transactionDepth -= 1;
    try {
      if (depth === 0) {
        db.exec('ROLLBACK');
      } else {
        db.exec(`ROLLBACK TO ${savepoint}`);
        db.exec(`RELEASE ${savepoint}`);
      }
    } catch {
      // A rollback that itself fails must not mask the original error, which is the one
      // that explains what actually went wrong.
    }
    throw error;
  }
}

export function closeDatabase(): void {
  try {
    // Fold the WAL back into the main file so a copied database file is complete.
    db.exec('PRAGMA wal_checkpoint(TRUNCATE)');
    db.close();
  } catch (error) {
    log.warn('database close failed', { error: String(error) });
  }
}

export function databaseStats(): Record<string, number> {
  const count = (table: string): number => {
    try {
      return Number((db.prepare(`SELECT COUNT(*) AS c FROM ${table}`).get() as { c: number }).c);
    } catch {
      return 0;
    }
  };
  return {
    assets: count('assets'),
    analyses: count('analyses'),
    findings: count('findings'),
    inferenceRecords: count('inference_records'),
    auditEvents: count('audit_events'),
    contributors: count('contributors'),
    users: count('users'),
    activeSessions: count('sessions'),
  };
}
