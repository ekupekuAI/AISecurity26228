/**
 * Adversarial tests for the audit ledger.
 *
 * The ledger's whole value is that database manipulation cannot silently produce a valid
 * history. These tests prove it two ways: the SQLite triggers refuse UPDATE and DELETE
 * outright, and -- when the triggers are forcibly dropped to simulate an attacker with raw
 * database access -- verification still fails closed on a modified field, a blanked hash, a
 * broken signature and a sequence gap, naming the first broken block.
 *
 * The database is redirected to a throwaway directory before any module that opens it is
 * imported.
 */

import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { test } from 'node:test';

const scratch = fs.mkdtempSync(path.join(os.tmpdir(), 'tv-audit-test-'));
process.env.AIA_DATA_DIR = scratch;

const { appendAuditEvent, verifyAuditChain } = await import('./audit.js');
const { db } = await import('./index.js');

const NO_UPDATE = `CREATE TRIGGER IF NOT EXISTS audit_events_no_update BEFORE UPDATE ON audit_events BEGIN SELECT RAISE(ABORT, 'audit_events is append-only: UPDATE is not permitted'); END;`;

function seed(n: number): void {
  for (let i = 0; i < n; i += 1) {
    appendAuditEvent({
      eventType: 'TEST_EVENT',
      assetName: `asset-${i}`,
      assetHash: 'a'.repeat(64),
      severity: 'INFO',
      actor: 'tester',
      description: `event number ${i}`,
      metadata: { i },
    });
  }
}

/** Run `fn` with the append-only UPDATE trigger removed, then restore it. */
function withoutUpdateTrigger<T>(fn: () => T): T {
  db.exec('DROP TRIGGER IF EXISTS audit_events_no_update');
  try {
    return fn();
  } finally {
    db.exec(NO_UPDATE);
  }
}

test('a freshly written chain verifies and every block is signed', () => {
  seed(3);
  const result = verifyAuditChain();
  assert.equal(result.valid, true, result.details);
  assert.ok(result.chainLength >= 3);
  // Ed25519 is always available in Node 22, so signing must have happened.
  assert.equal(result.signedBlocks, result.chainLength);
  assert.equal(result.signatureFailures, 0);
});

test('the append-only trigger refuses a direct UPDATE', () => {
  assert.throws(() => db.prepare(`UPDATE audit_events SET description = 'x' WHERE sequence = 1`).run());
});

test('the append-only trigger refuses a direct DELETE', () => {
  assert.throws(() => db.prepare(`DELETE FROM audit_events WHERE sequence = 1`).run());
});

test('a modified field is caught even when the trigger is bypassed', () => {
  const row = db.prepare(`SELECT sequence, description FROM audit_events ORDER BY sequence ASC LIMIT 1 OFFSET 1`).get() as {
    sequence: number;
    description: string;
  };
  withoutUpdateTrigger(() => {
    db.prepare(`UPDATE audit_events SET description = ? WHERE sequence = ?`).run('SILENTLY REWRITTEN', row.sequence);
    const broken = verifyAuditChain();
    assert.equal(broken.valid, false);
    assert.equal(broken.firstBrokenBlock?.sequence, row.sequence);
    assert.match(broken.firstBrokenBlock?.reason ?? '', /content was modified/);
    // Restore and confirm the chain heals -- proving the break was the edit, not the test.
    db.prepare(`UPDATE audit_events SET description = ? WHERE sequence = ?`).run(row.description, row.sequence);
  });
  assert.equal(verifyAuditChain().valid, true);
});

test('a blanked hash column is a break, not a skipped row (fail-closed)', () => {
  const row = db.prepare(`SELECT sequence, current_hash FROM audit_events ORDER BY sequence ASC LIMIT 1 OFFSET 1`).get() as {
    sequence: number;
    current_hash: string;
  };
  withoutUpdateTrigger(() => {
    db.prepare(`UPDATE audit_events SET current_hash = '' WHERE sequence = ?`).run(row.sequence);
    const broken = verifyAuditChain();
    assert.equal(broken.valid, false);
    assert.match(broken.firstBrokenBlock?.reason ?? '', /missing or malformed/);
    db.prepare(`UPDATE audit_events SET current_hash = ? WHERE sequence = ?`).run(row.current_hash, row.sequence);
  });
  assert.equal(verifyAuditChain().valid, true);
});

test('a forged signature (content intact) is rejected', () => {
  const row = db.prepare(`SELECT sequence, signature FROM audit_events WHERE signature IS NOT NULL ORDER BY sequence ASC LIMIT 1`).get() as {
    sequence: number;
    signature: string;
  };
  const wrong = Buffer.alloc(64, 7).toString('base64'); // valid length, wrong bytes
  withoutUpdateTrigger(() => {
    db.prepare(`UPDATE audit_events SET signature = ? WHERE sequence = ?`).run(wrong, row.sequence);
    const broken = verifyAuditChain();
    assert.equal(broken.valid, false);
    assert.match(broken.firstBrokenBlock?.reason ?? '', /signature does not verify/);
    db.prepare(`UPDATE audit_events SET signature = ? WHERE sequence = ?`).run(row.signature, row.sequence);
  });
  assert.equal(verifyAuditChain().valid, true);
});

test('a sequence gap is a break', () => {
  const rows = db.prepare(`SELECT sequence FROM audit_events ORDER BY sequence ASC`).all() as Array<{ sequence: number }>;
  const target = rows[1].sequence;
  withoutUpdateTrigger(() => {
    db.prepare(`UPDATE audit_events SET sequence = 9999 WHERE sequence = ?`).run(target);
    const broken = verifyAuditChain();
    assert.equal(broken.valid, false);
    assert.match(broken.firstBrokenBlock?.reason ?? '', /sequence gap/);
    db.prepare(`UPDATE audit_events SET sequence = ? WHERE sequence = 9999`).run(target);
  });
  assert.equal(verifyAuditChain().valid, true);
});

test('inference records reject in-place edits of the sealed columns', () => {
  const now = new Date().toISOString();
  db.prepare(
    `INSERT INTO inference_records (record_id, input_hash, model_identifier, model_hash, prediction, timestamp, nonce, record_hash, status, created_at)
     VALUES ('REC-1','h','m','mh','STOP',?, 'n1','rh','VERIFIED',?)`
  ).run(now, now);
  assert.throws(() => db.prepare(`UPDATE inference_records SET prediction = 'GO' WHERE record_id = 'REC-1'`).run());
  // Status alone may move (VERIFIED -> TAMPERED), which is how a re-verification is recorded.
  assert.doesNotThrow(() => db.prepare(`UPDATE inference_records SET status = 'TAMPERED' WHERE record_id = 'REC-1'`).run());
});
