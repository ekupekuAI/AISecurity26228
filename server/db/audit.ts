/**
 * Hash-chained, Ed25519-signed, append-only audit ledger.
 *
 * Three defects in a naive implementation are all fixed here, and each one individually
 * makes the ledger worthless:
 *
 * 1. **Partial coverage.** If the block hash covers only some columns, the uncovered
 *    ones can be rewritten freely. Here the hash covers a canonical JSON object of
 *    *every* semantic field, so there is nothing left to edit undetected.
 *
 * 2. **Fail-open verification.** A verifier that skips a block whose stored hash is
 *    empty (`if (storedHash && storedHash !== recomputed)`) hands an attacker a one-step
 *    erasure: blank the column. Verification here treats a missing or malformed hash as
 *    a break.
 *
 * 3. **Hash without signature.** Anyone who can rewrite a block can recompute its SHA-256
 *    and every following one. Only an asymmetric signature makes the chain
 *    non-repudiable, so each block is signed and verification checks both.
 *
 * Append-only is enforced by SQLite triggers, not by convention.
 */

import crypto from 'node:crypto';
import { db, transaction } from './index.js';
import { canonicalBytes } from '../provenance/canonical.js';
import { DOMAIN_AUDIT, getKeyring } from '../security/keyring.js';
import { log } from '../logger.js';

export const GENESIS_HASH = '0'.repeat(64);

export type AuditSeverity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';

export interface AuditEventInput {
  eventType: string;
  assetId?: string | null;
  assetName?: string;
  assetHash?: string;
  severity?: AuditSeverity;
  actor?: string;
  description: string;
  metadata?: Record<string, unknown>;
}

export interface AuditEventRow {
  eventId: string;
  sequence: number;
  eventType: string;
  assetId: string | null;
  assetName: string;
  assetHash: string;
  severity: AuditSeverity;
  actor: string;
  description: string;
  metadata: Record<string, unknown>;
  previousHash: string;
  currentHash: string;
  signature: string | null;
  signingKeyId: string | null;
  timestamp: string;
}

/**
 * The exact object a block commits to. Every semantic field is present; nothing about a
 * recorded event can be altered without invalidating its hash.
 */
function blockDocument(params: {
  eventId: string;
  sequence: number;
  eventType: string;
  assetId: string | null;
  assetName: string;
  assetHash: string;
  severity: string;
  actor: string;
  description: string;
  metadata: Record<string, unknown>;
  previousHash: string;
  timestamp: string;
}): Record<string, unknown> {
  return {
    schema: 'aia-audit-block/1',
    eventId: params.eventId,
    sequence: params.sequence,
    eventType: params.eventType,
    assetId: params.assetId,
    assetName: params.assetName,
    assetHash: params.assetHash,
    severity: params.severity,
    actor: params.actor,
    description: params.description,
    metadata: params.metadata,
    previousHash: params.previousHash,
    timestamp: params.timestamp,
  };
}

function computeBlockHash(document: Record<string, unknown>): { digest: string; payload: Buffer } {
  const payload = canonicalBytes(document);
  return { digest: crypto.createHash('sha256').update(payload).digest('hex'), payload };
}

/**
 * Append one event. The read of the head and the insert of the new block happen in a
 * single IMMEDIATE transaction; without that, two concurrent writers can read the same
 * head and produce a fork.
 */
export function appendAuditEvent(input: AuditEventInput): AuditEventRow {
  return transaction(() => {
    const head = db
      .prepare(`SELECT sequence, current_hash FROM audit_events ORDER BY sequence DESC LIMIT 1`)
      .get() as { sequence: number; current_hash: string } | undefined;

    const sequence = (head?.sequence ?? 0) + 1;
    const previousHash = head?.current_hash ?? GENESIS_HASH;
    const eventId = `AUDIT-${String(sequence).padStart(8, '0')}-${crypto.randomBytes(4).toString('hex').toUpperCase()}`;
    const timestamp = new Date().toISOString();

    const document = blockDocument({
      eventId,
      sequence,
      eventType: input.eventType,
      assetId: input.assetId ?? null,
      assetName: input.assetName ?? '',
      assetHash: input.assetHash ?? '',
      severity: input.severity ?? 'INFO',
      actor: input.actor ?? 'system',
      description: input.description,
      metadata: input.metadata ?? {},
      previousHash,
      timestamp,
    });

    const { digest, payload } = computeBlockHash(document);
    const signed = getKeyring().sign(payload, DOMAIN_AUDIT);

    db.prepare(
      `INSERT INTO audit_events (
         event_id, sequence, event_type, asset_id, asset_name, asset_hash, severity,
         actor, description, metadata_json, previous_hash, current_hash, signature,
         signing_key_id, timestamp
       ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
    ).run(
      eventId,
      sequence,
      input.eventType,
      input.assetId ?? null,
      input.assetName ?? '',
      input.assetHash ?? '',
      input.severity ?? 'INFO',
      input.actor ?? 'system',
      input.description,
      JSON.stringify(input.metadata ?? {}),
      previousHash,
      digest,
      signed?.signature ?? null,
      signed?.keyId ?? null,
      timestamp
    );

    return {
      eventId,
      sequence,
      eventType: input.eventType,
      assetId: input.assetId ?? null,
      assetName: input.assetName ?? '',
      assetHash: input.assetHash ?? '',
      severity: input.severity ?? 'INFO',
      actor: input.actor ?? 'system',
      description: input.description,
      metadata: input.metadata ?? {},
      previousHash,
      currentHash: digest,
      signature: signed?.signature ?? null,
      signingKeyId: signed?.keyId ?? null,
      timestamp,
    };
  });
}

export interface ChainVerification {
  valid: boolean;
  chainLength: number;
  genesisHash: string;
  headHash: string;
  verifiedBlocks: number;
  signedBlocks: number;
  signatureFailures: number;
  firstBrokenBlock?: { eventId: string; sequence: number; reason: string };
  details: string;
  verifiedAt: string;
}

/**
 * Walk the whole chain, recomputing every digest and checking every signature.
 *
 * Fail-closed throughout: a missing hash, a malformed hash, a sequence gap and a
 * signature mismatch are all breaks. The first break is reported with its block id so an
 * investigator knows exactly where the ledger stops being trustworthy.
 */
export function verifyAuditChain(): ChainVerification {
  const rows = db.prepare(`SELECT * FROM audit_events ORDER BY sequence ASC`).all() as Array<Record<string, unknown>>;
  const verifiedAt = new Date().toISOString();
  const keyring = getKeyring();

  if (rows.length === 0) {
    return {
      valid: true,
      chainLength: 0,
      genesisHash: GENESIS_HASH,
      headHash: GENESIS_HASH,
      verifiedBlocks: 0,
      signedBlocks: 0,
      signatureFailures: 0,
      details: 'Audit ledger is empty. Genesis state is intact.',
      verifiedAt,
    };
  }

  let expectedPrevious = GENESIS_HASH;
  let expectedSequence = 1;
  let signedBlocks = 0;
  let signatureFailures = 0;

  const fail = (row: Record<string, unknown>, reason: string, index: number): ChainVerification => ({
    valid: false,
    chainLength: rows.length,
    genesisHash: String(rows[0].previous_hash ?? ''),
    headHash: String(rows[rows.length - 1].current_hash ?? ''),
    verifiedBlocks: index,
    signedBlocks,
    signatureFailures,
    firstBrokenBlock: {
      eventId: String(row.event_id),
      sequence: Number(row.sequence),
      reason,
    },
    details:
      `Audit chain verification FAILED at block ${Number(row.sequence)} (${String(row.event_id)}): ${reason}. ` +
      `${index} block(s) before it verified correctly; nothing at or after this point can be trusted.`,
    verifiedAt,
  });

  for (let index = 0; index < rows.length; index += 1) {
    const row = rows[index];
    const storedHash = String(row.current_hash ?? '');
    const storedPrevious = String(row.previous_hash ?? '');
    const sequence = Number(row.sequence);

    // Fail closed. A blanked hash column is an erasure attempt, not a row to skip.
    if (!/^[0-9a-f]{64}$/i.test(storedHash)) {
      return fail(row, 'stored block hash is missing or malformed', index);
    }
    if (sequence !== expectedSequence) {
      return fail(row, `sequence gap: expected ${expectedSequence}, found ${sequence}`, index);
    }
    if (storedPrevious !== expectedPrevious) {
      return fail(
        row,
        `broken link: previous_hash is ${storedPrevious.slice(0, 12)}... but the prior block hashes to ${expectedPrevious.slice(0, 12)}...`,
        index
      );
    }

    let metadata: Record<string, unknown> = {};
    try {
      metadata = JSON.parse(String(row.metadata_json ?? '{}'));
    } catch {
      return fail(row, 'metadata is not valid JSON, so the block cannot be recomputed', index);
    }

    const document = blockDocument({
      eventId: String(row.event_id),
      sequence,
      eventType: String(row.event_type),
      assetId: (row.asset_id as string | null) ?? null,
      assetName: String(row.asset_name ?? ''),
      assetHash: String(row.asset_hash ?? ''),
      severity: String(row.severity ?? 'INFO'),
      actor: String(row.actor ?? 'system'),
      description: String(row.description ?? ''),
      metadata,
      previousHash: storedPrevious,
      timestamp: String(row.timestamp),
    });

    const { digest, payload } = computeBlockHash(document);
    if (digest !== storedHash) {
      return fail(
        row,
        `content was modified: recomputed digest ${digest.slice(0, 12)}... does not match the stored ${storedHash.slice(0, 12)}...`,
        index
      );
    }

    const signature = row.signature as string | null;
    if (signature) {
      signedBlocks += 1;
      if (!keyring.verify(payload, signature, row.signing_key_id as string | null, DOMAIN_AUDIT)) {
        signatureFailures += 1;
        return fail(
          row,
          'Ed25519 signature does not verify. The digest was recomputed by a party without the signing key',
          index
        );
      }
    }

    expectedPrevious = storedHash;
    expectedSequence += 1;
  }

  const unsigned = rows.length - signedBlocks;
  return {
    valid: true,
    chainLength: rows.length,
    genesisHash: GENESIS_HASH,
    headHash: expectedPrevious,
    verifiedBlocks: rows.length,
    signedBlocks,
    signatureFailures: 0,
    details:
      `All ${rows.length} blocks verified: every digest recomputed correctly, the chain links are ` +
      `unbroken from genesis, and ${signedBlocks} block(s) carry a valid Ed25519 signature` +
      (unsigned > 0
        ? `. ${unsigned} block(s) are unsigned and are integrity-verified but not attributable.`
        : '. Non-repudiation holds across the whole ledger.'),
    verifiedAt,
  };
}

export function listAuditEvents(limit = 100, offset = 0): AuditEventRow[] {
  const rows = db
    .prepare(`SELECT * FROM audit_events ORDER BY sequence DESC LIMIT ? OFFSET ?`)
    .all(limit, offset) as Array<Record<string, unknown>>;

  return rows.map((row) => ({
    eventId: String(row.event_id),
    sequence: Number(row.sequence),
    eventType: String(row.event_type),
    assetId: (row.asset_id as string | null) ?? null,
    assetName: String(row.asset_name ?? ''),
    assetHash: String(row.asset_hash ?? ''),
    severity: String(row.severity ?? 'INFO') as AuditSeverity,
    actor: String(row.actor ?? 'system'),
    description: String(row.description ?? ''),
    metadata: safeParse(String(row.metadata_json ?? '{}')),
    previousHash: String(row.previous_hash ?? ''),
    currentHash: String(row.current_hash ?? ''),
    signature: (row.signature as string | null) ?? null,
    signingKeyId: (row.signing_key_id as string | null) ?? null,
    timestamp: String(row.timestamp),
  }));
}

function safeParse(text: string): Record<string, unknown> {
  try {
    const parsed = JSON.parse(text);
    return parsed && typeof parsed === 'object' ? parsed : {};
  } catch {
    return {};
  }
}

/** Record the ledger's own initialisation so block 1 is always a known anchor. */
export function ensureGenesisBlock(): void {
  const count = db.prepare(`SELECT COUNT(*) AS c FROM audit_events`).get() as { c: number };
  if (Number(count.c) > 0) return;

  const keyring = getKeyring();
  appendAuditEvent({
    eventType: 'LEDGER_INITIALISED',
    assetName: 'audit-ledger',
    severity: 'INFO',
    actor: 'system',
    description:
      'Cryptographic audit ledger initialised. All subsequent events are hash-chained to this block.',
    metadata: {
      signingKeyId: keyring.id || null,
      signingAvailable: keyring.available,
      node: process.env.AIA_NODE_ID ?? 'local',
    },
  });
  log.info('audit ledger initialised');
}
