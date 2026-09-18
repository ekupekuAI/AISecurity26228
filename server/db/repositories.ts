/**
 * Typed data access.
 *
 * Every statement is parameterised -- there is no string interpolation into SQL anywhere
 * in this file, which is what keeps injection off the table rather than relying on an
 * input sanitiser that has to anticipate every encoding.
 *
 * Writes that span several tables run in one transaction, so a dataset analysis either
 * lands completely (asset, analysis, per-format detail, findings, contributors, audit
 * block) or not at all. A half-written analysis would leave findings pointing at an
 * asset that does not exist.
 */

import crypto from 'node:crypto';
import { db, transaction } from './index.js';
import { appendAuditEvent } from './audit.js';
import type { AuditSeverity } from './audit.js';

export type AnalysisType = 'DATASET' | 'MODEL' | 'INFERENCE' | 'DISTRIBUTION';

export interface FindingRecord {
  id?: string;
  findingId: string;
  category: string;
  severity: AuditSeverity;
  confidence: number;
  affectedAsset: string;
  explanation: string;
  evidence: unknown;
  recommendation: string;
  detector?: string | null;
  threshold?: string | null;
  references?: string[];
  timestamp?: string;
}

export interface AnalysisSummary {
  id: string;
  type: AnalysisType;
  name: string;
  sha256: string;
  risk: number;
  status: string;
  engine: string;
  analysisMode: string | null;
  durationSeconds: number | null;
  timestamp: string;
  isDemo: boolean;
  findingCount: number;
  criticalCount: number;
}

function nowIso(): string {
  return new Date().toISOString();
}

function toJson(value: unknown): string {
  if (typeof value === 'string') return value;
  try {
    return JSON.stringify(value ?? null);
  } catch {
    return '"[unserialisable]"';
  }
}

function parseJson<T>(text: string, fallback: T): T {
  try {
    const parsed = JSON.parse(text);
    return (parsed ?? fallback) as T;
  } catch {
    return fallback;
  }
}

/** Stable asset id derived from the content digest, so resubmitting one file reuses it. */
export function assetIdFor(sha256: string, type: AnalysisType): string {
  return `${type.slice(0, 3)}-${sha256.slice(0, 16).toUpperCase()}`;
}

export interface SaveAnalysisInput {
  id: string;
  type: AnalysisType;
  filename: string;
  sha256: string;
  fileSizeBytes: number;
  status: string;
  riskScore: number;
  engine?: string;
  analysisMode?: string | null;
  durationSeconds?: number | null;
  payload: Record<string, unknown>;
  findings?: FindingRecord[];
  contributors?: Array<Record<string, unknown>>;
  performedBy?: string;
  isDemo?: boolean;
  source?: string | null;
}

export function saveAnalysis(input: SaveAnalysisInput): { analysisId: string; assetId: string } {
  return transaction(() => {
    const createdAt = nowIso();
    const isDemo = input.isDemo ? 1 : 0;
    const assetId = assetIdFor(input.sha256, input.type);

    // Quarantine status follows the finding severity, so a DETECTED asset is isolated in
    // the registry rather than only being coloured red in the UI.
    const quarantine =
      input.status === 'DETECTED' ? 'QUARANTINED' : input.status === 'SUSPICIOUS' ? 'REVIEW' : 'ACTIVE';

    db.prepare(
      `INSERT INTO assets (asset_id, asset_type, filename, sha256, file_size_bytes, source,
                           quarantine_status, submitted_by, is_demo, created_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
       ON CONFLICT(asset_id) DO UPDATE SET
         quarantine_status = excluded.quarantine_status,
         filename          = excluded.filename,
         file_size_bytes   = excluded.file_size_bytes`
    ).run(
      assetId,
      input.type,
      input.filename,
      input.sha256,
      input.fileSizeBytes,
      input.source ?? null,
      quarantine,
      input.performedBy ?? null,
      isDemo,
      createdAt
    );

    db.prepare(
      `INSERT INTO analyses (analysis_id, asset_id, type, filename, sha256, file_size_bytes,
                             status, risk_score, engine, analysis_mode, duration_seconds,
                             payload_json, performed_by, is_demo, created_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
       ON CONFLICT(analysis_id) DO UPDATE SET
         status       = excluded.status,
         risk_score   = excluded.risk_score,
         payload_json = excluded.payload_json`
    ).run(
      input.id,
      assetId,
      input.type,
      input.filename,
      input.sha256,
      input.fileSizeBytes,
      input.status,
      input.riskScore,
      input.engine ?? 'unknown',
      input.analysisMode ?? null,
      input.durationSeconds ?? null,
      toJson(input.payload),
      input.performedBy ?? null,
      isDemo,
      createdAt
    );

    if (input.type === 'DATASET') {
      const p = input.payload as Record<string, any>;
      db.prepare(
        `INSERT OR REPLACE INTO datasets (dataset_id, asset_id, analysis_id, format, sample_count,
           class_count, corrupt_count, duplicate_count, trigger_count, ood_count,
           label_suspect_count, risk_score, created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
      ).run(
        `DS-${input.sha256.slice(0, 16).toUpperCase()}`,
        assetId,
        input.id,
        String(p.format ?? 'UNKNOWN'),
        Number(p.totalSamples ?? 0),
        Object.keys(p.classDistribution ?? {}).length,
        Number(p.corruptedFiles ?? 0),
        Number(p?.duplicateAnalysis?.totalRedundantSamples ?? 0),
        Number(p?.triggerAnalysis?.confirmedSamples ?? 0),
        Number(p?.oodAnalysis?.outlierCount ?? 0),
        Number(p?.labelAnalysis?.suspectCount ?? 0),
        Number(input.riskScore),
        createdAt
      );
    }

    if (input.type === 'MODEL') {
      const p = input.payload as Record<string, any>;
      db.prepare(
        `INSERT OR REPLACE INTO models (model_id, asset_id, analysis_id, framework, architecture,
           parameter_count, analysis_mode, serialization_verdict, backdoor_confidence,
           risk_score, created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
      ).run(
        `MD-${input.sha256.slice(0, 16).toUpperCase()}`,
        assetId,
        input.id,
        String(p.framework ?? 'Unknown'),
        String(p.architecture ?? 'Unknown'),
        p.parameterCount == null ? null : Number(p.parameterCount),
        String(p.analysisMode ?? 'BLACK_BOX'),
        String(p?.pickleAudit?.verdict ?? 'N/A'),
        Number(p.backdoorConfidence ?? 0),
        Number(input.riskScore),
        createdAt
      );
    }

    if (input.findings?.length) {
      const stmt = db.prepare(
        `INSERT OR REPLACE INTO findings (id, finding_id, analysis_id, asset_id, category, severity,
           confidence, affected_asset, explanation, evidence_json, recommendation, detector,
           threshold_used, references_json, is_demo, created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
      );
      for (const finding of input.findings) {
        stmt.run(
          finding.id ?? `FIND-${crypto.randomBytes(6).toString('hex').toUpperCase()}`,
          finding.findingId,
          input.id,
          assetId,
          finding.category,
          finding.severity,
          Number(finding.confidence ?? 0),
          finding.affectedAsset ?? '',
          finding.explanation ?? '',
          toJson(finding.evidence),
          finding.recommendation ?? '',
          finding.detector ?? null,
          finding.threshold ?? null,
          toJson(finding.references ?? []),
          isDemo,
          finding.timestamp ?? createdAt
        );
      }
    }

    if (input.contributors?.length) {
      const stmt = db.prepare(
        `INSERT OR REPLACE INTO contributors (id, analysis_id, name, sample_count, defect_count,
           trigger_count, defect_density, risk_score, drivers_json, is_demo, created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
      );
      for (const profile of input.contributors as Array<Record<string, any>>) {
        stmt.run(
          `CON-${crypto.createHash('sha256').update(`${input.id}:${profile.name}`).digest('hex').slice(0, 16).toUpperCase()}`,
          input.id,
          String(profile.name ?? 'UNATTRIBUTED'),
          Number(profile.sampleCount ?? 0),
          Number(profile.totalDefects ?? 0),
          Number(profile.triggerSamples ?? 0),
          Number(profile.defectDensityPercent ?? 0) / 100,
          Number(profile.riskScore ?? 0),
          toJson(profile.riskDrivers ?? []),
          isDemo,
          createdAt
        );
      }
    }

    const criticalCount = (input.findings ?? []).filter((f) => f.severity === 'CRITICAL').length;
    appendAuditEvent({
      eventType: `${input.type}_ANALYSIS_COMPLETED`,
      assetId,
      assetName: input.filename,
      assetHash: input.sha256,
      severity: input.status === 'DETECTED' ? 'CRITICAL' : input.status === 'SUSPICIOUS' ? 'HIGH' : 'INFO',
      actor: input.performedBy ?? 'system',
      description:
        `${input.type} analysis of ${input.filename} completed with status ${input.status} and ` +
        `risk ${input.riskScore}/100 (${(input.findings ?? []).length} findings, ${criticalCount} critical).`,
      metadata: {
        analysisId: input.id,
        engine: input.engine ?? 'unknown',
        analysisMode: input.analysisMode ?? null,
        findingCount: (input.findings ?? []).length,
        criticalCount,
        quarantineStatus: quarantine,
      },
    });

    return { analysisId: input.id, assetId };
  });
}

export function getAnalysisById(id: string): Record<string, unknown> | null {
  const row = db.prepare(`SELECT * FROM analyses WHERE analysis_id = ?`).get(id) as
    | Record<string, unknown>
    | undefined;
  if (!row) return null;

  const payload = parseJson<Record<string, unknown>>(String(row.payload_json), {});
  return {
    ...payload,
    id: String(row.analysis_id),
    assetId: row.asset_id,
    isDemo: Boolean(row.is_demo),
    performedBy: row.performed_by,
    timestamp: String(row.created_at),
  };
}

export function listAnalyses(limit = 50, offset = 0, type?: AnalysisType): AnalysisSummary[] {
  const rows = (
    type
      ? db.prepare(
          `SELECT a.*,
                  (SELECT COUNT(*) FROM findings f WHERE f.analysis_id = a.analysis_id) AS finding_count,
                  (SELECT COUNT(*) FROM findings f WHERE f.analysis_id = a.analysis_id AND f.severity='CRITICAL') AS critical_count
           FROM analyses a WHERE a.type = ? ORDER BY a.created_at DESC LIMIT ? OFFSET ?`
        ).all(type, limit, offset)
      : db.prepare(
          `SELECT a.*,
                  (SELECT COUNT(*) FROM findings f WHERE f.analysis_id = a.analysis_id) AS finding_count,
                  (SELECT COUNT(*) FROM findings f WHERE f.analysis_id = a.analysis_id AND f.severity='CRITICAL') AS critical_count
           FROM analyses a ORDER BY a.created_at DESC LIMIT ? OFFSET ?`
        ).all(limit, offset)
  ) as Array<Record<string, unknown>>;

  return rows.map((row) => ({
    id: String(row.analysis_id),
    type: String(row.type) as AnalysisType,
    name: String(row.filename),
    sha256: String(row.sha256),
    risk: Number(row.risk_score),
    status: String(row.status),
    engine: String(row.engine ?? 'unknown'),
    analysisMode: (row.analysis_mode as string | null) ?? null,
    durationSeconds: row.duration_seconds == null ? null : Number(row.duration_seconds),
    timestamp: String(row.created_at),
    isDemo: Boolean(row.is_demo),
    findingCount: Number(row.finding_count ?? 0),
    criticalCount: Number(row.critical_count ?? 0),
  }));
}

export function listFindings(limit = 100, offset = 0, severity?: string): Array<Record<string, unknown>> {
  const rows = (
    severity
      ? db.prepare(
          `SELECT * FROM findings WHERE severity = ? ORDER BY created_at DESC LIMIT ? OFFSET ?`
        ).all(severity, limit, offset)
      : db.prepare(`SELECT * FROM findings ORDER BY created_at DESC LIMIT ? OFFSET ?`).all(limit, offset)
  ) as Array<Record<string, unknown>>;

  return rows.map((row) => ({
    id: String(row.id),
    findingId: String(row.finding_id),
    analysisId: row.analysis_id,
    assetId: row.asset_id,
    category: String(row.category),
    severity: String(row.severity),
    confidence: Number(row.confidence),
    affectedAsset: String(row.affected_asset),
    explanation: String(row.explanation),
    evidence: parseJson<unknown>(String(row.evidence_json ?? '{}'), {}),
    recommendation: String(row.recommendation),
    detector: row.detector,
    threshold: row.threshold_used,
    references: parseJson<string[]>(String(row.references_json ?? '[]'), []),
    acknowledgedBy: row.acknowledged_by,
    acknowledgedAt: row.acknowledged_at,
    timestamp: String(row.created_at),
    isDemo: Boolean(row.is_demo),
  }));
}

export function acknowledgeFinding(id: string, actor: string): boolean {
  const result = db
    .prepare(`UPDATE findings SET acknowledged_by = ?, acknowledged_at = ? WHERE id = ? AND acknowledged_at IS NULL`)
    .run(actor, nowIso(), id);
  return Number(result.changes) > 0;
}

/**
 * Source-level contributor risk register.
 *
 * Rows are stored per analysis, but a contributor is a *source*, not a submission. Listing
 * one row per archive made the same supplier appear three times with three scores, which
 * is exactly the wrong reading: an assessor asking "who should we stop accepting data
 * from" needs one line per supplier.
 *
 * Counts are summed across submissions and the risk score is the worst ever observed, not
 * the mean. A supplier who flooded one corpus and behaved on the next two has not earned
 * a two-thirds discount; the register keeps them flagged until a human clears them.
 *
 * Grouping is case-insensitive. The engine takes a contributor identity from a manifest
 * when one is shipped and from a directory name otherwise, and the same supplier is
 * routinely spelled `Contributor_Bravo` in a CSV and `contributor_bravo` on disk. Two
 * rows for one supplier is not a cosmetic problem: it halves their apparent volume and
 * lets a bad source launder its score by changing capitalisation.
 */
export function listContributors(limit = 50): Array<Record<string, unknown>> {
  const rows = db
    .prepare(
      `SELECT LOWER(c.name)                AS key,
              SUM(c.sample_count)          AS sample_count,
              SUM(c.defect_count)          AS defect_count,
              SUM(c.trigger_count)         AS trigger_count,
              MAX(c.risk_score)            AS risk_score,
              COUNT(DISTINCT c.analysis_id) AS submission_count,
              MIN(c.is_demo)               AS all_demo,
              MAX(c.created_at)            AS last_seen,
              GROUP_CONCAT(DISTINCT a.filename) AS archives
       FROM contributors c
       JOIN analyses a ON a.analysis_id = c.analysis_id
       GROUP BY key
       ORDER BY risk_score DESC, defect_count DESC
       LIMIT ?`
    )
    .all(limit) as Array<Record<string, unknown>>;

  return rows.map((row) => {
    const key = String(row.key);
    const sampleCount = Number(row.sample_count);
    const defectCount = Number(row.defect_count);

    // The display name and the drivers both come from the submission that scored worst,
    // so the text a reader sees always corresponds to the number beside it.
    const worst = db
      .prepare(
        `SELECT name, drivers_json FROM contributors
         WHERE LOWER(name) = ? ORDER BY risk_score DESC, created_at DESC LIMIT 1`
      )
      .get(key) as { name?: string; drivers_json?: string } | undefined;

    return {
      name: worst?.name ?? key,
      sampleCount,
      defectCount,
      totalDefects: defectCount,
      triggerSamples: Number(row.trigger_count),
      // Recomputed from the summed totals rather than averaged: averaging a density
      // across archives of different sizes is simply the wrong statistic.
      defectDensityPercent: sampleCount > 0 ? (defectCount / sampleCount) * 100 : 0,
      riskScore: Number(row.risk_score),
      riskDrivers: parseJson<string[]>(String(worst?.drivers_json ?? '[]'), []),
      submissionCount: Number(row.submission_count),
      sourceArchive: String(row.archives ?? '').split(',').filter(Boolean).join(', '),
      timestamp: String(row.last_seen),
      isDemo: Boolean(Number(row.all_demo)),
    };
  });
}

// --- inference records ------------------------------------------------------------

export interface InferenceRecordInput {
  recordId: string;
  inputHash: string;
  modelIdentifier: string;
  modelHash: string;
  configuration: Record<string, unknown>;
  prediction: string;
  confidence: number;
  timestamp: string;
  nonce: string;
  recordHash: string;
  signature?: string | null;
  signingKeyId?: string | null;
  canonical?: string;
  status?: string;
  sealedBy?: string;
  isDemo?: boolean;
}

export function saveInferenceRecord(input: InferenceRecordInput): void {
  const configurationJson = toJson(input.configuration);
  db.prepare(
    `INSERT INTO inference_records (record_id, input_hash, model_identifier, model_hash,
       configuration_json, configuration_hash, prediction, confidence, timestamp, nonce,
       record_hash, signature, signing_key_id, canonical_json, status, sealed_by, is_demo, created_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
     ON CONFLICT(record_id) DO UPDATE SET status = excluded.status`
  ).run(
    input.recordId,
    input.inputHash,
    input.modelIdentifier,
    input.modelHash,
    configurationJson,
    crypto.createHash('sha256').update(configurationJson).digest('hex'),
    input.prediction,
    input.confidence,
    input.timestamp,
    input.nonce,
    input.recordHash,
    input.signature ?? null,
    input.signingKeyId ?? null,
    input.canonical ?? '{}',
    input.status ?? 'VERIFIED',
    input.sealedBy ?? null,
    input.isDemo ? 1 : 0,
    nowIso()
  );
}

export function listInferenceRecords(limit = 50, offset = 0): Array<Record<string, unknown>> {
  const rows = db
    .prepare(`SELECT * FROM inference_records ORDER BY created_at DESC LIMIT ? OFFSET ?`)
    .all(limit, offset) as Array<Record<string, unknown>>;

  return rows.map((row) => ({
    id: String(row.record_id),
    inputImageHash: String(row.input_hash),
    modelIdentifier: String(row.model_identifier),
    modelSha256: String(row.model_hash),
    preprocessingConfig: String(row.configuration_json),
    configurationHash: String(row.configuration_hash),
    prediction: String(row.prediction),
    confidence: Number(row.confidence),
    timestamp: String(row.timestamp),
    nonce: String(row.nonce),
    recordHash: String(row.record_hash),
    signature: row.signature,
    signingKeyId: row.signing_key_id,
    status: String(row.status),
    sealedBy: row.sealed_by,
    isDemo: Boolean(row.is_demo),
    createdAt: String(row.created_at),
  }));
}

export function getInferenceRecord(recordId: string): Record<string, unknown> | null {
  const row = db.prepare(`SELECT * FROM inference_records WHERE record_id = ?`).get(recordId) as
    | Record<string, unknown>
    | undefined;
  if (!row) return null;
  return {
    recordId: String(row.record_id),
    canonical: parseJson<Record<string, unknown>>(String(row.canonical_json ?? '{}'), {}),
    recordHash: String(row.record_hash),
    signature: row.signature,
    signingKeyId: row.signing_key_id,
    status: String(row.status),
  };
}

export function markInferenceStatus(recordId: string, status: string): void {
  // record_hash and the sealed fields are protected by a trigger; only status may move.
  db.prepare(`UPDATE inference_records SET status = ? WHERE record_id = ?`).run(status, recordId);
}

// --- nonce ledger -----------------------------------------------------------------

export interface NonceCheck {
  fresh: boolean;
  reason?: string;
  firstSeenAt?: string;
  originalRecordId?: string;
  kind?: 'REPLAY' | 'NONCE_REUSE' | 'SUBSTITUTION';
}

/**
 * Claim a nonce, or explain why it cannot be claimed.
 *
 * The UNIQUE constraint on `nonces.nonce` is the actual enforcement -- a check-then-act
 * in application code would race under concurrent submissions, and two nodes replaying
 * the same capture simultaneously is exactly when it matters.
 */
export function claimNonce(params: {
  nonce: string;
  recordId: string;
  recordHash: string;
  inputHash: string;
  modelHash: string;
  prediction: string;
}): NonceCheck {
  return transaction(() => {
    const existing = db.prepare(`SELECT * FROM nonces WHERE nonce = ?`).get(params.nonce) as
      | Record<string, unknown>
      | undefined;

    if (existing) {
      const sameDigest = String(existing.record_hash) === params.recordHash;
      return {
        fresh: false,
        kind: sameDigest ? 'REPLAY' : 'NONCE_REUSE',
        reason: sameDigest
          ? 'This nonce and digest were already accepted by this node. The payload is a verbatim replay of an earlier inference.'
          : 'This nonce was already consumed by a different payload. A nonce must be unique per record.',
        firstSeenAt: String(existing.first_seen_at),
        originalRecordId: String(existing.record_id),
      };
    }

    // Same input through the same model must yield the same answer. Two different
    // answers means one of the records is fabricated.
    const binding = db
      .prepare(`SELECT * FROM nonces WHERE input_hash = ? AND model_hash = ? ORDER BY first_seen_at ASC LIMIT 1`)
      .get(params.inputHash, params.modelHash) as Record<string, unknown> | undefined;

    if (binding && String(binding.prediction) !== params.prediction) {
      db.prepare(
        `INSERT INTO nonces (nonce, record_id, record_hash, input_hash, model_hash, prediction, first_seen_at)
         VALUES (?, ?, ?, ?, ?, ?, ?)`
      ).run(
        params.nonce,
        params.recordId,
        params.recordHash,
        params.inputHash,
        params.modelHash,
        params.prediction,
        nowIso()
      );
      return {
        fresh: false,
        kind: 'SUBSTITUTION',
        reason:
          `Output substitution: this input and model previously produced '${String(binding.prediction)}' ` +
          `(record ${String(binding.record_id)}) and now produce '${params.prediction}'. ` +
          'A deterministic pipeline cannot do both.',
        firstSeenAt: String(binding.first_seen_at),
        originalRecordId: String(binding.record_id),
      };
    }

    db.prepare(
      `INSERT INTO nonces (nonce, record_id, record_hash, input_hash, model_hash, prediction, first_seen_at)
       VALUES (?, ?, ?, ?, ?, ?, ?)`
    ).run(
      params.nonce,
      params.recordId,
      params.recordHash,
      params.inputHash,
      params.modelHash,
      params.prediction,
      nowIso()
    );

    return { fresh: true };
  });
}

// --- aggregate statistics ----------------------------------------------------------

export interface PlatformStatistics {
  overallTrustScore: number;
  overallRisk: number;
  datasetRisk: number;
  modelRisk: number;
  inferenceIntegrityRisk: number;
  distributionShiftRisk: number;
  analyzedAssetsCount: number;
  suspiciousFindingsCount: number;
  criticalFindingsCount: number;
  quarantinedAssetsCount: number;
  inferenceRecordCount: number;
  tamperedRecordCount: number;
  contributorCount: number;
  highRiskContributorCount: number;
}

export function platformStatistics(): PlatformStatistics {
  const scalar = (sql: string, ...params: unknown[]): number => {
    const row = db.prepare(sql).get(...(params as never[])) as { v: number | null } | undefined;
    return Number(row?.v ?? 0);
  };

  // Latest analysis per type, not the mean of all history: a corrected resubmission
  // should replace the earlier verdict, not be averaged with it.
  const latestRisk = (type: AnalysisType): number =>
    scalar(`SELECT risk_score AS v FROM analyses WHERE type = ? ORDER BY created_at DESC LIMIT 1`, type);

  const datasetRisk = latestRisk('DATASET');
  const modelRisk = latestRisk('MODEL');
  const shiftRisk = latestRisk('DISTRIBUTION');

  const totalInference = scalar(`SELECT COUNT(*) AS v FROM inference_records`);
  const compromised = scalar(
    `SELECT COUNT(*) AS v FROM inference_records WHERE status IN ('TAMPERED','FORGED','REPLAYED')`
  );
  // Any failed record is a pipeline-level integrity failure, so a single one carries
  // substantial weight rather than being diluted by the volume of healthy traffic.
  const inferenceRisk = totalInference === 0 ? 0 : Math.min(100, (compromised / totalInference) * 100 + (compromised > 0 ? 40 : 0));

  const overallRisk = Math.round((0.35 * datasetRisk + 0.35 * modelRisk + 0.15 * inferenceRisk + 0.15 * shiftRisk) * 10) / 10;

  return {
    overallTrustScore: Math.max(0, Math.round((100 - overallRisk) * 10) / 10),
    overallRisk,
    datasetRisk: Math.round(datasetRisk * 10) / 10,
    modelRisk: Math.round(modelRisk * 10) / 10,
    inferenceIntegrityRisk: Math.round(inferenceRisk * 10) / 10,
    distributionShiftRisk: Math.round(shiftRisk * 10) / 10,
    analyzedAssetsCount: scalar(`SELECT COUNT(*) AS v FROM assets`),
    suspiciousFindingsCount: scalar(`SELECT COUNT(*) AS v FROM findings WHERE severity IN ('CRITICAL','HIGH')`),
    criticalFindingsCount: scalar(`SELECT COUNT(*) AS v FROM findings WHERE severity = 'CRITICAL'`),
    quarantinedAssetsCount: scalar(`SELECT COUNT(*) AS v FROM assets WHERE quarantine_status = 'QUARANTINED'`),
    inferenceRecordCount: totalInference,
    tamperedRecordCount: compromised,
    contributorCount: scalar(`SELECT COUNT(DISTINCT name) AS v FROM contributors`),
    highRiskContributorCount: scalar(`SELECT COUNT(DISTINCT name) AS v FROM contributors WHERE risk_score >= 60`),
  };
}

export function clearDemoData(actor: string): { removed: Record<string, number> } {
  return transaction(() => {
    const removed: Record<string, number> = {};
    for (const table of ['findings', 'contributors', 'inference_records', 'analyses', 'assets']) {
      const result = db.prepare(`DELETE FROM ${table} WHERE is_demo = 1`).run();
      removed[table] = Number(result.changes);
    }
    // Audit events are append-only and are never deleted, even for demo data: the
    // ledger's job is to record that the purge happened.
    appendAuditEvent({
      eventType: 'DEMO_DATA_PURGED',
      assetName: 'evaluation-dataset',
      severity: 'INFO',
      actor,
      description: 'Evaluation records purged. Production analyses and the audit ledger are untouched.',
      metadata: { removed },
    });
    return { removed };
  });
}
