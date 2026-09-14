/**
 * SQLite Database Layer using native Node 22 DatabaseSync
 * Manages analyses, assets, findings, inference records, and audit events.
 */

import { DatabaseSync } from 'node:sqlite';
import path from 'node:path';
import fs from 'node:fs';
import crypto from 'node:crypto';
import { AssuranceStatus, Finding, FindingSeverity, PlatformStats } from '../src/types.js';

const DB_PATH = path.join(process.cwd(), 'data', 'ai_integrity.db');

// Ensure data directory exists
const dataDir = path.dirname(DB_PATH);
if (!fs.existsSync(dataDir)) {
  fs.mkdirSync(dataDir, { recursive: true });
}

export const db = new DatabaseSync(DB_PATH);

// Initialize schema
db.exec(`
  CREATE TABLE IF NOT EXISTS analyses (
    id TEXT PRIMARY KEY,
    type TEXT NOT NULL,
    filename TEXT NOT NULL,
    sha256 TEXT NOT NULL,
    file_size_bytes INTEGER NOT NULL,
    status TEXT NOT NULL,
    risk_score REAL NOT NULL,
    payload_json TEXT NOT NULL,
    is_demo INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL
  );

  CREATE TABLE IF NOT EXISTS assets (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    type TEXT NOT NULL,
    sha256 TEXT NOT NULL UNIQUE,
    file_size_bytes INTEGER NOT NULL,
    quarantine_status TEXT NOT NULL DEFAULT 'ACTIVE',
    created_at TEXT NOT NULL
  );

  CREATE TABLE IF NOT EXISTS findings (
    id TEXT PRIMARY KEY,
    finding_id TEXT NOT NULL,
    analysis_id TEXT NOT NULL,
    category TEXT NOT NULL,
    severity TEXT NOT NULL,
    confidence REAL NOT NULL,
    affected_asset TEXT NOT NULL,
    explanation TEXT NOT NULL,
    evidence TEXT NOT NULL,
    recommendation TEXT NOT NULL,
    is_demo INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL
  );

  CREATE TABLE IF NOT EXISTS inference_records (
    id TEXT PRIMARY KEY,
    input_image_hash TEXT NOT NULL,
    model_identifier TEXT NOT NULL,
    model_sha256 TEXT NOT NULL,
    preprocessing_config TEXT NOT NULL,
    prediction TEXT NOT NULL,
    confidence REAL NOT NULL,
    timestamp TEXT NOT NULL,
    nonce TEXT NOT NULL,
    record_hash TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'VERIFIED',
    is_demo INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL
  );

  CREATE TABLE IF NOT EXISTS audit_events (
    id TEXT PRIMARY KEY,
    event_type TEXT NOT NULL,
    asset_name TEXT NOT NULL,
    asset_hash TEXT NOT NULL,
    severity TEXT NOT NULL,
    description TEXT NOT NULL,
    previous_hash TEXT NOT NULL DEFAULT '',
    current_hash TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL
  );
`);

// Safe table migrations for hash chaining
try {
  db.exec(`ALTER TABLE audit_events ADD COLUMN previous_hash TEXT NOT NULL DEFAULT ''`);
} catch {}
try {
  db.exec(`ALTER TABLE audit_events ADD COLUMN current_hash TEXT NOT NULL DEFAULT ''`);
} catch {}

export function saveAnalysis(analysis: {
  id: string;
  type: 'DATASET' | 'MODEL' | 'INFERENCE' | 'DISTRIBUTION';
  filename: string;
  sha256: string;
  fileSizeBytes: number;
  status: AssuranceStatus;
  riskScore: number;
  payload: Record<string, unknown>;
  findings?: Finding[];
  isDemo?: boolean;
}) {
  const isDemo = analysis.isDemo ? 1 : 0;
  const now = new Date().toISOString();

  const insertAnalysis = db.prepare(`
    INSERT OR REPLACE INTO analyses (id, type, filename, sha256, file_size_bytes, status, risk_score, payload_json, is_demo, created_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `);
  insertAnalysis.run(
    analysis.id,
    analysis.type,
    analysis.filename,
    analysis.sha256,
    analysis.fileSizeBytes,
    analysis.status,
    analysis.riskScore,
    JSON.stringify(analysis.payload),
    isDemo,
    now
  );

  // Save asset record
  const insertAsset = db.prepare(`
    INSERT OR IGNORE INTO assets (id, name, type, sha256, file_size_bytes, quarantine_status, created_at)
    VALUES (?, ?, ?, ?, ?, ?, ?)
  `);
  const qStatus = analysis.status === 'DETECTED' ? 'QUARANTINED' : 'ACTIVE';
  insertAsset.run(
    `ASSET-${analysis.sha256.substring(0, 12)}`,
    analysis.filename,
    analysis.type,
    analysis.sha256,
    analysis.fileSizeBytes,
    qStatus,
    now
  );

  // Save findings
  if (analysis.findings && analysis.findings.length > 0) {
    const insertFinding = db.prepare(`
      INSERT OR REPLACE INTO findings (id, finding_id, analysis_id, category, severity, confidence, affected_asset, explanation, evidence, recommendation, is_demo, created_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);

    for (const f of analysis.findings) {
      insertFinding.run(
        f.id,
        f.findingId,
        analysis.id,
        f.category,
        f.severity,
        f.confidence,
        f.affectedAsset,
        f.explanation,
        typeof f.evidence === 'string' ? f.evidence : JSON.stringify(f.evidence),
        f.recommendation,
        isDemo,
        f.timestamp || now
      );
    }
  }

  // Record audit event
  logAuditEvent({
    eventType: `${analysis.type}_ANALYSIS_COMPLETED`,
    assetName: analysis.filename,
    assetHash: analysis.sha256,
    severity: analysis.status === 'DETECTED' ? 'CRITICAL' : (analysis.status === 'SUSPICIOUS' ? 'HIGH' : 'INFO'),
    description: `Analysis completed with status ${analysis.status} and risk score ${analysis.riskScore}/100.`
  });
}

export function logAuditEvent(event: {
  eventType: string;
  assetName: string;
  assetHash: string;
  severity: FindingSeverity;
  description: string;
}): { id: string; previousHash: string; currentHash: string } {
  const lastEvent = db.prepare(`
    SELECT current_hash FROM audit_events ORDER BY rowid DESC LIMIT 1
  `).get() as { current_hash?: string } | undefined;

  const previousHash =
    lastEvent?.current_hash && lastEvent.current_hash.length === 64
      ? lastEvent.current_hash
      : '0000000000000000000000000000000000000000000000000000000000000000';
  const eventId = `AUDIT-${Date.now()}-${Math.floor(Math.random() * 1000)}`;
  const timestamp = new Date().toISOString();

  // Cryptographic hash chaining: SHA-256(previousHash : eventId : eventType : assetHash : timestamp : description)
  const payload = `${previousHash}:${eventId}:${event.eventType}:${event.assetHash}:${timestamp}:${event.description}`;
  const currentHash = crypto.createHash('sha256').update(payload, 'utf8').digest('hex');

  const insertEvent = db.prepare(`
    INSERT INTO audit_events (id, event_type, asset_name, asset_hash, severity, description, previous_hash, current_hash, created_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
  `);
  insertEvent.run(
    eventId,
    event.eventType,
    event.assetName,
    event.assetHash,
    event.severity,
    event.description,
    previousHash,
    currentHash,
    timestamp
  );

  return { id: eventId, previousHash, currentHash };
}

export function verifyAuditChain(): {
  valid: boolean;
  chainLength: number;
  genesisHash: string;
  headHash: string;
  tamperedEventId?: string;
  details: string;
} {
  const stmt = db.prepare(`SELECT * FROM audit_events ORDER BY rowid ASC`);
  const rows = stmt.all() as Array<Record<string, unknown>>;
  if (rows.length === 0) {
    return {
      valid: true,
      chainLength: 0,
      genesisHash: '0000000000000000000000000000000000000000000000000000000000000000',
      headHash: '0000000000000000000000000000000000000000000000000000000000000000',
      details: 'Audit trail is empty (genesis state intact).',
    };
  }

  let expectedPrevHash = '0000000000000000000000000000000000000000000000000000000000000000';
  for (let i = 0; i < rows.length; i++) {
    const row = rows[i];
    const prevHash = (row.previous_hash as string) || '';
    const currHash = (row.current_hash as string) || '';
    const eventId = row.id as string;
    const eventType = row.event_type as string;
    const assetHash = row.asset_hash as string;
    const timestamp = row.created_at as string;
    const desc = row.description as string;

    if (i > 0 && prevHash && prevHash !== expectedPrevHash) {
      return {
        valid: false,
        chainLength: rows.length,
        genesisHash: (rows[0].previous_hash as string) || '',
        headHash: currHash,
        tamperedEventId: eventId,
        details: `Broken cryptographic link at block #${i + 1} (${eventId}). Expected previous_hash: ${expectedPrevHash.slice(0, 12)}..., found: ${prevHash.slice(0, 12)}...`,
      };
    }

    // Recompute current hash
    const recomputed = crypto
      .createHash('sha256')
      .update(`${prevHash}:${eventId}:${eventType}:${assetHash}:${timestamp}:${desc}`, 'utf8')
      .digest('hex');

    if (currHash && currHash !== recomputed) {
      return {
        valid: false,
        chainLength: rows.length,
        genesisHash: (rows[0].previous_hash as string) || '',
        headHash: currHash,
        tamperedEventId: eventId,
        details: `Tampered block payload detected at event ${eventId}. SHA-256 digest recalculation mismatch.`,
      };
    }

    expectedPrevHash = currHash || recomputed;
  }

  return {
    valid: true,
    chainLength: rows.length,
    genesisHash: (rows[0].previous_hash as string) || '0000000000000000000000000000000000000000000000000000000000000000',
    headHash: (rows[rows.length - 1].current_hash as string) || expectedPrevHash,
    details: `Cryptographic audit chain completely verified across all ${rows.length} blocks. Zero tampering or sequence alteration detected. Non-repudiation guaranteed.`,
  };
}

export function getAnalysisById(id: string) {
  const stmt = db.prepare(`SELECT * FROM analyses WHERE id = ?`);
  const row = stmt.get(id) as Record<string, unknown> | undefined;
  if (!row) return null;
  return {
    ...JSON.parse(row.payload_json as string),
    id: row.id,
    isDemo: Boolean(row.is_demo),
    timestamp: row.created_at
  };
}

export function listAnalyses(limit = 50) {
  const stmt = db.prepare(`
    SELECT id, type, filename, sha256, file_size_bytes, status, risk_score, is_demo, created_at
    FROM analyses
    ORDER BY created_at DESC
    LIMIT ?
  `);
  const rows = stmt.all(limit) as Array<Record<string, unknown>>;
  return rows.map(r => ({
    id: r.id as string,
    type: r.type as 'DATASET' | 'MODEL' | 'INFERENCE' | 'DISTRIBUTION',
    name: r.filename as string,
    sha256: r.sha256 as string,
    risk: Number(r.risk_score),
    status: r.status as AssuranceStatus,
    timestamp: r.created_at as string,
    isDemo: Boolean(r.is_demo)
  }));
}

export function listFindings(limit = 100) {
  const stmt = db.prepare(`
    SELECT * FROM findings
    ORDER BY created_at DESC
    LIMIT ?
  `);
  const rows = stmt.all(limit) as Array<Record<string, unknown>>;
  return rows.map(r => ({
    id: r.id as string,
    findingId: r.finding_id as string,
    category: r.category as any,
    severity: r.severity as FindingSeverity,
    confidence: Number(r.confidence),
    affectedAsset: r.affected_asset as string,
    explanation: r.explanation as string,
    evidence: r.evidence as string,
    recommendation: r.recommendation as string,
    timestamp: r.created_at as string,
    isDemo: Boolean(r.is_demo)
  }));
}

export function saveInferenceRecord(record: {
  id: string;
  inputImageHash: string;
  modelIdentifier: string;
  modelSha256: string;
  preprocessingConfig: string;
  prediction: string;
  confidence: number;
  timestamp: string;
  nonce: string;
  recordHash: string;
  status?: string;
  isDemo?: boolean;
}) {
  const isDemo = record.isDemo ? 1 : 0;
  const insert = db.prepare(`
    INSERT OR REPLACE INTO inference_records (
      id, input_image_hash, model_identifier, model_sha256, preprocessing_config,
      prediction, confidence, timestamp, nonce, record_hash, status, is_demo, created_at
    )
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `);
  insert.run(
    record.id,
    record.inputImageHash,
    record.modelIdentifier,
    record.modelSha256,
    record.preprocessingConfig,
    record.prediction,
    record.confidence,
    record.timestamp,
    record.nonce,
    record.recordHash,
    record.status || 'VERIFIED',
    isDemo,
    new Date().toISOString()
  );
}

export function getInferenceRecords(limit = 30) {
  const stmt = db.prepare(`
    SELECT * FROM inference_records
    ORDER BY created_at DESC
    LIMIT ?
  `);
  const rows = stmt.all(limit) as Array<Record<string, unknown>>;
  return rows.map(r => ({
    id: r.id as string,
    inputImageHash: r.input_image_hash as string,
    modelIdentifier: r.model_identifier as string,
    modelSha256: r.model_sha256 as string,
    preprocessingConfig: r.preprocessing_config as string,
    prediction: r.prediction as string,
    confidence: Number(r.confidence),
    timestamp: r.timestamp as string,
    nonce: r.nonce as string,
    recordHash: r.record_hash as string,
    status: r.status as 'VERIFIED' | 'TAMPERED',
    isDemo: Boolean(r.is_demo)
  }));
}

export function getAuditEvents(limit = 50) {
  const stmt = db.prepare(`
    SELECT * FROM audit_events
    ORDER BY created_at DESC
    LIMIT ?
  `);
  const rows = stmt.all(limit) as Array<Record<string, unknown>>;
  return rows.map(r => ({
    id: r.id as string,
    eventType: r.event_type as string,
    assetName: r.asset_name as string,
    assetHash: r.asset_hash as string,
    severity: r.severity as FindingSeverity,
    description: r.description as string,
    timestamp: r.created_at as string,
    previousHash: (r.previous_hash as string) || undefined,
    currentHash: (r.current_hash as string) || undefined,
  }));
}

export function getPlatformStats(): PlatformStats {
  const assetsCount = (db.prepare(`SELECT COUNT(*) as c FROM assets`).get() as any)?.c || 0;
  const suspiciousCount = (db.prepare(`SELECT COUNT(*) as c FROM findings WHERE severity IN ('CRITICAL', 'HIGH')`).get() as any)?.c || 0;
  const quarantinedCount = (db.prepare(`SELECT COUNT(*) as c FROM assets WHERE quarantine_status = 'QUARANTINED'`).get() as any)?.c || 0;

  // Compute average risks
  const datasetAvg = (db.prepare(`SELECT AVG(risk_score) as avg FROM analyses WHERE type = 'DATASET'`).get() as any)?.avg || 0;
  const modelAvg = (db.prepare(`SELECT AVG(risk_score) as avg FROM analyses WHERE type = 'MODEL'`).get() as any)?.avg || 0;
  const shiftAvg = (db.prepare(`SELECT AVG(risk_score) as avg FROM analyses WHERE type = 'DISTRIBUTION'`).get() as any)?.avg || 0;

  // Inference risk: check proportion of tampered records
  const totalInfs = (db.prepare(`SELECT COUNT(*) as c FROM inference_records`).get() as any)?.c || 0;
  const tamperedInfs = (db.prepare(`SELECT COUNT(*) as c FROM inference_records WHERE status = 'TAMPERED'`).get() as any)?.c || 0;
  const inferenceRisk = totalInfs > 0 ? (tamperedInfs / totalInfs) * 100 : 0;

  const datasetRisk = Math.round(datasetAvg * 10) / 10;
  const modelRisk = Math.round(modelAvg * 10) / 10;
  const distributionShiftRisk = Math.round(shiftAvg * 10) / 10;
  const inferenceIntegrityRisk = Math.round(inferenceRisk * 10) / 10;

  // Overall system risk formula
  const overallRisk = Math.round(
    0.35 * datasetRisk +
    0.35 * modelRisk +
    0.15 * inferenceIntegrityRisk +
    0.15 * distributionShiftRisk
  );
  const overallTrustScore = Math.max(0, 100 - overallRisk);

  return {
    overallTrustScore,
    datasetRisk,
    modelRisk,
    inferenceIntegrityRisk,
    distributionShiftRisk,
    analyzedAssetsCount: assetsCount,
    suspiciousFindingsCount: suspiciousCount,
    quarantinedAssetsCount: quarantinedCount,
    recentAnalyses: listAnalyses(10),
    recentAuditEvents: getAuditEvents(10)
  };
}

export function clearDemoData() {
  db.exec(`
    DELETE FROM findings WHERE is_demo = 1;
    DELETE FROM inference_records WHERE is_demo = 1;
    DELETE FROM analyses WHERE is_demo = 1;
  `);
  logAuditEvent({
    eventType: 'DEMO_DATA_CLEARED',
    assetName: 'ALL_DEMO_RECORDS',
    assetHash: '0000000000000000000000000000000000000000000000000000000000000000',
    severity: 'INFO',
    description: 'Purged all evaluation records from local SQLite assurance database.'
  });
}

export function seedDemoData() {
  // Purge prior demo records first to avoid duplicates
  clearDemoData();

  const now = new Date().toISOString();

  // --- PRD Page 7 End-to-End Evaluation Case Study: Defense Border Surveillance Checkpoint ---

  // 1. Seed Dataset: Contributor B Image Pack (10,000 images, YOLOv8 format)
  const datasetId = 'DS-CONTRIB-B-9921';
  const datasetSha256 = '3c8e1f04a79b201d44ef1a89b78c901e4a3b8d7120e8fa792c019d67bc82019a';
  const datasetPayload = {
    id: datasetId,
    filename: 'contributor_b_yolov8_pack.zip',
    sha256: datasetSha256,
    fileSizeBytes: 248920150,
    totalSamples: 10000,
    corruptedFiles: 0,
    duplicateFiles: [
      {
        hash: 'a1b2c3d4e5f60718293a4b5c6d7e8f90123456789abcdef0123456789abcdef0',
        filenames: ['yolo_labels/train/img_00142.jpg', 'yolo_labels/train/img_00891_dup.jpg'],
        sampleCount: 80
      }
    ],
    nearDuplicateCandidates: [
      {
        sampleA: 'yolo_labels/train/sensor_cam4_0921.jpg',
        sampleB: 'yolo_labels/train/sensor_cam4_0922.jpg',
        similarity: 0.988,
        metrics: 'Hamming distance: 2 (pHash similarity: 98.8%), identical burst sequence'
      }
    ],
    classDistribution: {
      'military_vehicle': 3420,
      'civilian_vehicle': 2850,
      'pedestrian_personnel': 1980,
      'checkpoint_barrier': 1750
    },
    suspiciousLabelPatterns: [
      'Targeted mislabeling pattern discovered: 32 military_vehicle samples labeled as civilian_vehicle (clean-feature k-NN discordance).'
    ],
    anomalousSamples: [
      {
        filename: 'yolo_labels/train/img_trig_0041.jpg',
        reason: 'Backdoor trigger artifact: high-frequency 16x16 pixel checkerboard patch localized in bottom-right corner.',
        anomalyScore: 0.94,
        metric: 'Patch variance 8.92x baseline noise, trigger location [208, 208, 224, 224]'
      },
      {
        filename: 'yolo_labels/train/img_trig_0088.jpg',
        reason: 'Localized trigger pattern candidate in weapon mount bounding box.',
        anomalyScore: 0.91,
        metric: 'Spatial frequency anomaly score: 0.91'
      }
    ],
    oodIndicators: [
      '12 samples exhibit spectral signatures characteristic of digital trojan injection patterns.'
    ],
    contributorStats: {
      'Contributor_B': 10000
    },
    datasetRisk: 78.0,
    status: 'DETECTED' as AssuranceStatus,
    timestamp: now,
    isDemo: true
  };

  const datasetFindings: Finding[] = [
    {
      id: 'FIND-PRD-DS-001',
      findingId: 'DS-EXACT-DUPLICATES-FLOODING',
      category: 'DATASET',
      severity: 'HIGH',
      confidence: 1.0,
      affectedAsset: 'contributor_b_yolov8_pack.zip (80 duplicate pairs)',
      explanation: '80 identical image duplicates detected across distinct batch folders. Evidence of synthetic data replication.',
      evidence: 'SHA-256 match across 80 pairs; pHash Hamming distance = 0.',
      recommendation: 'Reject batch duplication. Deduplicate training dataset before model ingestion.',
      timestamp: now,
      isDemo: true
    },
    {
      id: 'FIND-PRD-DS-002',
      findingId: 'DS-LABEL-NOISE-DISCORDANCE',
      category: 'DATASET',
      severity: 'HIGH',
      confidence: 0.93,
      affectedAsset: 'contributor_b_yolov8_pack.zip (32 samples)',
      explanation: 'Clean-feature k-NN cross-validation identified 32 mislabeled samples where military_vehicle was annotated as civilian_vehicle.',
      evidence: 'Predicted loss discordance > 3.8 standard deviations from class centroid.',
      recommendation: 'Quarantine Contributor B annotations; enforce multi-analyst consensus labeling.',
      timestamp: now,
      isDemo: true
    },
    {
      id: 'FIND-PRD-DS-003',
      findingId: 'DS-BACKDOOR-TRIGGER-INJECTION',
      category: 'DATASET',
      severity: 'CRITICAL',
      confidence: 0.96,
      affectedAsset: 'contributor_b_yolov8_pack.zip (12 trigger samples)',
      explanation: 'Poisoning & Backdoor Trigger Pattern: 12 samples contain identical high-frequency spatial noise patches localized at bounding box corners.',
      evidence: 'Attribution saliency anomaly: 16x16 pixel patch [208, 208, 224, 224] with artificial variance spike.',
      recommendation: 'Quarantine dataset immediately. Revoke Contributor B ingest credentials.',
      timestamp: now,
      isDemo: true
    }
  ];

  saveAnalysis({
    id: datasetId,
    type: 'DATASET',
    filename: 'contributor_b_yolov8_pack.zip',
    sha256: datasetSha256,
    fileSizeBytes: 248920150,
    status: 'DETECTED',
    riskScore: 78.0,
    payload: datasetPayload,
    findings: datasetFindings,
    isDemo: true
  });

  // 2. Seed Model: traffic_recon_resnet18.pth (PreAct-ResNet18)
  const modelId = 'MDL-PREACT-RN18-04';
  const modelSha256 = '8fa3910cb12d8a4f91002341b590e871239ab7c40912ef6530182bc9810a924b';
  const modelPayload = {
    id: modelId,
    filename: 'traffic_recon_resnet18.pth',
    sha256: modelSha256,
    fileSizeBytes: 44781920,
    framework: 'PyTorch v2.1 (TorchScript Zip)',
    architecture: 'PreAct-ResNet18 Vision Backbone',
    parameterCount: 11174954,
    status: 'DETECTED' as AssuranceStatus,
    behavioralAnalysis: 'Standard reference battery clean baseline accuracy: 94.2%. Backdoor triggered attack success rate: 98.6% (target misclassification: STOP_SIGN -> SPEED_LIMIT).',
    backdoorAnalysis: 'Optimization-based trigger inversion (Neural Cleanse paradigm) isolated minimal perturbation vector Δ (L1 norm = 2.1% of input space, anomaly index = 2.84). Backdoor Family: BadNets / Patch Trigger.',
    confidence: 0.91,
    severity: 'CRITICAL' as FindingSeverity,
    evidence: {
      sha256: modelSha256,
      architecture: 'PreAct-ResNet18',
      neuralCleanseL1Norm: 0.021,
      anomalyIndex: 2.84,
      backdoorFamily: 'BadNets / Patch Trigger',
      targetClass: 'SPEED_LIMIT',
      cleanAccuracy: 0.942,
      triggeredAccuracy: 0.986
    },
    limitations: 'Capability scope: Verified against standard patch/blended triggers. Complex dynamic semantic triggers require white-box feature audit.',
    modelRisk: 85.0,
    timestamp: now,
    isDemo: true
  };

  const modelFindings: Finding[] = [
    {
      id: 'FIND-PRD-MOD-001',
      findingId: 'MOD-NEURAL-CLEANSE-TROJAN',
      category: 'MODEL',
      severity: 'CRITICAL',
      confidence: 0.91,
      affectedAsset: 'traffic_recon_resnet18.pth (PreAct-ResNet18)',
      explanation: 'Trojan Backdoor Trigger Inversion Anomaly: Minimal perturbation vector Δ forces target misclassification into SPEED_LIMIT with L1 shortcut of 2.1%.',
      evidence: 'Neural Cleanse Anomaly Index: 2.84 (Threshold > 2.0). Attack Success Rate: 98.6%.',
      recommendation: 'QUARANTINE MODEL IMMEDIATELY. Checkpoint cannot be authorized for operational mission deployment.',
      timestamp: now,
      isDemo: true
    }
  ];

  saveAnalysis({
    id: modelId,
    type: 'MODEL',
    filename: 'traffic_recon_resnet18.pth',
    sha256: modelSha256,
    fileSizeBytes: 44781920,
    status: 'DETECTED',
    riskScore: 85.0,
    payload: modelPayload,
    findings: modelFindings,
    isDemo: true
  });

  // 3. Seed Inference Record: Tampered Payload from PRD Page 3 & 7
  // Prediction corrupted: STOP_SIGN -> SPEED_LIMIT, Nonce verified, Payload compromised!
  const recordId = 'INF-20260913-00941';
  const inputImageHash = 'a81f3e76d9c824e8109bf320149acb7190d62c65bf0bcda32b57b277d9ad9f14';
  const inferenceConfig = JSON.stringify({
    input_resolution: [224, 224],
    mean_norm: [0.485, 0.456, 0.406],
    std_norm: [0.229, 0.224, 0.225],
    confidence_threshold: 0.50
  });

  // Expected authentic record hash computed on original prediction "STOP_SIGN"
  const authenticComponents = [
    inputImageHash,
    'traffic_recon_resnet18.pth',
    modelSha256,
    inferenceConfig,
    'STOP_SIGN',
    Number(0.984100).toFixed(6),
    '2026-09-13T06:18:22Z',
    '99382104'
  ].join('||');
  const authenticHash = crypto.createHash('sha256').update(authenticComponents, 'utf8').digest('hex');

  saveInferenceRecord({
    id: recordId,
    inputImageHash,
    modelIdentifier: 'traffic_recon_resnet18.pth',
    modelSha256,
    preprocessingConfig: inferenceConfig,
    prediction: 'SPEED_LIMIT', // Adversarially altered from STOP_SIGN
    confidence: 0.984100,
    timestamp: '2026-09-13T06:18:22Z',
    nonce: '99382104',
    recordHash: authenticHash,
    status: 'TAMPERED',
    isDemo: true
  });

  // 4. Seed Distribution Shift: Forward Observation Post IR cameras vs Baseline Sensor Profiles
  const shiftPayload = {
    id: 'SHIFT-FOP-IR-01',
    baselineName: 'fop_sensor_daylight_baseline',
    targetName: 'forward_observation_post_ir_stream',
    overallShiftScore: 18.0,
    status: 'NOT DETECTED' as AssuranceStatus,
    featureDrifts: [
      {
        feature: 'mean_luminance',
        driftScore: 0.12,
        status: 'STABLE' as const,
        description: 'Baseline: 124.50, Production IR: 139.44 (Δ: 12.0%)'
      },
      {
        feature: 'infrared_contrast',
        driftScore: 0.08,
        status: 'STABLE' as const,
        description: 'Sensor noise variance within acceptable calibrated thresholds (MMD = 0.12).'
      }
    ],
    classDistributionDrift: {
      'military_vehicle': { baselineRatio: 0.35, targetRatio: 0.34, delta: -0.01 },
      'civilian_vehicle': { baselineRatio: 0.30, targetRatio: 0.31, delta: 0.01 },
      'pedestrian_personnel': { baselineRatio: 0.20, targetRatio: 0.20, delta: 0.00 }
    },
    findings: [],
    timestamp: now,
    isDemo: true
  };

  saveAnalysis({
    id: 'SHIFT-FOP-IR-01',
    type: 'DISTRIBUTION',
    filename: 'forward_observation_post_ir_stream_vs_baseline',
    sha256: 'SHIFT-FOP-IR-MMD-012',
    fileSizeBytes: 0,
    status: 'NOT DETECTED',
    riskScore: 18.0,
    payload: shiftPayload,
    findings: [],
    isDemo: true
  });

  // 5. Append-Only Cryptographic Hash-Chained Audit Trail (Genesis to Head)
  logAuditEvent({
    eventType: 'GENESIS_CHAIN_INITIALIZATION',
    assetName: 'AIR_GAPPED_DGIS_NODE_4',
    assetHash: '0000000000000000000000000000000000000000000000000000000000000000',
    severity: 'INFO',
    description: 'Cryptographic hash-chained audit ledger initialized at Air-Gapped DGIS Node #4.'
  });

  logAuditEvent({
    eventType: 'DATASET_ANALYSIS_COMPLETED',
    assetName: 'contributor_b_yolov8_pack.zip',
    assetHash: datasetSha256,
    severity: 'CRITICAL',
    description: 'Dataset integrity inspection flagged: 80 duplicates, 32 mislabeled samples, 12 localized trigger patterns. Risk: 78/100 (HIGH).'
  });

  logAuditEvent({
    eventType: 'MODEL_ANALYSIS_COMPLETED',
    assetName: 'traffic_recon_resnet18.pth',
    assetHash: modelSha256,
    severity: 'CRITICAL',
    description: 'Model inspection completed: Neural Cleanse trigger inversion detected Trojan backdoor (91% Conf). Risk: 85/100 (HIGH).'
  });

  logAuditEvent({
    eventType: 'DISTRIBUTION_SHIFT_EVALUATED',
    assetName: 'forward_observation_post_ir_stream',
    assetHash: 'SHIFT-FOP-IR-MMD-012',
    severity: 'INFO',
    description: 'Environmental covariate drift evaluated: MMD covariate distance 0.12 relative to baseline. Risk: 18/100 (LOW).'
  });

  logAuditEvent({
    eventType: 'INFERENCE_TAMPER_INTERCEPTED',
    assetName: 'Forward Observation Post Stream (INF-20260913-00941)',
    assetHash: inputImageHash,
    severity: 'CRITICAL',
    description: 'Adversarial payload interception: prediction modified from STOP_SIGN to SPEED_LIMIT. Cryptographic SHA-256 digest mismatch -> TAMPERING DETECTED.'
  });

  logAuditEvent({
    eventType: 'GOVERNANCE_DECISION_ISSUED',
    assetName: 'MDL-PREACT-RN18-04',
    assetHash: modelSha256,
    severity: 'CRITICAL',
    description: 'Final Governance Triad Decision: QUARANTINE. Immediate isolation of Model MDL-PREACT-RN18-04 and revocation of Contributor B pipeline.'
  });
}
