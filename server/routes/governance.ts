/**
 * Governance: the decision triad, the formal assurance report, and the audit ledger.
 *
 * The decision thresholds are the problem statement's, not the previous build's: ACCEPT
 * below 30, REVIEW from 30 to 69, QUARANTINE at 70 and above. The old code quarantined at
 * 50 and reviewed above 20, which would have been an immediate and visible
 * non-conformance.
 *
 * Override conditions are evaluated before the score. A cryptographic tamper, a confirmed
 * backdoor or a malicious checkpoint disqualifies an asset regardless of how healthy the
 * remaining pillars are -- averaging a fatal defect against four clean ones is precisely
 * how a real failure gets released.
 */

import crypto from 'node:crypto';
import type { Express, Request, Response } from 'express';
import { listAuditEvents, verifyAuditChain } from '../db/audit.js';
import { db } from '../db/index.js';
import {
  getAnalysisById,
  inferenceRecordsForModel,
  listAnalyses,
  listContributors,
  listFindings,
  listInferenceRecords,
  platformStatistics,
} from '../db/repositories.js';
import { captureException } from '../logger.js';
import { canonicalize } from '../provenance/canonical.js';
import { DOMAIN_REPORT, getKeyring } from '../security/keyring.js';
import { requireAuth, requireCapability } from '../security/guards.js';
import { paginationSchema, validate, validated } from '../security/validation.js';

/** Fixed by the problem statement. */
export const DECISION_THRESHOLDS = { acceptBelow: 30, quarantineAtOrAbove: 70 } as const;

/**
 * A backdoor is "confirmed" only when a detector said so explicitly, not inferred from a
 * risk number. These finding ids are the contract between the engine and the override rule.
 */
const BACKDOOR_FINDING_IDS = new Set([
  'MOD-NEURAL-CLEANSE-TRIGGER',
  'MOD-BEHAVIOURAL-BACKDOOR-RESPONSE',
  'DS-BACKDOOR-TRIGGER-INJECTION',
]);

const MALICIOUS_SERIALIZATION_IDS = new Set(['SEC-MALICIOUS-PICKLE-OPCODE', 'SEC-BROKEN-PICKLE-STREAM']);

/** Findings that declare a coverage gap: they cannot yield ACCEPT because absence of
 *  evidence is not evidence of absence. */
const COVERAGE_GAP_IDS = new Set([
  'SYS-DEGRADED-ANALYSIS',
  'MOD-WHITEBOX-UNAVAILABLE',
  'MOD-TRIGGER-SCAN-INCOMPLETE',
  'MOD-ONNX-BEHAVIOURAL-UNAVAILABLE',
]);

const findingId = (f: Record<string, unknown>): string => String(f.findingId ?? f.finding_id ?? 'UNKNOWN');

export interface GovernanceEvaluation {
  decision: 'ACCEPT' | 'REVIEW' | 'QUARANTINE';
  actionRequired: string;
  rationale: string;
  triggeredRules: string[];
  thresholds: typeof DECISION_THRESHOLDS;
  overallRisk: number;
  trustScore: number;
  componentRisks: Record<string, number>;
  evaluatedAt: string;
  /** 'PLATFORM' for the node-wide posture, 'ASSET' for a single-asset decision. */
  scope?: 'PLATFORM' | 'ASSET';
  /** Present only on an asset-scoped decision: which asset it is about. */
  subject?: { analysisId: string; type: string; filename: string; sha256: string };
}

function gatherSignals() {
  const stats = platformStatistics();
  const findings = listFindings(500, 0);
  const inference = listInferenceRecords(500, 0);
  const analyses = listAnalyses(200, 0);

  const hasCritical = findings.some((f) => f.severity === 'CRITICAL' && !f.acknowledgedAt);
  const compromisedRecords = inference.filter((r) =>
    ['TAMPERED', 'FORGED', 'REPLAYED'].includes(String(r.status))
  );

  const hasBackdoor = findings.some((f) => BACKDOOR_FINDING_IDS.has(findingId(f)));

  const maliciousSerialization = findings.some((f) => MALICIOUS_SERIALIZATION_IDS.has(findingId(f)));

  // Any engine that could not complete is a coverage gap, and a coverage gap can never
  // yield ACCEPT -- absence of evidence is not evidence of absence.
  const incompleteAnalysis = analyses.some((a) => a.engine === 'node-fallback' || a.status === 'ANALYSIS FAILED');
  const coverageFindings = findings.filter((f) => COVERAGE_GAP_IDS.has(findingId(f)));

  return {
    stats,
    findings,
    inference,
    analyses,
    hasCritical,
    compromisedRecords,
    hasBackdoor,
    maliciousSerialization,
    incompleteAnalysis: incompleteAnalysis || coverageFindings.length > 0,
    coverageFindings,
  };
}

/**
 * Node-wide posture: a single verdict over everything the node currently holds. This is
 * the dashboard's "are we clean right now" view. It is deliberately NOT the decision for
 * any one asset -- see {@link evaluateAssetGovernance} for that.
 */
export function evaluateGovernance(): GovernanceEvaluation {
  return { ...platformGovernance(), scope: 'PLATFORM' };
}

function platformGovernance(): GovernanceEvaluation {
  const signals = gatherSignals();
  const { stats } = signals;
  const overallRisk = stats.overallRisk;
  const evaluatedAt = new Date().toISOString();

  const componentRisks = {
    dataset: stats.datasetRisk,
    model: stats.modelRisk,
    inference: stats.inferenceIntegrityRisk,
    distributionShift: stats.distributionShiftRisk,
  };

  const overrides: string[] = [];
  if (signals.maliciousSerialization) {
    overrides.push('MALICIOUS_SERIALIZATION: a submitted checkpoint contains an execution primitive or a broken pickle stream');
  }
  if (signals.compromisedRecords.length > 0) {
    const kinds = [...new Set(signals.compromisedRecords.map((r) => String(r.status)))].join(', ');
    overrides.push(`INFERENCE_INTEGRITY_FAILURE: ${signals.compromisedRecords.length} record(s) in state ${kinds}`);
  }
  if (signals.hasBackdoor) {
    overrides.push('BACKDOOR_CONFIRMED: trigger inversion, behavioural battery or dataset consensus confirmed a backdoor');
  }
  if (signals.hasCritical) {
    overrides.push('CRITICAL_FINDING: at least one unacknowledged CRITICAL finding is outstanding');
  }

  if (overrides.length > 0) {
    return {
      decision: 'QUARANTINE',
      actionRequired:
        'IMMEDIATE OPERATIONAL QUARANTINE. Isolate the affected assets, revoke the contributing ' +
        'ingest pipeline, preserve the artefacts for forensic analysis and notify the security ' +
        'officer. Do not deploy under a compensating control.',
      rationale:
        'A mandatory override fired. These conditions are not averaged against the composite ' +
        'score because a single disqualifying defect cannot be offset by healthy pillars elsewhere.',
      triggeredRules: overrides,
      thresholds: DECISION_THRESHOLDS,
      overallRisk,
      trustScore: stats.overallTrustScore,
      componentRisks,
      evaluatedAt,
    };
  }

  if (overallRisk >= DECISION_THRESHOLDS.quarantineAtOrAbove) {
    return {
      decision: 'QUARANTINE',
      actionRequired:
        'Isolate the asset and revoke its deployment authorisation. Remediate the highest-weighted ' +
        'findings and resubmit for a complete re-assessment.',
      rationale: `Composite risk ${overallRisk.toFixed(1)} meets or exceeds the quarantine threshold of ${DECISION_THRESHOLDS.quarantineAtOrAbove}.`,
      triggeredRules: [`COMPOSITE_RISK >= ${DECISION_THRESHOLDS.quarantineAtOrAbove}`],
      thresholds: DECISION_THRESHOLDS,
      overallRisk,
      trustScore: stats.overallTrustScore,
      componentRisks,
      evaluatedAt,
    };
  }

  if (overallRisk >= DECISION_THRESHOLDS.acceptBelow || signals.incompleteAnalysis) {
    const rules: string[] = [];
    if (overallRisk >= DECISION_THRESHOLDS.acceptBelow) {
      rules.push(`COMPOSITE_RISK in [${DECISION_THRESHOLDS.acceptBelow}, ${DECISION_THRESHOLDS.quarantineAtOrAbove})`);
    }
    if (signals.incompleteAnalysis) {
      rules.push(
        `COVERAGE_GAP: ${signals.coverageFindings.length || 1} assessment(s) did not complete every engine`
      );
    }
    return {
      decision: 'REVIEW',
      actionRequired:
        'Human-in-the-loop analyst triage required before operational release. Restrict the asset to ' +
        'a limited operational scope and obtain secondary sign-off from the Lead Assurance Engineer.',
      rationale:
        `Composite risk ${overallRisk.toFixed(1)} sits in the review band` +
        (signals.incompleteAnalysis
          ? ', and at least one engine could not complete its assessment, so a clean result cannot be certified.'
          : '.'),
      triggeredRules: rules,
      thresholds: DECISION_THRESHOLDS,
      overallRisk,
      trustScore: stats.overallTrustScore,
      componentRisks,
      evaluatedAt,
    };
  }

  return {
    decision: 'ACCEPT',
    actionRequired:
      'Authorised for operational deployment. A cryptographic seal has been issued and recorded in ' +
      'the append-only audit ledger.',
    rationale:
      `Composite risk ${overallRisk.toFixed(1)} is below the acceptance threshold of ` +
      `${DECISION_THRESHOLDS.acceptBelow}, no override condition fired, and every engine completed ` +
      'its assessment.',
    triggeredRules: [`COMPOSITE_RISK < ${DECISION_THRESHOLDS.acceptBelow}`],
    thresholds: DECISION_THRESHOLDS,
    overallRisk,
    trustScore: stats.overallTrustScore,
    componentRisks,
    evaluatedAt,
  };
}

export interface AssetGovernanceInput {
  analysisId: string;
  type: string;
  filename: string;
  sha256: string;
  /** This asset's own risk, 0-100 (modelRisk / datasetRisk / shift score). */
  risk: number;
  engine: string;
  degraded: boolean;
  findings: Array<Record<string, unknown>>;
}

/**
 * Decide the fate of ONE asset from ONLY that asset's own evidence.
 *
 * The override rules and decision bands are identical to the node-wide posture, but every
 * signal is scoped: the findings are this analysis's findings, the inference-integrity
 * check looks only at records bound to this checkpoint's digest, and the composite risk is
 * this asset's own risk rather than a weighted blend across whatever else the node has
 * seen. Uploading a malicious checkpoint no longer condemns the clean dataset examined
 * beside it, which the composite view could not distinguish.
 */
export function evaluateAssetGovernance(input: AssetGovernanceInput): GovernanceEvaluation {
  const evaluatedAt = new Date().toISOString();
  const findings = input.findings ?? [];
  const overallRisk = Math.round(Math.min(100, Math.max(0, input.risk)) * 10) / 10;
  const trustScore = Math.round((100 - overallRisk) * 10) / 10;

  const componentRisks: Record<string, number> =
    input.type === 'MODEL'
      ? { model: overallRisk }
      : input.type === 'DATASET'
        ? { dataset: overallRisk }
        : input.type === 'DISTRIBUTION'
          ? { distributionShift: overallRisk }
          : { asset: overallRisk };

  const subject = {
    analysisId: input.analysisId,
    type: input.type,
    filename: input.filename,
    sha256: input.sha256,
  };
  const base = { thresholds: DECISION_THRESHOLDS, overallRisk, trustScore, componentRisks, evaluatedAt, scope: 'ASSET' as const, subject };

  const hasCritical = findings.some((f) => String(f.severity) === 'CRITICAL' && !f.acknowledgedAt);
  const hasBackdoor = findings.some((f) => BACKDOOR_FINDING_IDS.has(findingId(f)));
  const maliciousSerialization = findings.some((f) => MALICIOUS_SERIALIZATION_IDS.has(findingId(f)));
  const hasCoverageGap =
    input.degraded || input.engine === 'node-fallback' || findings.some((f) => COVERAGE_GAP_IDS.has(findingId(f)));

  // Inference integrity is a model concern, and only for records produced by THIS model.
  const compromised =
    input.type === 'MODEL'
      ? inferenceRecordsForModel(input.sha256).filter((r) => ['TAMPERED', 'FORGED', 'REPLAYED'].includes(String(r.status)))
      : [];

  const overrides: string[] = [];
  if (maliciousSerialization) {
    overrides.push('MALICIOUS_SERIALIZATION: this checkpoint contains an execution primitive or a broken pickle stream');
  }
  if (compromised.length > 0) {
    const kinds = [...new Set(compromised.map((r) => String(r.status)))].join(', ');
    overrides.push(`INFERENCE_INTEGRITY_FAILURE: ${compromised.length} record(s) bound to this model are in state ${kinds}`);
  }
  if (hasBackdoor) {
    overrides.push('BACKDOOR_CONFIRMED: trigger inversion, behavioural battery or dataset consensus confirmed a backdoor in this asset');
  }
  if (hasCritical) {
    overrides.push('CRITICAL_FINDING: this asset has at least one unacknowledged CRITICAL finding');
  }

  if (overrides.length > 0) {
    return {
      ...base,
      decision: 'QUARANTINE',
      actionRequired:
        'IMMEDIATE OPERATIONAL QUARANTINE of this asset. Isolate it, revoke the contributing ingest ' +
        'pipeline, preserve the artefact for forensic analysis and notify the security officer. Do not ' +
        'deploy under a compensating control.',
      rationale:
        'A mandatory override fired on this asset. These conditions are not averaged against the risk ' +
        'score because a single disqualifying defect cannot be offset by healthy evidence elsewhere.',
      triggeredRules: overrides,
    };
  }

  if (overallRisk >= DECISION_THRESHOLDS.quarantineAtOrAbove) {
    return {
      ...base,
      decision: 'QUARANTINE',
      actionRequired:
        'Isolate this asset and revoke its deployment authorisation. Remediate the highest-weighted ' +
        'findings and resubmit for a complete re-assessment.',
      rationale: `This asset's risk ${overallRisk.toFixed(1)} meets or exceeds the quarantine threshold of ${DECISION_THRESHOLDS.quarantineAtOrAbove}.`,
      triggeredRules: [`ASSET_RISK >= ${DECISION_THRESHOLDS.quarantineAtOrAbove}`],
    };
  }

  if (overallRisk >= DECISION_THRESHOLDS.acceptBelow || hasCoverageGap) {
    const rules: string[] = [];
    if (overallRisk >= DECISION_THRESHOLDS.acceptBelow) {
      rules.push(`ASSET_RISK in [${DECISION_THRESHOLDS.acceptBelow}, ${DECISION_THRESHOLDS.quarantineAtOrAbove})`);
    }
    if (hasCoverageGap) {
      rules.push('COVERAGE_GAP: this assessment did not complete every engine, so a clean result cannot be certified');
    }
    return {
      ...base,
      decision: 'REVIEW',
      actionRequired:
        'Human-in-the-loop analyst triage required before operational release. Restrict this asset to a ' +
        'limited operational scope and obtain secondary sign-off from the Lead Assurance Engineer.',
      rationale:
        `This asset's risk ${overallRisk.toFixed(1)} sits in the review band` +
        (hasCoverageGap
          ? ', and at least one engine could not complete its assessment, so a clean result cannot be certified.'
          : '.'),
      triggeredRules: rules,
    };
  }

  return {
    ...base,
    decision: 'ACCEPT',
    actionRequired:
      'This asset is authorised for operational deployment. A cryptographic seal can be issued and ' +
      'recorded in the append-only audit ledger.',
    rationale:
      `This asset's risk ${overallRisk.toFixed(1)} is below the acceptance threshold of ` +
      `${DECISION_THRESHOLDS.acceptBelow}, no override condition fired, and its assessment completed.`,
    triggeredRules: [`ASSET_RISK < ${DECISION_THRESHOLDS.acceptBelow}`],
  };
}

/** Build an asset-scoped decision from a stored analysis id, or null if it does not exist. */
export function assetGovernanceForAnalysis(analysisId: string): GovernanceEvaluation | null {
  const analysis = getAnalysisById(analysisId);
  if (!analysis) return null;
  const type = String(analysis.type ?? 'MODEL');
  const risk =
    type === 'MODEL'
      ? Number(analysis.modelRisk ?? analysis.riskScore ?? 0)
      : type === 'DATASET'
        ? Number(analysis.datasetRisk ?? analysis.riskScore ?? 0)
        : type === 'DISTRIBUTION'
          ? Number(analysis.overallShiftScore ?? analysis.riskScore ?? 0)
          : Number(analysis.riskScore ?? 0);
  return evaluateAssetGovernance({
    analysisId,
    type,
    filename: String(analysis.filename ?? 'submitted asset'),
    sha256: String(analysis.sha256 ?? ''),
    risk,
    engine: String(analysis.engine ?? 'unknown'),
    degraded: Boolean(analysis.degraded),
    findings: Array.isArray(analysis.findings) ? (analysis.findings as Array<Record<string, unknown>>) : [],
  });
}

export function registerGovernanceRoutes(app: Express): void {
  app.get('/api/stats', requireAuth, (_req: Request, res: Response) => {
    const stats = platformStatistics();
    res.json({
      ...stats,
      recentAnalyses: listAnalyses(10, 0),
      recentAuditEvents: listAuditEvents(10, 0),
      topContributors: listContributors(5),
    });
  });

  app.get('/api/governance/decision', requireAuth, (_req: Request, res: Response) => {
    res.json(evaluateGovernance());
  });

  // Asset-scoped decision: the verdict for one analysis, from its own evidence alone.
  app.get('/api/governance/decision/:id', requireAuth, (req: Request, res: Response) => {
    const decision = assetGovernanceForAnalysis(String(req.params.id));
    if (!decision) {
      res.status(404).json({ error: 'No analysis with that id.', code: 'NOT_FOUND' });
      return;
    }
    res.json(decision);
  });

  app.get(
    '/api/audit-events',
    requireAuth,
    validate(paginationSchema, 'query'),
    (req: Request, res: Response) => {
      const { limit, offset } = validated<{ limit: number; offset: number }>(req, 'query');
      res.json(listAuditEvents(limit, offset));
    }
  );

  app.get('/api/audit/verify-chain', requireAuth, requireCapability('audit:verify'), (_req, res) => {
    res.json(verifyAuditChain());
  });

  /**
   * The formal assurance report of the problem statement's section 10.
   *
   * The report is itself canonicalised, hashed and Ed25519-signed, so a report handed to
   * a third party can be independently verified. A report that merely quotes a hash of
   * its own contents proves nothing.
   */
  app.get('/api/governance/report', requireAuth, requireCapability('report:generate'), (req: Request, res: Response) => {
    try {
      const evaluation = evaluateGovernance();
      const stats = platformStatistics();
      const findings = listFindings(200, 0);
      const inference = listInferenceRecords(50, 0);
      const contributors = listContributors(10);
      const chain = verifyAuditChain();

      const latest = (type: string) =>
        (db
          .prepare(`SELECT filename, sha256, status, risk_score FROM analyses WHERE type = ? ORDER BY created_at DESC LIMIT 1`)
          .get(type) as Record<string, unknown> | undefined) ?? undefined;

      const dataset = latest('DATASET');
      const model = latest('MODEL');
      const shift = latest('DISTRIBUTION');

      const compromised = inference.filter((r) => ['TAMPERED', 'FORGED', 'REPLAYED'].includes(String(r.status)));

      const body = {
        schema: 'trustvision-report/1',
        reportId: `ASSURE-${new Date().getFullYear()}-${crypto.randomBytes(3).toString('hex').toUpperCase()}`,
        generatedAt: new Date().toISOString(),
        generatedBy: req.session?.user.username ?? 'system',
        classification: 'CONFIDENTIAL / RESTRICTED',
        deployment: process.env.AIA_NODE_ID ?? 'AIR-GAPPED ASSURANCE NODE',
        problemStatementId: 'SIH26228 (Ministry of Defence / Indian Army DGIS)',

        assets: {
          dataset: dataset
            ? { name: String(dataset.filename), sha256: String(dataset.sha256), status: String(dataset.status), risk: Number(dataset.risk_score) }
            : null,
          model: model
            ? { name: String(model.filename), sha256: String(model.sha256), status: String(model.status), risk: Number(model.risk_score) }
            : null,
          distributionShift: shift
            ? { name: String(shift.filename), status: String(shift.status), risk: Number(shift.risk_score) }
            : null,
        },

        risk: {
          datasetRisk: stats.datasetRisk,
          modelRisk: stats.modelRisk,
          distributionShiftRisk: stats.distributionShiftRisk,
          inferenceIntegrityRisk: stats.inferenceIntegrityRisk,
          overallRisk: evaluation.overallRisk,
          trustScore: evaluation.trustScore,
          componentWeights: { dataset: 0.35, model: 0.35, inference: 0.15, distributionShift: 0.15 },
        },

        inferenceIntegrity: {
          status: compromised.length > 0 ? 'COMPROMISED' : 'VERIFIED',
          totalRecords: stats.inferenceRecordCount,
          compromisedRecords: compromised.length,
          detail: compromised.slice(0, 10).map((r) => ({
            recordId: r.id,
            status: r.status,
            prediction: r.prediction,
            modelSha256: r.modelSha256,
          })),
        },

        findings: {
          total: findings.length,
          critical: findings.filter((f) => f.severity === 'CRITICAL').length,
          high: findings.filter((f) => f.severity === 'HIGH').length,
          medium: findings.filter((f) => f.severity === 'MEDIUM').length,
          top: findings.slice(0, 15).map((f) => ({
            findingId: f.findingId,
            severity: f.severity,
            confidence: f.confidence,
            category: f.category,
            affectedAsset: f.affectedAsset,
            explanation: f.explanation,
            detector: f.detector,
            threshold: f.threshold,
            recommendation: f.recommendation,
          })),
        },

        contributors: contributors.slice(0, 8).map((c) => ({
          name: c.name,
          sampleCount: c.sampleCount,
          defectCount: c.defectCount,
          riskScore: c.riskScore,
          drivers: c.drivers,
        })),

        auditLedger: {
          valid: chain.valid,
          chainLength: chain.chainLength,
          headHash: chain.headHash,
          signedBlocks: chain.signedBlocks,
          details: chain.details,
        },

        decision: evaluation.decision,
        actionRequired: evaluation.actionRequired,
        rationale: evaluation.rationale,
        triggeredRules: evaluation.triggeredRules,
        thresholds: evaluation.thresholds,
      };

      const keyring = getKeyring();
      const canonical = canonicalize(body);
      const digest = crypto.createHash('sha256').update(canonical, 'utf8').digest('hex');
      const signed = keyring.sign(Buffer.from(canonical, 'utf8'), DOMAIN_REPORT);

      res.json({
        ...body,
        seal: {
          canonicalization: 'RFC8785-JCS',
          sha256: digest,
          signature: signed?.signature ?? null,
          signingKeyId: signed?.keyId ?? null,
          algorithm: signed ? 'Ed25519' : null,
          verificationNote:
            'Re-canonicalise this document with every field except "seal", take its SHA-256 and ' +
            'verify the signature with the node public key from /api/provenance/public-key.',
        },
      });
    } catch (error) {
      const incidentId = captureException(error, 'governance/report');
      res.status(500).json({ error: 'Report generation failed.', code: 'REPORT_ERROR', incidentId });
    }
  });

  /** Plain-text rendering of the report, matching the PS section 10 layout. */
  app.get('/api/governance/report.txt', requireAuth, requireCapability('report:generate'), (req: Request, res: Response) => {
    try {
      const evaluation = evaluateGovernance();
      const stats = platformStatistics();
      const findings = listFindings(50, 0);
      const chain = verifyAuditChain();
      const inference = listInferenceRecords(50, 0);
      const compromised = inference.filter((r) => ['TAMPERED', 'FORGED', 'REPLAYED'].includes(String(r.status)));

      const line = '='.repeat(88);
      const rule = '-'.repeat(88);
      const reportId = `ASSURE-${new Date().getFullYear()}-${crypto.randomBytes(3).toString('hex').toUpperCase()}`;

      const band = (risk: number) => (risk >= 70 ? 'HIGH' : risk >= 30 ? 'MEDIUM' : 'LOW');
      const verdict = (risk: number) => (risk >= 30 ? '[FAIL]' : '[PASS]');

      const section = (title: string, risk: number, notes: string[]) =>
        [
          `[${title}] RISK SCORE: ${risk.toFixed(0)}/100   SEVERITY: ${band(risk)}   ${verdict(risk)}`,
          ...notes.map((note) => `   -> ${note}`),
          '',
        ].join('\n');

      const noteFor = (category: string) =>
        findings
          .filter((f) => f.category === category)
          .slice(0, 4)
          .map((f) => `[${f.severity}] ${f.explanation}`);

      const text = [
        line,
        '  TRUSTVISION ASSURANCE REPORT',
        line,
        `  REPORT ID    : ${reportId}`,
        `  GENERATED    : ${new Date().toISOString()}`,
        `  GENERATED BY : ${req.session?.user.name ?? 'system'} (${req.session?.user.role ?? 'SYSTEM'})`,
        '  CLASSIFICATION: CONFIDENTIAL / RESTRICTED',
        `  DEPLOYMENT   : ${process.env.AIA_NODE_ID ?? 'AIR-GAPPED ASSURANCE NODE'}`,
        '  PROBLEM STMT : SIH26228 (MoD / Indian Army DGIS)',
        rule,
        '',
        'INTEGRITY AUDIT BREAKDOWN',
        '',
        section('DATASET INTEGRITY', stats.datasetRisk, noteFor('DATASET').length ? noteFor('DATASET') : ['No dataset findings recorded.']),
        section('MODEL INTEGRITY', stats.modelRisk, noteFor('MODEL').length ? noteFor('MODEL') : ['No model findings recorded.']),
        section('DISTRIBUTION SHIFT', stats.distributionShiftRisk, noteFor('DISTRIBUTION').length ? noteFor('DISTRIBUTION') : ['No covariate drift beyond calibrated tolerance.']),
        `[INFERENCE INTEGRITY] STATUS: ${compromised.length > 0 ? 'COMPROMISED' : 'VERIFIED'}   ${compromised.length > 0 ? 'SEVERITY: CRITICAL   [FAIL]' : '[PASS]'}`,
        ...(compromised.length > 0
          ? compromised.slice(0, 5).map((r) => `   -> Record ${r.id}: ${r.status} (prediction '${r.prediction}')`)
          : [`   -> ${stats.inferenceRecordCount} sealed record(s); all digests and signatures verify.`]),
        '',
        `[AUDIT LEDGER] ${chain.valid ? 'INTACT' : 'BROKEN'}   ${chain.chainLength} block(s), ${chain.signedBlocks} signed`,
        `   -> ${chain.details}`,
        '',
        rule,
        `FINAL GOVERNANCE DECISION: ${evaluation.decision}`,
        `COMPOSITE RISK: ${evaluation.overallRisk.toFixed(1)}/100    TRUST SCORE: ${evaluation.trustScore.toFixed(1)}/100`,
        `THRESHOLDS: ACCEPT < ${evaluation.thresholds.acceptBelow} | REVIEW ${evaluation.thresholds.acceptBelow}-${evaluation.thresholds.quarantineAtOrAbove - 1} | QUARANTINE >= ${evaluation.thresholds.quarantineAtOrAbove}`,
        '',
        'TRIGGERED RULES:',
        ...evaluation.triggeredRules.map((r) => `   - ${r}`),
        '',
        'ACTION REQUIRED:',
        ...evaluation.actionRequired.match(/.{1,84}(\s|$)/g)?.map((chunk) => `   ${chunk.trim()}`) ?? [],
        '',
        'RATIONALE:',
        ...evaluation.rationale.match(/.{1,84}(\s|$)/g)?.map((chunk) => `   ${chunk.trim()}`) ?? [],
        line,
      ].join('\n');

      res.setHeader('Content-Type', 'text/plain; charset=utf-8');
      res.setHeader('Content-Disposition', `attachment; filename="${reportId}.txt"`);
      res.send(text);
    } catch (error) {
      const incidentId = captureException(error, 'governance/report.txt');
      res.status(500).json({ error: 'Report rendering failed.', code: 'REPORT_ERROR', incidentId });
    }
  });
}
