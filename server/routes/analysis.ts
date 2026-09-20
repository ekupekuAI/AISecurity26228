/**
 * Dataset, model and distribution-shift analysis routes.
 *
 * Uploads are held in memory only for as long as it takes to forward them, and are never
 * written to disk under a caller-influenced name. The previous build's
 * `/api/demo/load-real-fixture` endpoint -- which took a filesystem path from the request
 * body and read it -- is removed entirely; it was an arbitrary-file-read primitive
 * reachable by anyone who could reach the (then unauthenticated) admin surface.
 */

import crypto from 'node:crypto';
import type { Express, Request, Response } from 'express';
import multer from 'multer';
import { CONFIG } from '../config.js';
import {
  analyzeDatasetRemote,
  analyzeModelRemote,
  analyzeShiftRemote,
  checkEngineHealth,
  markDegraded,
} from '../engineClient.js';
import { captureException, log } from '../logger.js';
import {
  analyzeDatasetFallback,
  analyzeModelFallback,
  analyzeShiftFallback,
} from '../analyzers/fallback.js';
import {
  acknowledgeFinding,
  getAnalysisById,
  listAnalyses,
  listContributors,
  listFindings,
  ownerTag,
  saveAnalysis,
} from '../db/repositories.js';
import type { FindingRecord } from '../db/repositories.js';
import { actorOf, ownerOf, requireAuth, requireCapability } from '../security/guards.js';
import { evaluateAssetGovernance } from './governance.js';
import { appendAuditEvent } from '../db/audit.js';
import { enforceContentLength, rateLimit } from '../security/middleware.js';
import {
  ALLOWED_DATASET_EXTENSIONS,
  ALLOWED_MODEL_EXTENSIONS,
  acknowledgeSchema,
  distributionShiftSchema,
  extensionOf,
  paginationSchema,
  safeFilename,
  validate,
  validated,
} from '../security/validation.js';

/**
 * Memory storage with a hard ceiling. Disk storage would mean writing attacker-named
 * files; memory keeps the bytes in exactly one place with a bound already applied, and
 * the buffer is released as soon as the engine call returns.
 */
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: CONFIG.maxUploadBytes, files: 1, fields: 8, parts: 12 },
});

/** Analysis is expensive; a handful of concurrent submissions is the realistic ceiling. */
const analysisLimiter = rateLimit({ capacity: 10, refillPerSecond: 10 / 60, name: 'analysis' });

function uploadErrorResponse(error: unknown, res: Response): boolean {
  if (error instanceof multer.MulterError) {
    const message =
      error.code === 'LIMIT_FILE_SIZE'
        ? `Upload exceeds the ${Math.floor(CONFIG.maxUploadBytes / 1024 / 1024)} MB ceiling.`
        : `Upload rejected: ${error.code}.`;
    res.status(413).json({ error: message, code: 'PAYLOAD_TOO_LARGE' });
    return true;
  }
  return false;
}

function toFindingRecords(raw: unknown): FindingRecord[] {
  if (!Array.isArray(raw)) return [];
  return raw
    .filter((item): item is Record<string, unknown> => Boolean(item) && typeof item === 'object')
    .map((item) => ({
      id: typeof item.id === 'string' ? item.id : undefined,
      findingId: String(item.findingId ?? 'UNKNOWN'),
      category: String(item.category ?? 'DATASET'),
      severity: (['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'].includes(String(item.severity))
        ? String(item.severity)
        : 'INFO') as FindingRecord['severity'],
      confidence: Number(item.confidence ?? 0),
      affectedAsset: String(item.affectedAsset ?? ''),
      explanation: String(item.explanation ?? ''),
      evidence: item.evidence ?? {},
      recommendation: String(item.recommendation ?? ''),
      detector: typeof item.detector === 'string' ? item.detector : null,
      threshold: typeof item.threshold === 'string' ? item.threshold : null,
      references: Array.isArray(item.references) ? (item.references as string[]) : [],
      timestamp: typeof item.timestamp === 'string' ? item.timestamp : undefined,
    }));
}

/**
 * Run a fallback analysis and record that it happened.
 *
 * "No silent degradation" is enforced in three places at once: the result is flagged
 * `degraded` and carries a MEDIUM coverage-gap finding (markDegraded), the event is written
 * to the append-only audit ledger at HIGH severity so an assessor sees it on the timeline,
 * and the asset-scoped governance decision downgrades to at best REVIEW. A degraded
 * assessment can never be mistaken for, or laundered into, a completed one.
 */
function degradeModel(filename: string, buffer: Buffer, reason: string, actor: string): Record<string, unknown> {
  log.warn('engine unavailable; using gateway fallback for model analysis', { reason, filename });
  const result = markDegraded(analyzeModelFallback(filename, buffer) as unknown as Record<string, unknown>, reason);
  recordDegradation('MODEL', filename, String(result.sha256 ?? ''), reason, actor);
  return result;
}

function degradeDataset(filename: string, buffer: Buffer, reason: string, actor: string): Record<string, unknown> {
  log.warn('engine unavailable; using gateway fallback for dataset analysis', { reason, filename });
  const result = markDegraded(analyzeDatasetFallback(filename, buffer) as unknown as Record<string, unknown>, reason);
  recordDegradation('DATASET', filename, String(result.sha256 ?? ''), reason, actor);
  return result;
}

function recordDegradation(kind: string, filename: string, sha256: string, reason: string, actor: string): void {
  try {
    appendAuditEvent({
      eventType: 'ANALYSIS_DEGRADED',
      assetName: filename,
      assetHash: sha256,
      severity: 'HIGH',
      actor,
      description:
        `${kind} analysis of ${filename} fell back to the degraded gateway analyser because the Python ` +
        `assurance engine was unreachable (${reason}). Deep-learning detectors did not run; this result ` +
        `cannot certify the asset and governance is capped at REVIEW.`,
      metadata: { engine: 'node-fallback', reason },
    });
  } catch (error) {
    // The ledger append must never turn an already-degraded analysis into a hard failure.
    log.error('failed to record degradation audit event', { error: error instanceof Error ? error.message : String(error) });
  }
}

export function registerAnalysisRoutes(app: Express): void {
  // --- dataset ---------------------------------------------------------------

  const handleDataset = async (req: Request, res: Response): Promise<void> => {
    if (!req.file) {
      res.status(400).json({ error: 'No file part in the request.', code: 'NO_FILE' });
      return;
    }

    const filename = safeFilename(req.file.originalname);
    const extension = extensionOf(filename);
    // A recognised extension is required: an unlabelled blob is not routed to a detector by
    // guesswork. Accepting an empty extension previously let a file bypass the allowlist
    // entirely, which is the kind of gap a hostile upload is built to find.
    if (!extension || !ALLOWED_DATASET_EXTENSIONS.has(extension)) {
      res.status(415).json({
        error: extension
          ? `Extension '${extension}' is not accepted for dataset submission.`
          : 'A dataset upload must carry a recognised file extension.',
        code: 'UNSUPPORTED_MEDIA_TYPE',
        accepted: [...ALLOWED_DATASET_EXTENSIONS],
      });
      return;
    }

    const buffer = req.file.buffer;
    const sha256 = crypto.createHash('sha256').update(buffer).digest('hex');
    log.info('dataset analysis requested', { filename, bytes: buffer.length, sha256, actor: actorOf(req) });

    let result: Record<string, unknown>;
    try {
      result = await analyzeDatasetRemote(filename, buffer);
    } catch (error) {
      const reason = error instanceof Error ? error.message : String(error);
      result = degradeDataset(filename, buffer, reason, actorOf(req));
    }

    const ownerId = ownerOf(req);
    // Persist under a content-derived id (not the engine's random uuid) so re-analysing the
    // same file replaces its evidence via ON CONFLICT/DELETE-findings instead of piling up
    // duplicate rows. The id is namespaced by owner so two operators analysing the same file
    // still get independent rows; result.id is set to match so the response, the attached
    // governance subject and every later lookup all reference the same per-user analysis.
    const engineId = `DS-${sha256.slice(0, 12).toUpperCase()}`;
    const analysisId = ownerTag(ownerId) ? `${engineId}-${ownerTag(ownerId)}` : engineId;
    result.id = analysisId;
    const findings = toFindingRecords(result.findings);

    // Asset-scoped decision, computed from THIS submission's evidence alone, attached to
    // both the response and the persisted payload so every consumer sees the same verdict.
    result.governance = evaluateAssetGovernance({
      analysisId,
      type: 'DATASET',
      filename,
      sha256: String(result.sha256 ?? sha256),
      risk: Number(result.datasetRisk ?? 0),
      engine: String(result.engine ?? 'unknown'),
      degraded: Boolean(result.degraded),
      findings: findings as unknown as Array<Record<string, unknown>>,
      ownerId,
    });

    saveAnalysis({
      id: analysisId,
      type: 'DATASET',
      filename,
      sha256: String(result.sha256 ?? sha256),
      fileSizeBytes: buffer.length,
      status: String(result.status ?? 'ANALYSIS FAILED'),
      riskScore: Number(result.datasetRisk ?? 0),
      engine: String(result.engine ?? 'unknown'),
      durationSeconds: result.analysisDurationSeconds == null ? null : Number(result.analysisDurationSeconds),
      payload: result,
      findings,
      contributors: Array.isArray(result.contributorProfiles)
        ? (result.contributorProfiles as Array<Record<string, unknown>>)
        : [],
      performedBy: actorOf(req),
      ownerId,
    });

    res.json(result);
  };

  for (const path of ['/analyze/dataset', '/api/analyze/dataset']) {
    app.post(
      path,
      requireAuth,
      requireCapability('analysis:run'),
      analysisLimiter,
      enforceContentLength(CONFIG.maxUploadBytes),
      (req, res, next) => {
        upload.single('file')(req, res, (error) => {
          if (error && uploadErrorResponse(error, res)) return;
          if (error) {
            next(error);
            return;
          }
          next();
        });
      },
      (req, res) => {
        handleDataset(req, res).catch((error) => {
          const incidentId = captureException(error, 'analyze/dataset');
          res.status(500).json({ error: 'Dataset analysis failed.', code: 'ANALYSIS_ERROR', incidentId });
        });
      }
    );
  }

  // --- model -----------------------------------------------------------------

  const handleModel = async (req: Request, res: Response): Promise<void> => {
    if (!req.file) {
      res.status(400).json({ error: 'No file part in the request.', code: 'NO_FILE' });
      return;
    }

    const filename = safeFilename(req.file.originalname);
    const extension = extensionOf(filename);
    if (!extension || !ALLOWED_MODEL_EXTENSIONS.has(extension)) {
      res.status(415).json({
        error: extension
          ? `Extension '${extension}' is not accepted for model submission.`
          : 'A model upload must carry a recognised file extension.',
        code: 'UNSUPPORTED_MEDIA_TYPE',
        accepted: [...ALLOWED_MODEL_EXTENSIONS],
      });
      return;
    }

    const buffer = req.file.buffer;
    const sha256 = crypto.createHash('sha256').update(buffer).digest('hex');
    log.info('model analysis requested', { filename, bytes: buffer.length, sha256, actor: actorOf(req) });

    let result: Record<string, unknown>;
    try {
      result = await analyzeModelRemote(filename, buffer);
    } catch (error) {
      const reason = error instanceof Error ? error.message : String(error);
      result = degradeModel(filename, buffer, reason, actorOf(req));
    }

    const ownerId = ownerOf(req);
    // Content-derived id (see the dataset handler) so re-analysing the same checkpoint
    // replaces its findings rather than accumulating duplicates.
    const engineId = `MOD-${sha256.slice(0, 12).toUpperCase()}`;
    const analysisId = ownerTag(ownerId) ? `${engineId}-${ownerTag(ownerId)}` : engineId;
    result.id = analysisId;
    const findings = toFindingRecords(result.findings);

    result.governance = evaluateAssetGovernance({
      analysisId,
      type: 'MODEL',
      filename,
      sha256: String(result.sha256 ?? sha256),
      risk: Number(result.modelRisk ?? 0),
      engine: String(result.engine ?? 'unknown'),
      degraded: Boolean(result.degraded),
      findings: findings as unknown as Array<Record<string, unknown>>,
      ownerId,
    });

    saveAnalysis({
      id: analysisId,
      type: 'MODEL',
      filename,
      sha256: String(result.sha256 ?? sha256),
      fileSizeBytes: buffer.length,
      status: String(result.status ?? 'ANALYSIS FAILED'),
      riskScore: Number(result.modelRisk ?? 0),
      engine: String(result.engine ?? 'unknown'),
      analysisMode: result.analysisMode == null ? null : String(result.analysisMode),
      durationSeconds: result.analysisDurationSeconds == null ? null : Number(result.analysisDurationSeconds),
      payload: result,
      findings,
      performedBy: actorOf(req),
      ownerId,
    });

    res.json(result);
  };

  for (const path of ['/analyze/model', '/api/analyze/model']) {
    app.post(
      path,
      requireAuth,
      requireCapability('analysis:run'),
      analysisLimiter,
      enforceContentLength(CONFIG.maxUploadBytes),
      (req, res, next) => {
        upload.single('file')(req, res, (error) => {
          if (error && uploadErrorResponse(error, res)) return;
          if (error) {
            next(error);
            return;
          }
          next();
        });
      },
      (req, res) => {
        handleModel(req, res).catch((error) => {
          const incidentId = captureException(error, 'analyze/model');
          res.status(500).json({ error: 'Model analysis failed.', code: 'ANALYSIS_ERROR', incidentId });
        });
      }
    );
  }

  // --- distribution shift ------------------------------------------------------

  app.post(
    '/api/analyze/distribution-shift',
    requireAuth,
    requireCapability('analysis:run'),
    analysisLimiter,
    validate(distributionShiftSchema),
    (req: Request, res: Response) => {
      const body = validated<Record<string, unknown>>(req);

      const run = async (): Promise<Record<string, unknown>> => {
        try {
          return await analyzeShiftRemote({
            baseline_name: body.baselineName,
            target_name: body.targetName,
            baseline_vectors: body.baselineVectors,
            target_vectors: body.targetVectors,
            feature_names: body.featureNames,
            baseline_features: body.baselineFeatures,
            target_features: body.targetFeatures,
            baseline_class_ratios: body.baselineClassRatios,
            target_class_ratios: body.targetClassRatios,
          });
        } catch (error) {
          const reason = error instanceof Error ? error.message : String(error);
          log.warn('engine unavailable; using gateway fallback for shift analysis', { reason });
          recordDegradation('DISTRIBUTION', `${String(body.targetName)}_vs_${String(body.baselineName)}`, '', reason, actorOf(req));
          return markDegraded(
            analyzeShiftFallback({
              baselineName: String(body.baselineName ?? 'baseline'),
              targetName: String(body.targetName ?? 'target'),
              baselineFeatures: body.baselineFeatures as Record<string, number> | undefined,
              targetFeatures: body.targetFeatures as Record<string, number> | undefined,
              baselineClassRatios: body.baselineClassRatios as Record<string, number> | undefined,
              targetClassRatios: body.targetClassRatios as Record<string, number> | undefined,
            }) as unknown as Record<string, unknown>,
            reason
          );
        }
      };

      run()
        .then((result) => {
          const ownerId = ownerOf(req);
          const engineId = String(result.id ?? `SHIFT-${Date.now()}`);
          const analysisId = ownerTag(ownerId) ? `${engineId}-${ownerTag(ownerId)}` : engineId;
          result.id = analysisId;
          saveAnalysis({
            id: analysisId,
            type: 'DISTRIBUTION',
            filename: `${String(body.targetName)}_vs_${String(body.baselineName)}`,
            sha256: crypto
              .createHash('sha256')
              .update(`${String(body.baselineName)}:${String(body.targetName)}:${engineId}`)
              .digest('hex'),
            fileSizeBytes: 0,
            status: String(result.status ?? 'NOT DETECTED'),
            riskScore: Number(result.overallShiftScore ?? 0),
            engine: String(result.engine ?? 'unknown'),
            payload: result,
            findings: toFindingRecords(result.findings),
            performedBy: actorOf(req),
            ownerId,
          });
          res.json(result);
        })
        .catch((error) => {
          const incidentId = captureException(error, 'analyze/distribution-shift');
          res.status(500).json({ error: 'Distribution-shift analysis failed.', code: 'ANALYSIS_ERROR', incidentId });
        });
    }
  );

  // --- reads -------------------------------------------------------------------

  app.get('/api/analysis', requireAuth, validate(paginationSchema, 'query'), (req: Request, res: Response) => {
    const { limit, offset, type } = validated<{ limit: number; offset: number; type?: string }>(req, 'query');
    res.json(listAnalyses(limit, offset, type as never, ownerOf(req)));
  });

  app.get('/api/analysis/:id', requireAuth, (req: Request, res: Response) => {
    const analysis = getAnalysisById(req.params.id, ownerOf(req));
    if (!analysis) {
      res.status(404).json({ error: 'Analysis not found.', code: 'NOT_FOUND' });
      return;
    }
    res.json(analysis);
  });

  app.get('/api/findings', requireAuth, validate(paginationSchema, 'query'), (req: Request, res: Response) => {
    const { limit, offset, severity } = validated<{ limit: number; offset: number; severity?: string }>(req, 'query');
    res.json(listFindings(limit, offset, severity, ownerOf(req)));
  });

  app.get('/api/contributors', requireAuth, (req: Request, res: Response) => {
    res.json(listContributors(100, ownerOf(req)));
  });

  app.post(
    '/api/findings/:id/acknowledge',
    requireAuth,
    requireCapability('finding:acknowledge'),
    validate(acknowledgeSchema, 'params'),
    (req: Request, res: Response) => {
      const { id } = validated<{ id: string }>(req, 'params');
      const changed = acknowledgeFinding(id, actorOf(req), ownerOf(req));
      if (!changed) {
        res.status(404).json({ error: 'Finding not found or already acknowledged.', code: 'NOT_FOUND' });
        return;
      }
      res.json({ success: true, acknowledgedBy: actorOf(req), acknowledgedAt: new Date().toISOString() });
    }
  );

  // Legacy aliases kept so existing clients and scripts continue to work.
  app.get('/analysis', requireAuth, (req, res) => res.json(listAnalyses(50, 0, undefined, ownerOf(req))));
  app.get('/findings', requireAuth, (req, res) => res.json(listFindings(100, 0, undefined, ownerOf(req))));

  app.get('/api/engine/health', requireAuth, (_req: Request, res: Response) => {
    checkEngineHealth(true)
      .then((health) => res.json(health))
      .catch((error) => {
        const incidentId = captureException(error, 'engine/health');
        res.status(500).json({ error: 'Health check failed.', code: 'ENGINE_ERROR', incidentId });
      });
  });
}
