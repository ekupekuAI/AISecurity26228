/**
 * Inference provenance routes: seal, verify, and the replay ledger.
 *
 * Sealing binds the five elements the problem statement names -- input digest, model
 * digest, preprocessing and inference configuration, the prediction, and a nonce plus
 * timestamp -- into one canonical document, hashes it and signs it.
 *
 * Verification is done entirely in the gateway rather than proxied to the engine. That is
 * deliberate: tamper detection must keep working when the engine is down, because "the
 * integrity checker was offline" is exactly when an adversary would act.
 */

import type { Express, Request, Response } from 'express';
import { appendAuditEvent } from '../db/audit.js';
import {
  claimNonce,
  getInferenceRecord,
  listInferenceRecords,
  markInferenceStatus,
  saveInferenceRecord,
} from '../db/repositories.js';
import { captureException, log } from '../logger.js';
import {
  canonicalDocument,
  newNonce,
  newRecordId,
  seal,
  stalenessVerdict,
  verify,
} from '../provenance/records.js';
import type { InferenceRecordInput } from '../provenance/records.js';
import { getKeyring } from '../security/keyring.js';
import { actorOf, requireAuth, requireCapability } from '../security/guards.js';
import { rateLimit } from '../security/middleware.js';
import {
  paginationSchema,
  sealInferenceSchema,
  validate,
  validated,
  verifyInferenceSchema,
} from '../security/validation.js';

/** Operational streams seal continuously, so this ceiling is high but not unbounded. */
const sealLimiter = rateLimit({ capacity: 240, refillPerSecond: 4, name: 'inference-seal' });
const verifyLimiter = rateLimit({ capacity: 240, refillPerSecond: 4, name: 'inference-verify' });

const DEFAULT_CONFIG = {
  input_resolution: [224, 224],
  mean_norm: [0.485, 0.456, 0.406],
  std_norm: [0.229, 0.224, 0.225],
  confidence_threshold: 0.5,
};

export function registerInferenceRoutes(app: Express): void {
  // --- seal ------------------------------------------------------------------

  const handleSeal = (req: Request, res: Response): void => {
    const body = validated<{
      recordId?: string;
      inputImageSha256: string;
      modelIdentifier: string;
      modelSha256: string;
      inferenceConfig?: Record<string, unknown>;
      prediction: string;
      confidence: number;
      timestampUtc?: string;
      nonce?: string;
    }>(req);

    const record: InferenceRecordInput = {
      recordId: body.recordId ?? newRecordId(),
      inputImageSha256: body.inputImageSha256,
      modelIdentifier: body.modelIdentifier,
      modelSha256: body.modelSha256,
      inferenceConfig: body.inferenceConfig ?? DEFAULT_CONFIG,
      prediction: body.prediction,
      confidence: body.confidence,
      timestampUtc: body.timestampUtc ?? new Date().toISOString(),
      nonce: body.nonce ?? newNonce(),
    };

    const sealed = seal(record);

    // Claim the nonce at seal time. A nonce that is only checked on verification leaves
    // the sealing path free to mint duplicates, and the ledger is what makes replay
    // detectable later.
    const claim = claimNonce({
      nonce: record.nonce,
      recordId: record.recordId,
      recordHash: sealed.recordSha256,
      inputHash: record.inputImageSha256,
      modelHash: record.modelSha256,
      prediction: record.prediction,
    });

    if (!claim.fresh) {
      appendAuditEvent({
        eventType: 'INFERENCE_SEAL_REFUSED',
        assetName: record.recordId,
        assetHash: record.inputImageSha256,
        severity: 'HIGH',
        actor: actorOf(req),
        description: `Sealing refused: ${claim.reason}`,
        metadata: { kind: claim.kind, originalRecordId: claim.originalRecordId, nonce: '[redacted]' },
      });
      res.status(409).json({
        error: claim.reason,
        code: claim.kind ?? 'NONCE_CONFLICT',
        firstSeenAt: claim.firstSeenAt,
        originalRecordId: claim.originalRecordId,
      });
      return;
    }

    saveInferenceRecord({
      recordId: record.recordId,
      inputHash: record.inputImageSha256,
      modelIdentifier: record.modelIdentifier,
      modelHash: record.modelSha256,
      configuration: record.inferenceConfig,
      prediction: record.prediction,
      confidence: record.confidence,
      timestamp: record.timestampUtc,
      nonce: record.nonce,
      recordHash: sealed.recordSha256,
      signature: sealed.signature,
      signingKeyId: sealed.signingKeyId,
      canonical: JSON.stringify(sealed.document),
      status: 'VERIFIED',
      sealedBy: actorOf(req),
    });

    appendAuditEvent({
      eventType: 'INFERENCE_SEALED',
      assetName: record.recordId,
      assetHash: record.inputImageSha256,
      severity: 'INFO',
      actor: actorOf(req),
      description:
        `Inference record ${record.recordId} sealed: '${record.prediction}' at ` +
        `${(record.confidence * 100).toFixed(2)}% confidence, bound to model ` +
        `${record.modelSha256.slice(0, 12)}...`,
      metadata: {
        recordHash: sealed.recordSha256,
        signed: sealed.signature !== null,
        signingKeyId: sealed.signingKeyId,
      },
    });

    res.json({
      ...sealed.document,
      recordSha256: sealed.recordSha256,
      signature: sealed.signature,
      signingKeyId: sealed.signingKeyId,
      signatureAlgorithm: sealed.signatureAlgorithm,
      canonicalization: sealed.canonicalization,
      canonicalString: sealed.canonical,
      signingError: sealed.signingError,
      sealedAt: sealed.sealedAt,
      status: 'VERIFIED',
    });
  };

  for (const path of ['/analyze/inference', '/api/analyze/inference', '/api/inference/seal']) {
    app.post(
      path,
      requireAuth,
      requireCapability('inference:seal'),
      sealLimiter,
      validate(sealInferenceSchema),
      (req, res) => {
        try {
          handleSeal(req, res);
        } catch (error) {
          const incidentId = captureException(error, 'inference/seal');
          res.status(500).json({ error: 'Inference sealing failed.', code: 'SEAL_ERROR', incidentId });
        }
      }
    );
  }

  // --- verify ----------------------------------------------------------------

  const handleVerify = (req: Request, res: Response): void => {
    const body = validated<{
      recordId?: string;
      inputImageSha256: string;
      modelIdentifier: string;
      modelSha256: string;
      inferenceConfig?: Record<string, unknown>;
      prediction: string;
      confidence: number;
      timestampUtc?: string;
      nonce?: string;
      recordSha256: string;
      signature?: string | null;
      signingKeyId?: string | null;
      checkReplay?: boolean;
    }>(req);

    const record: InferenceRecordInput = {
      recordId: body.recordId ?? 'UNKNOWN',
      inputImageSha256: body.inputImageSha256,
      modelIdentifier: body.modelIdentifier,
      modelSha256: body.modelSha256,
      inferenceConfig: body.inferenceConfig ?? DEFAULT_CONFIG,
      prediction: body.prediction,
      confidence: body.confidence,
      timestampUtc: body.timestampUtc ?? '',
      nonce: body.nonce ?? '',
    };

    // When we hold the original, the verifier can name the changed fields rather than
    // only reporting that something changed.
    const stored = body.recordId ? getInferenceRecord(body.recordId) : null;
    const reference = (stored?.canonical as Record<string, unknown> | undefined) ?? null;

    const result = verify({
      record,
      expectedHash: body.recordSha256,
      signature: body.signature ?? null,
      signingKeyId: body.signingKeyId ?? null,
      reference,
    });

    const staleness = stalenessVerdict(record.timestampUtc);
    let replay: Record<string, unknown> | null = null;

    // Replay is only meaningful for an otherwise-intact record: a tampered payload is
    // already disqualified, and reporting both muddies the alert.
    if (result.status === 'VERIFIED' && body.checkReplay !== false && record.nonce) {
      const claim = claimNonce({
        nonce: record.nonce,
        recordId: record.recordId,
        recordHash: result.computedHash,
        inputHash: record.inputImageSha256,
        modelHash: record.modelSha256,
        prediction: record.prediction,
      });

      // A nonce claimed by *this same record* at seal time is not a replay.
      const selfClaim = claim.kind === 'REPLAY' && claim.originalRecordId === record.recordId;

      if (!claim.fresh && !selfClaim) {
        result.status = 'REPLAYED';
        result.mismatches.push(claim.reason ?? 'Replay detected.');
        replay = {
          kind: claim.kind,
          reason: claim.reason,
          firstSeenAt: claim.firstSeenAt,
          originalRecordId: claim.originalRecordId,
        };
      } else if (staleness.stale) {
        result.status = 'REPLAYED';
        result.mismatches.push(staleness.reason ?? 'Record is stale.');
        replay = { kind: 'STALE', reason: staleness.reason, skewSeconds: staleness.skewSeconds };
      }
    }

    if (body.recordId && stored) {
      markInferenceStatus(body.recordId, result.status);
    }

    if (result.status !== 'VERIFIED') {
      log.warn('inference verification failed', { recordId: record.recordId, status: result.status });
      appendAuditEvent({
        eventType: `INFERENCE_${result.status}`,
        assetName: record.recordId,
        assetHash: record.inputImageSha256,
        severity: 'CRITICAL',
        actor: actorOf(req),
        description:
          `Inference integrity failure (${result.status}) on record ${record.recordId}: ` +
          (result.mismatches[0] ?? 'no detail available'),
        metadata: {
          computedHash: result.computedHash,
          expectedHash: result.expectedHash,
          alteredFields: result.alteredFields,
          signatureValid: result.signatureValid,
          replay,
        },
      });
    }

    res.json({
      ...result,
      replay,
      staleness,
      recordId: record.recordId,
    });
  };

  for (const path of ['/verify/inference', '/api/verify/inference', '/api/inference/verify']) {
    app.post(
      path,
      requireAuth,
      requireCapability('inference:verify'),
      verifyLimiter,
      validate(verifyInferenceSchema),
      (req, res) => {
        try {
          handleVerify(req, res);
        } catch (error) {
          const incidentId = captureException(error, 'inference/verify');
          res.status(500).json({ error: 'Inference verification failed.', code: 'VERIFY_ERROR', incidentId });
        }
      }
    );
  }

  // --- reads ------------------------------------------------------------------

  app.get(
    '/api/inference-records',
    requireAuth,
    validate(paginationSchema, 'query'),
    (req: Request, res: Response) => {
      const { limit, offset } = validated<{ limit: number; offset: number }>(req, 'query');
      res.json(listInferenceRecords(limit, offset));
    }
  );

  app.get('/api/provenance/public-key', requireAuth, (_req: Request, res: Response) => {
    const keyring = getKeyring();
    res.json({
      available: keyring.available,
      key: keyring.publicKeyInfo(),
      error: keyring.error,
      canonicalization: 'RFC8785-JCS',
      schema: 'aia-inference/1',
      signatureAlgorithm: 'Ed25519 (RFC 8032)',
      note:
        'Verification needs only this public key. Any party holding it can independently ' +
        'confirm that a sealed record was produced by this node and has not been altered.',
    });
  });

  /**
   * Recompute a stored record's digest from its own canonical document.
   *
   * This is the self-audit path: it answers "is what we have on disk still what we
   * sealed", which is a different question from verifying a record presented by a caller.
   */
  app.get('/api/inference/:id/reverify', requireAuth, (req: Request, res: Response) => {
    const stored = getInferenceRecord(req.params.id);
    if (!stored) {
      res.status(404).json({ error: 'Inference record not found.', code: 'NOT_FOUND' });
      return;
    }

    const document = stored.canonical as Record<string, unknown>;
    const record: InferenceRecordInput = {
      recordId: String(document.recordId ?? req.params.id),
      inputImageSha256: String(document.inputImageSha256 ?? ''),
      modelIdentifier: String(document.modelIdentifier ?? ''),
      modelSha256: String(document.modelSha256 ?? ''),
      inferenceConfig: (document.inferenceConfig as Record<string, unknown>) ?? {},
      prediction: String(document.prediction ?? ''),
      confidence: Number(document.confidence ?? 0),
      timestampUtc: String(document.timestampUtc ?? ''),
      nonce: String(document.nonce ?? ''),
    };

    const result = verify({
      record,
      expectedHash: String(stored.recordHash),
      signature: (stored.signature as string | null) ?? null,
      signingKeyId: (stored.signingKeyId as string | null) ?? null,
    });

    res.json({
      recordId: req.params.id,
      storedStatus: stored.status,
      recomputed: result,
      canonicalDocument: canonicalDocument(record),
    });
  });
}
