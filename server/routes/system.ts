/**
 * Health, configuration and evaluation-data routes.
 *
 * `/api/system/config` is the endpoint that previously allowed the ML engine URL to be
 * set to any http(s) address, turning it into an exfiltration channel for every uploaded
 * dataset and checkpoint. It is now capability-gated, validated against the loopback and
 * private-range allowlist, and every change is written to the audit ledger.
 *
 * The demo seeding endpoints are capability-gated *and* refused entirely when demo mode
 * is off, so a production node has no path to them at all.
 */

import type { Express, Request, Response } from 'express';
import { CONFIG, isAllowedEngineUrl } from '../config.js';
import { appendAuditEvent, verifyAuditChain } from '../db/audit.js';
import { databaseStats } from '../db/index.js';
import { purgeEvaluationData, platformStatistics } from '../db/repositories.js';
import { checkEngineHealth, getEngineUrl, setEngineUrl } from '../engineClient.js';
import { captureException, log } from '../logger.js';
import { getKeyring } from '../security/keyring.js';
import { actorOf, requireAuth, requireCapability } from '../security/guards.js';
import { rateLimit } from '../security/middleware.js';
import { systemConfigSchema, validate, validated } from '../security/validation.js';
import { seedEvaluationData } from '../demo/seed.js';

const adminLimiter = rateLimit({ capacity: 20, refillPerSecond: 20 / 60, name: 'admin' });

export function registerSystemRoutes(app: Express): void {
  /**
   * Liveness and readiness. Unauthenticated by design so a supervisor can probe it, and
   * therefore deliberately free of anything an anonymous caller should not learn: no
   * paths, no versions of dependencies, no configuration values.
   */
  const health = async (_req: Request, res: Response): Promise<void> => {
    const engine = await checkEngineHealth();
    res.json({
      status: 'HEALTHY',
      service: 'TrustVision',
      timestamp: new Date().toISOString(),
      engine: { status: engine.status },
      // Whether a read-only evaluation session is on offer. Safe to publish: it reveals
      // nothing an attacker could not learn by calling the endpoint, and the sign-in
      // screen needs it before it has a session.
      demoMode: CONFIG.demoMode,
    });
  };

  app.get('/health', (req, res) => {
    health(req, res).catch(() => res.status(503).json({ status: 'DEGRADED' }));
  });
  app.get('/api/health', (req, res) => {
    health(req, res).catch(() => res.status(503).json({ status: 'DEGRADED' }));
  });

  /** The detailed view, which does expose internals and therefore requires a session. */
  app.get('/api/system/status', requireAuth, (_req: Request, res: Response) => {
    checkEngineHealth(true)
      .then((engine) => {
        const keyring = getKeyring();
        const chain = verifyAuditChain();
        res.json({
          service: 'TrustVision',
          version: '2.0.0',
          environment: CONFIG.environment,
          demoMode: CONFIG.demoMode,
          timestamp: new Date().toISOString(),
          engine: {
            url: engine.url,
            status: engine.status,
            error: engine.error ?? null,
            capabilities: (engine.details?.capabilities as Record<string, boolean>) ?? null,
            backbone: engine.details?.backbone ?? null,
          },
          database: { path: CONFIG.databasePath, ...databaseStats() },
          signing: {
            available: keyring.available,
            keyId: keyring.id,
            publicKey: keyring.publicKeyInfo(),
            error: keyring.error,
          },
          auditLedger: {
            valid: chain.valid,
            chainLength: chain.chainLength,
            signedBlocks: chain.signedBlocks,
            headHash: chain.headHash,
          },
          riskWeights: { dataset: 0.35, model: 0.35, inference: 0.15, distributionShift: 0.15 },
          decisionThresholds: { acceptBelow: 30, quarantineAtOrAbove: 70 },
          airGapped: true,
          statistics: platformStatistics(),
        });
      })
      .catch((error) => {
        const incidentId = captureException(error, 'system/status');
        res.status(500).json({ error: 'Status unavailable.', code: 'STATUS_ERROR', incidentId });
      });
  });

  // Kept for the existing console, which reads mlServiceUrl/mlServiceStatus.
  app.get('/api/system/config', requireAuth, (_req: Request, res: Response) => {
    checkEngineHealth()
      .then((engine) => {
        res.json({
          mlServiceUrl: getEngineUrl(),
          mlServiceStatus: engine.status,
          databasePath: CONFIG.databasePath,
          demoMode: CONFIG.demoMode,
          environment: CONFIG.environment,
          weights: { datasetWeight: 0.35, modelWeight: 0.35, inferenceWeight: 0.15, shiftWeight: 0.15 },
          decisionThresholds: { acceptBelow: 30, quarantineAtOrAbove: 70 },
        });
      })
      .catch(() => res.status(503).json({ error: 'Configuration unavailable.', code: 'STATUS_ERROR' }));
  });

  app.post(
    '/api/system/config',
    requireAuth,
    requireCapability('system:configure'),
    adminLimiter,
    validate(systemConfigSchema),
    (req: Request, res: Response) => {
      const { engineUrl } = validated<{ engineUrl?: string }>(req);
      if (!engineUrl) {
        res.json({ success: true, mlServiceUrl: getEngineUrl(), changed: false });
        return;
      }

      const verdict = isAllowedEngineUrl(engineUrl);
      if (!verdict.ok) {
        // Refusal is itself security-relevant: a request to point the engine at an
        // external host is what data exfiltration looks like from here.
        log.warn('engine url change refused', { attempted: engineUrl, reason: verdict.reason });
        appendAuditEvent({
          eventType: 'ENGINE_URL_CHANGE_REFUSED',
          assetName: 'system-configuration',
          severity: 'HIGH',
          actor: actorOf(req),
          description: `Attempt to point the assurance engine at a non-permitted host was refused: ${verdict.reason}`,
          metadata: { attempted: engineUrl, reason: verdict.reason, ip: req.clientIp },
        });
        res.status(400).json({
          error: `Engine URL refused: ${verdict.reason}`,
          code: 'ENGINE_URL_REFUSED',
          policy:
            'The assurance engine must run on loopback or a private-range address. This constraint ' +
            'exists because the engine receives every uploaded dataset and checkpoint.',
        });
        return;
      }

      const previous = getEngineUrl();
      const applied = setEngineUrl(engineUrl);
      if (!applied.ok) {
        res.status(400).json({ error: applied.reason, code: 'ENGINE_URL_REFUSED' });
        return;
      }

      appendAuditEvent({
        eventType: 'ENGINE_URL_CHANGED',
        assetName: 'system-configuration',
        severity: 'MEDIUM',
        actor: actorOf(req),
        description: `Assurance engine endpoint changed from ${previous} to ${getEngineUrl()}.`,
        metadata: { previous, current: getEngineUrl(), ip: req.clientIp },
      });

      res.json({ success: true, mlServiceUrl: getEngineUrl(), changed: true, previous });
    }
  );

  // --- evaluation data --------------------------------------------------------

  const demoOnly = (_req: Request, res: Response, next: () => void): void => {
    if (!CONFIG.demoMode) {
      res.status(404).json({
        error: 'Evaluation data management is not available on this node.',
        code: 'DEMO_DISABLED',
      });
      return;
    }
    next();
  };

  app.post(
    '/api/demo/seed',
    requireAuth,
    requireCapability('demo:manage'),
    adminLimiter,
    demoOnly,
    (req: Request, res: Response) => {
      try {
        const summary = seedEvaluationData(actorOf(req));
        res.json({ success: true, ...summary });
      } catch (error) {
        const incidentId = captureException(error, 'demo/seed');
        res.status(500).json({ error: 'Seeding failed.', code: 'SEED_ERROR', incidentId });
      }
    }
  );

  app.delete(
    '/api/demo/clear',
    requireAuth,
    requireCapability('demo:manage'),
    adminLimiter,
    demoOnly,
    (req: Request, res: Response) => {
      // This removes real evaluation records, not just the demo fixture, so it must be an
      // explicit act. A caller that has not set `confirm` is refused rather than silently
      // wiping the node.
      if ((req.body as { confirm?: unknown } | undefined)?.confirm !== true) {
        res.status(400).json({
          error: 'Confirmation required to purge all evaluation records.',
          code: 'CONFIRM_REQUIRED',
        });
        return;
      }
      try {
        const result = purgeEvaluationData(actorOf(req));
        res.json({
          success: true,
          ...result,
          note: 'All evaluation records were removed. The append-only audit ledger was not touched; the purge itself is recorded in it.',
        });
      } catch (error) {
        const incidentId = captureException(error, 'demo/clear');
        res.status(500).json({ error: 'Purge failed.', code: 'CLEAR_ERROR', incidentId });
      }
    }
  );
}
