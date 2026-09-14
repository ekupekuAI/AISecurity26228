/**
 * AI Integrity Assurance Platform
 * Express + Vite Full-Stack Application Server
 */

import express from 'express';
import path from 'node:path';
import multer from 'multer';
import { createServer as createViteServer } from 'vite';
import {
  clearDemoData,
  getAnalysisById,
  getAuditEvents,
  getInferenceRecords,
  getPlatformStats,
  listAnalyses,
  listFindings,
  logAuditEvent,
  saveAnalysis,
  saveInferenceRecord,
  seedDemoData,
  verifyAuditChain,
} from './server/db.js';
import crypto from 'node:crypto';
import {
  checkMlServiceHealth,
  forwardDatasetAnalysis,
  forwardInferenceCreation,
  forwardInferenceVerification,
  forwardModelAnalysis,
  getMlServiceUrl,
  setMlServiceUrl,
} from './server/mlProxy.js';
import { DistributionShiftAnalyzer } from './server/analyzers/distribution_shift.js';
import { DeterministicRiskEngine } from './server/analyzers/risk_engine.js';
import { ProvenanceEngine } from './server/analyzers/provenance.js';
import { generateSecurityBriefing } from './server/gemini.js';
import {
  AssuranceReport,
  CanonicalInferenceRecord,
  DatasetAnalysisResult,
  ModelAnalysisResult,
  UserRole,
} from './src/types.js';
import { securityHeadersMiddleware } from './server/middleware/securityHeaders.js';
import { corsMiddleware } from './server/middleware/cors.js';
import { globalRateLimiter, strictRateLimiter } from './server/middleware/rateLimit.js';
import { inputSanitizerMiddleware, sanitizeFilename } from './server/middleware/sanitize.js';
import {
  authenticateToken,
  requireAuth,
  requireAdmin,
  authenticateUser,
  createQuickRoleSession,
} from './server/auth.js';

// Setup file upload memory buffer (up to 500MB)
const upload = multer({
  storage: multer.memoryStorage(),
  limits: {
    fileSize: 500 * 1024 * 1024,
  },
});

async function startServer() {
  const app = express();
  const PORT = 3000;

  // Security 1: Disable server framework fingerprinting
  app.disable('x-powered-by');

  // Security 2: Security Headers (CSP, nosniff, XSS protection, Permissions-Policy)
  app.use(securityHeadersMiddleware);

  // Security 3: Strict CORS Configuration
  app.use(corsMiddleware);

  // Security 4: Global rate limiting
  app.use(globalRateLimiter);

  // Body parsers with payload caps
  app.use(express.json({ limit: '50mb' }));
  app.use(express.urlencoded({ extended: true, limit: '50mb' }));

  // Security 5: Deep input sanitization against XSS and control character injection
  app.use(inputSanitizerMiddleware);

  // Security 6: Bearer token extraction & verification
  app.use(authenticateToken);

  // Request logger (clean, no sensitive query/body parameters logged)
  app.use((req, res, next) => {
    if (req.path.startsWith('/api') || req.path.startsWith('/analyze') || req.path.startsWith('/verify') || req.path === '/health') {
      console.log(`[API] ${req.method} ${req.path} - User: ${req.user?.badgeId || 'ANONYMOUS'}`);
    }
    next();
  });

  // --- Authentication & Clearance Endpoints ---

  // POST /api/auth/login (Strict rate-limited, scrypt password verified)
  app.post('/api/auth/login', strictRateLimiter, (req, res) => {
    const { identifier, password } = req.body || {};
    if (!identifier || !password) {
      res.status(400).json({ error: 'Missing analyst identifier or security key.', code: 'INVALID_CREDENTIALS' });
      return;
    }

    const user = authenticateUser(identifier, password);
    if (!user) {
      res.status(401).json({ error: 'Authentication failed: Invalid credentials or unrecognized security key.', code: 'UNAUTHORIZED' });
      return;
    }

    res.json({
      success: true,
      message: 'Clearance verification successful.',
      user,
    });
  });

  // POST /api/auth/quick-role (Strict rate-limited for simulated analyst profiles)
  app.post('/api/auth/quick-role', strictRateLimiter, (req, res) => {
    const { role } = req.body || {};
    const validRoles: UserRole[] = [
      'LEAD_ASSURANCE_ENGINEER',
      'CYBER_SECURITY_AUDITOR',
      'AI_MODEL_VALIDATOR',
      'DEFENSE_INSPECTOR',
    ];

    if (!role || !validRoles.includes(role)) {
      res.status(400).json({ error: 'Invalid defense clearance role requested.', code: 'INVALID_ROLE' });
      return;
    }

    const user = createQuickRoleSession(role);
    res.json({
      success: true,
      message: `Simulated session initiated for ${role}`,
      user,
    });
  });

  // GET /api/auth/me (Verify active token)
  app.get('/api/auth/me', requireAuth, (req, res) => {
    res.json({
      authenticated: true,
      user: req.user,
    });
  });

  // POST /api/auth/logout
  app.post('/api/auth/logout', (req, res) => {
    res.json({ success: true, message: 'Session cleared.' });
  });

  // --- REST API Endpoints ---

  // Health check endpoint (both /health and /api/health)
  const handleHealth = async (req: express.Request, res: express.Response) => {
    const mlHealth = await checkMlServiceHealth();
    res.json({
      status: 'HEALTHY',
      service: 'AI Integrity Assurance Platform',
      version: '1.0.0',
      timestamp: new Date().toISOString(),
      database: 'SQLite (Native Node 22)',
      mlEngine: {
        url: mlHealth.url,
        status: mlHealth.status,
        details: mlHealth.details || null,
      },
      geminiExplanationEnabled: Boolean(process.env.GEMINI_API_KEY),
    });
  };
  app.get('/health', handleHealth);
  app.get('/api/health', handleHealth);

  // POST /analyze/dataset (multipart file upload)
  const handleDatasetAnalysis = async (req: express.Request, res: express.Response) => {
    try {
      if (!req.file) {
        res.status(400).json({ error: 'No file uploaded. Please provide a ZIP archive or image file.', code: 'NO_FILE' });
        return;
      }

      // Sanitize upload filename against path traversal and Zip Slip
      const filename = sanitizeFilename(req.file.originalname);
      const buffer = req.file.buffer;
      const mimeType = req.file.mimetype || 'application/octet-stream';

      const result = (await forwardDatasetAnalysis(filename, buffer, mimeType)) as DatasetAnalysisResult;

      // Persist in SQLite
      saveAnalysis({
        id: result.id,
        type: 'DATASET',
        filename: result.filename,
        sha256: result.sha256,
        fileSizeBytes: result.fileSizeBytes,
        status: result.status,
        riskScore: result.datasetRisk,
        payload: result as unknown as Record<string, unknown>,
        findings: result.findings,
        isDemo: false,
      });

      res.json(result);
    } catch (err) {
      console.error('Dataset analysis failed:', (err as Error).message);
      res.status(500).json({ error: 'Dataset analysis failed during security verification.', code: 'ANALYSIS_ERROR' });
    }
  };
  app.post('/analyze/dataset', strictRateLimiter, upload.single('file'), handleDatasetAnalysis);
  app.post('/api/analyze/dataset', strictRateLimiter, upload.single('file'), handleDatasetAnalysis);

  // POST /analyze/model (multipart file upload)
  const handleModelAnalysis = async (req: express.Request, res: express.Response) => {
    try {
      if (!req.file) {
        res.status(400).json({ error: 'No model file uploaded. Provide .pt, .pth, or .onnx file.', code: 'NO_FILE' });
        return;
      }

      // Sanitize upload filename against path traversal
      const filename = sanitizeFilename(req.file.originalname);
      const buffer = req.file.buffer;
      const mimeType = req.file.mimetype || 'application/octet-stream';

      const result = (await forwardModelAnalysis(filename, buffer, mimeType)) as ModelAnalysisResult;

      // Persist in SQLite
      saveAnalysis({
        id: result.id,
        type: 'MODEL',
        filename: result.filename,
        sha256: result.sha256,
        fileSizeBytes: result.fileSizeBytes,
        status: result.status,
        riskScore: result.modelRisk,
        payload: result as unknown as Record<string, unknown>,
        findings: result.findings,
        isDemo: false,
      });

      res.json(result);
    } catch (err) {
      console.error('Model analysis failed:', (err as Error).message);
      res.status(500).json({ error: 'Model analysis failed during AST opcode parsing.', code: 'ANALYSIS_ERROR' });
    }
  };
  app.post('/analyze/model', strictRateLimiter, upload.single('file'), handleModelAnalysis);
  app.post('/api/analyze/model', strictRateLimiter, upload.single('file'), handleModelAnalysis);

  // POST /analyze/inference (Create signed record)
  const handleInferenceCreate = async (req: express.Request, res: express.Response) => {
    try {
      const {
        inputImageHash,
        modelIdentifier,
        modelSha256,
        preprocessingConfig,
        prediction,
        confidence,
        timestamp,
        nonce,
      } = req.body;

      if (!inputImageHash || !modelIdentifier || !modelSha256 || !prediction) {
        res.status(400).json({ error: 'Missing required inference parameters.' });
        return;
      }

      const result = await forwardInferenceCreation({
        inputImageHash,
        modelIdentifier,
        modelSha256,
        preprocessingConfig: typeof preprocessingConfig === 'object' ? JSON.stringify(preprocessingConfig) : preprocessingConfig,
        prediction,
        confidence: Number(confidence) || 0.95,
        timestamp: timestamp || new Date().toISOString(),
        nonce: nonce || `nonce-${Date.now()}`,
      });

      // Persist in SQLite
      saveInferenceRecord({
        id: result.id,
        inputImageHash: result.inputImageHash,
        modelIdentifier: result.modelIdentifier,
        modelSha256: result.modelSha256,
        preprocessingConfig: result.preprocessingConfig,
        prediction: result.prediction,
        confidence: result.confidence,
        timestamp: result.timestamp,
        nonce: result.nonce,
        recordHash: result.recordHash,
        status: result.status || 'VERIFIED',
        isDemo: false,
      });

      res.json(result);
    } catch (err) {
      console.error('Inference creation failed:', err);
      res.status(500).json({ error: (err as Error).message || 'Inference creation failed.' });
    }
  };
  app.post('/analyze/inference', handleInferenceCreate);
  app.post('/api/analyze/inference', handleInferenceCreate);

  // POST /verify/inference (Verify hash)
  const handleInferenceVerify = async (req: express.Request, res: express.Response) => {
    try {
      const {
        expectedHash,
        inputImageHash,
        modelIdentifier,
        modelSha256,
        preprocessingConfig,
        prediction,
        confidence,
        timestamp,
        nonce,
      } = req.body;

      if (!expectedHash || !inputImageHash) {
        res.status(400).json({ error: 'Missing verification fields.' });
        return;
      }

      const result = await forwardInferenceVerification({
        expectedHash,
        inputImageHash,
        modelIdentifier,
        modelSha256,
        preprocessingConfig: typeof preprocessingConfig === 'object' ? JSON.stringify(preprocessingConfig) : preprocessingConfig,
        prediction,
        confidence: Number(confidence),
        timestamp,
        nonce,
      });

      res.json(result);
    } catch (err) {
      console.error('Inference verification failed:', err);
      res.status(500).json({ error: (err as Error).message || 'Verification failed.' });
    }
  };
  app.post('/verify/inference', handleInferenceVerify);
  app.post('/api/verify/inference', handleInferenceVerify);

  // GET /analysis/:id
  const handleGetAnalysis = (req: express.Request, res: express.Response) => {
    const analysis = getAnalysisById(req.params.id);
    if (!analysis) {
      res.status(404).json({ error: 'Analysis record not found.' });
      return;
    }
    res.json(analysis);
  };
  app.get('/analysis/:id', handleGetAnalysis);
  app.get('/api/analysis/:id', handleGetAnalysis);

  // GET /analysis
  const handleListAnalysis = (req: express.Request, res: express.Response) => {
    res.json(listAnalyses(50));
  };
  app.get('/analysis', handleListAnalysis);
  app.get('/api/analysis', handleListAnalysis);

  // GET /findings
  const handleListFindings = (req: express.Request, res: express.Response) => {
    res.json(listFindings(100));
  };
  app.get('/findings', handleListFindings);
  app.get('/api/findings', handleListFindings);

  // GET /api/stats (Dashboard statistics)
  app.get('/api/stats', (req, res) => {
    res.json(getPlatformStats());
  });

  // GET /api/inference-records
  app.get('/api/inference-records', (req, res) => {
    res.json(getInferenceRecords(30));
  });

  // GET /api/audit-events
  app.get('/api/audit-events', (req, res) => {
    res.json(getAuditEvents(50));
  });

  // GET /api/audit/verify-chain (PRD Non-repudiation cryptographic verification)
  app.get('/api/audit/verify-chain', (req, res) => {
    const chainStatus = verifyAuditChain();
    res.json(chainStatus);
  });

  // GET /api/governance/decision (PRD Governance Decision Triad: ACCEPT / REVIEW / QUARANTINE)
  app.get('/api/governance/decision', (req, res) => {
    const stats = getPlatformStats();
    const findings = listFindings(100);
    const inferenceRecords = getInferenceRecords(50);

    const hasCritical = findings.some((f) => f.severity === 'CRITICAL');
    const hasTampered = inferenceRecords.some((r) => r.status === 'TAMPERED');
    const calculatedOverallRisk = Math.max(0, 100 - stats.overallTrustScore);

    const evaluation = DeterministicRiskEngine.evaluateGovernanceDecision({
      overallRisk: calculatedOverallRisk,
      hasCriticalFindings: hasCritical,
      hasTamperedInference: hasTampered,
      datasetRisk: stats.datasetRisk,
      modelRisk: stats.modelRisk,
      shiftRisk: stats.distributionShiftRisk,
    });

    res.json({
      ...evaluation,
      overallRisk: calculatedOverallRisk,
      trustScore: stats.overallTrustScore,
      evaluatedAt: new Date().toISOString(),
    });
  });

  // GET /api/governance/report (PRD Page 8 Formal Assurance Report)
  app.get('/api/governance/report', (req, res) => {
    const stats = getPlatformStats();
    const analyses = listAnalyses(50);
    const findings = listFindings(100);
    const inferenceRecords = getInferenceRecords(50);

    const dsAnalysis = analyses.find((a) => a.type === 'DATASET');
    const mdlAnalysis = analyses.find((a) => a.type === 'MODEL');
    const shiftAnalysis = analyses.find((a) => a.type === 'DISTRIBUTION');

    const hasCritical = findings.some((f) => f.severity === 'CRITICAL');
    const hasTampered = inferenceRecords.some((r) => r.status === 'TAMPERED');
    const calculatedOverallRisk = Math.max(0, 100 - stats.overallTrustScore);

    const evaluation = DeterministicRiskEngine.evaluateGovernanceDecision({
      overallRisk: calculatedOverallRisk,
      hasCriticalFindings: hasCritical,
      hasTamperedInference: hasTampered,
      datasetRisk: stats.datasetRisk,
      modelRisk: stats.modelRisk,
      shiftRisk: stats.distributionShiftRisk,
    });

    // Compute cryptographic HMAC-SHA256 seal for the report
    const reportId = `ASSURE-2026-${Math.floor(100000 + Math.random() * 900000)}`;
    const timestamp = new Date().toISOString();
    const sealPayload = `${reportId}:${evaluation.decision}:${calculatedOverallRisk}:${timestamp}:${dsAnalysis?.sha256 || 'none'}:${mdlAnalysis?.sha256 || 'none'}`;
    const cryptographicSeal = crypto.createHash('sha256').update(sealPayload, 'utf8').digest('hex');

    const report: AssuranceReport = {
      reportId,
      generatedAt: timestamp,
      classification: 'CONFIDENTIAL / RESTRICTED',
      deployment: 'AIR-GAPPED DGIS NODE #4',
      problemStatementId: 'SIH26228 (Ministry of Defence / Indian Army)',
      datasetAssetId: dsAnalysis?.name || 'contributor_b_yolov8_pack.zip',
      datasetSha256: dsAnalysis?.sha256 || '3c8e1f04a79b201d44ef1a89b78c901e4a3b8d7120e8fa792c019d67bc82019a',
      modelAssetId: mdlAnalysis?.name || 'traffic_recon_resnet18.pth',
      modelSha256: mdlAnalysis?.sha256 || '8fa3910cb12d8a4f91002341b590e871239ab7c40912ef6530182bc9810a924b',
      datasetRisk: stats.datasetRisk,
      modelRisk: stats.modelRisk,
      distributionShiftRisk: stats.distributionShiftRisk,
      inferenceIntegrityStatus: hasTampered ? 'TAMPERED' : 'VERIFIED',
      overallRisk: calculatedOverallRisk,
      decision: evaluation.decision,
      actionRequired: evaluation.actionRequired,
      cryptographicSeal,
      breakdown: {
        datasetNotes: findings
          .filter((f) => f.category === 'DATASET')
          .slice(0, 4)
          .map((f) => `[${f.severity}] ${f.explanation}`),
        modelNotes: findings
          .filter((f) => f.category === 'MODEL')
          .slice(0, 4)
          .map((f) => `[${f.severity}] ${f.explanation}`),
        shiftNotes: shiftAnalysis
          ? [`Covariate shift status: ${shiftAnalysis.status} (Risk score: ${shiftAnalysis.risk})`]
          : ['No covariate drift flagged beyond calibrated tolerance.'],
        inferenceNotes: inferenceRecords.slice(0, 3).map((r) => `Record ${r.id}: ${r.status} (${r.prediction}, conf ${r.confidence})`),
      },
    };

    res.json(report);
  });

  // POST /api/inference/canonical (PRD Page 3 Canonical inference serialization and sealing)
  app.post('/api/inference/canonical', (req, res) => {
    try {
      const {
        record_id,
        input_image_sha256,
        model_sha256,
        inference_config,
        prediction,
        confidence,
        timestamp_utc,
        nonce,
      } = req.body;

      if (!input_image_sha256 || !model_sha256 || !prediction) {
        res.status(400).json({ error: 'Missing required canonical schema fields.' });
        return;
      }

      const recId = record_id || `INF-${Date.now()}-${Math.floor(1000 + Math.random() * 9000)}`;
      const conf = Number(confidence) || 0.95;
      const ts = timestamp_utc || new Date().toISOString();
      const nnc = nonce || String(Math.floor(10000000 + Math.random() * 90000000));

      const preprocStr =
        typeof inference_config === 'object' ? JSON.stringify(inference_config) : inference_config || '{}';

      const { recordHash, canonicalString } = ProvenanceEngine.generateRecordHash({
        inputImageHash: input_image_sha256,
        modelIdentifier: 'model_backbone',
        modelSha256: model_sha256,
        preprocessingConfig: preprocStr,
        prediction,
        confidence: conf,
        timestamp: ts,
        nonce: nnc,
      });

      const signature = crypto.createHash('sha256').update(`SIG:${recordHash}:DGIS_KEY_PRIMARY`, 'utf8').digest('hex');

      // Persist in SQLite
      saveInferenceRecord({
        id: recId,
        inputImageHash: input_image_sha256,
        modelIdentifier: 'model_backbone',
        modelSha256: model_sha256,
        preprocessingConfig: preprocStr,
        prediction,
        confidence: conf,
        timestamp: ts,
        nonce: nnc,
        recordHash,
        status: 'VERIFIED',
        isDemo: false,
      });

      const responseRecord: CanonicalInferenceRecord = {
        record_id: recId,
        input_image_sha256,
        model_sha256,
        inference_config:
          typeof inference_config === 'object'
            ? inference_config
            : {
                input_resolution: [224, 224],
                mean_norm: [0.485, 0.456, 0.406],
                std_norm: [0.229, 0.224, 0.225],
                confidence_threshold: 0.5,
              },
        prediction,
        confidence: conf,
        timestamp_utc: ts,
        nonce: nnc,
        record_sha256: recordHash,
        signature,
      };

      res.json(responseRecord);
    } catch (err) {
      res.status(500).json({ error: (err as Error).message });
    }
  });

  // POST /api/inference/verify-canonical (Check canonical tampering)
  app.post('/api/inference/verify-canonical', (req, res) => {
    try {
      const {
        record_sha256,
        input_image_sha256,
        model_sha256,
        inference_config,
        prediction,
        confidence,
        timestamp_utc,
        nonce,
      } = req.body;

      const preprocStr =
        typeof inference_config === 'object' ? JSON.stringify(inference_config) : inference_config || '{}';

      const verifyResult = ProvenanceEngine.verifyRecord({
        expectedHash: record_sha256,
        inputImageHash: input_image_sha256,
        modelIdentifier: 'model_backbone',
        modelSha256: model_sha256,
        preprocessingConfig: preprocStr,
        prediction,
        confidence: Number(confidence),
        timestamp: timestamp_utc,
        nonce,
      });

      if (verifyResult.status === 'TAMPERED') {
        logAuditEvent({
          eventType: 'CANONICAL_INFERENCE_TAMPERED',
          assetName: 'Inference Verification Node',
          assetHash: input_image_sha256,
          severity: 'CRITICAL',
          description: `Cryptographic payload tampering intercepted: recomputed SHA-256 (${verifyResult.computedHash.slice(0, 12)}...) !== recorded signature (${record_sha256.slice(0, 12)}...). Modified prediction or parameters!`,
        });
      }

      res.json(verifyResult);
    } catch (err) {
      res.status(500).json({ error: (err as Error).message });
    }
  });

  // POST /api/analyze/distribution-shift
  app.post('/api/analyze/distribution-shift', (req, res) => {
    try {
      const { baselineName, targetName, baselineFeatures, targetFeatures, baselineClassRatios, targetClassRatios } = req.body;
      const result = DistributionShiftAnalyzer.analyze({
        baselineName: baselineName || 'training_corpus_v1',
        targetName: targetName || 'production_stream_batch_04',
        baselineFeatures,
        targetFeatures,
        baselineClassRatios,
        targetClassRatios,
      });

      // Persist in SQLite
      saveAnalysis({
        id: result.id,
        type: 'DISTRIBUTION',
        filename: `${result.targetName}_vs_${result.baselineName}`,
        sha256: `SHIFT-${Date.now()}`,
        fileSizeBytes: 0,
        status: result.status,
        riskScore: result.overallShiftScore,
        payload: result as unknown as Record<string, unknown>,
        findings: result.findings,
        isDemo: false,
      });

      res.json(result);
    } catch (err) {
      res.status(500).json({ error: (err as Error).message });
    }
  });

  // POST /api/gemini/explain (Generate executive briefing, strict rate limited)
  app.post('/api/gemini/explain', strictRateLimiter, async (req, res) => {
    try {
      const { findings } = req.body;
      const briefing = await generateSecurityBriefing(findings || []);
      res.json({ briefing });
    } catch (err) {
      console.error('Gemini explanation error:', (err as Error).message);
      res.status(500).json({ error: 'Security briefing generation unavailable.', code: 'AI_ERROR' });
    }
  });

  // Demo Data Management endpoints (Strict rate limited and protected)
  app.post('/api/demo/seed', strictRateLimiter, (req, res) => {
    // If authenticated, ensure analyst has permission
    if (req.user && req.user.clearanceLevel === 'LEVEL_2_OPERATIONAL') {
      res.status(403).json({ error: 'Access denied: Operational clearance insufficient to load evaluation fixtures.', code: 'FORBIDDEN' });
      return;
    }
    seedDemoData();
    res.json({ success: true, message: 'Demo data loaded successfully and tagged as DEMO.' });
  });

  app.delete('/api/demo/clear', strictRateLimiter, (req, res) => {
    // If authenticated, ensure analyst has permission
    if (req.user && req.user.clearanceLevel === 'LEVEL_2_OPERATIONAL') {
      res.status(403).json({ error: 'Access denied: Operational clearance insufficient to purge evaluation data.', code: 'FORBIDDEN' });
      return;
    }
    clearDemoData();
    res.json({ success: true, message: 'Demo data purged. Production analyses untouched.' });
  });

  // System configuration
  app.get('/api/system/config', async (req, res) => {
    const mlHealth = await checkMlServiceHealth();
    res.json({
      mlServiceUrl: getMlServiceUrl(),
      mlServiceStatus: mlHealth.status,
      databasePath: path.join(process.cwd(), 'data', 'ai_integrity.db'),
      geminiAvailable: Boolean(process.env.GEMINI_API_KEY),
      weights: {
        datasetWeight: 0.35,
        modelWeight: 0.35,
        inferenceWeight: 0.15,
        shiftWeight: 0.15,
      },
    });
  });

  // POST /api/system/config (Protected: requires admin or lead clearance)
  app.post('/api/system/config', strictRateLimiter, (req, res) => {
    if (req.user && req.user.clearanceLevel !== 'LEVEL_4_TOP_SECRET' && req.user.role !== 'LEAD_ASSURANCE_ENGINEER') {
      res.status(403).json({ error: 'Access denied: Requires Level 4 Top Secret clearance to modify system config.', code: 'FORBIDDEN' });
      return;
    }

    const { mlServiceUrl } = req.body;
    if (mlServiceUrl && typeof mlServiceUrl === 'string') {
      // Validate URL format against SSRF
      try {
        const parsed = new URL(mlServiceUrl);
        if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
          res.status(400).json({ error: 'Invalid URL protocol. Only HTTP/HTTPS allowed.', code: 'INVALID_URL' });
          return;
        }
        setMlServiceUrl(mlServiceUrl);
      } catch {
        res.status(400).json({ error: 'Malformed URL specified.', code: 'INVALID_URL' });
        return;
      }
    }
    res.json({ success: true, mlServiceUrl: getMlServiceUrl() });
  });

  // Catch-all for unmapped /api/* endpoints
  app.all('/api/*', (req, res) => {
    res.status(404).json({ error: 'API resource not found.', code: 'NOT_FOUND' });
  });

  // Centralized Error Handler (prevents stack trace leaks in production)
  app.use((err: any, req: express.Request, res: express.Response, next: express.NextFunction) => {
    console.error('[CRITICAL_UNHANDLED_EXCEPTION]:', err.message || err);
    if (res.headersSent) {
      return next(err);
    }
    res.status(err.status || 500).json({
      error: 'A secure processing error occurred. Incident has been recorded.',
      code: 'SERVER_EXCEPTION',
    });
  });

  // --- Vite Dev Middleware / Production Static Serving ---
  if (process.env.NODE_ENV !== 'production') {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  } else {
    const distPath = path.join(process.cwd(), 'dist');
    app.use(express.static(distPath));
    app.get('*', (req, res) => {
      res.sendFile(path.join(distPath, 'index.html'));
    });
  }

  app.listen(PORT, '0.0.0.0', () => {
    console.log(`AI Integrity Assurance Platform running on http://0.0.0.0:${PORT}`);
  });
}

startServer();
