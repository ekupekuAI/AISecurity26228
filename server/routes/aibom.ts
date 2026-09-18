/**
 * AI-BOM routes: issue a signed passport for an analysed artifact, list and download
 * passports, and verify any passport -- including one issued by another node.
 */

import type { Express, Request, Response } from 'express';
import { actorOf, requireAuth, requireCapability } from '../security/guards.js';
import { appendAuditEvent } from '../db/audit.js';
import { getAnalysisById, getAibom, listAiboms, saveAibom } from '../db/repositories.js';
import { buildAibom, verifyAibom } from '../provenance/aibom.js';

export function registerAibomRoutes(app: Express): void {
  // Issue a passport from an existing analysis.
  app.post('/api/aibom/generate', requireAuth, requireCapability('report:generate'), (req: Request, res: Response) => {
    const analysisId = String((req.body as { analysisId?: unknown })?.analysisId ?? '').trim();
    if (!analysisId) {
      res.status(400).json({ error: 'analysisId is required.', code: 'BAD_REQUEST' });
      return;
    }
    const analysis = getAnalysisById(analysisId);
    if (!analysis) {
      res.status(404).json({ error: 'No analysis with that id.', code: 'NOT_FOUND' });
      return;
    }

    const actor = actorOf(req);
    const passport = buildAibom(analysis, actor);
    saveAibom({
      bomId: passport.bomId,
      subjectKind: passport.subject.kind,
      subjectName: passport.subject.filename,
      subjectSha256: passport.subject.sha256,
      status: passport.assurance.status,
      decision: passport.assurance.decision,
      riskScore: passport.assurance.riskScore,
      signingKeyId: passport.seal.signingKeyId,
      sha256: passport.seal.sha256,
      passportJson: JSON.stringify(passport),
      createdBy: actor,
    });
    appendAuditEvent({
      eventType: 'AIBOM_ISSUED',
      assetName: passport.subject.filename,
      assetHash: passport.subject.sha256,
      severity: 'INFO',
      actor,
      description: `AI-BOM ${passport.bomId} issued for ${passport.subject.kind} ${passport.subject.filename}.`,
      metadata: { bomId: passport.bomId, decision: passport.assurance.decision, sha256: passport.seal.sha256 },
    });

    res.json(passport);
  });

  app.get('/api/aibom', requireAuth, (req: Request, res: Response) => {
    const raw = Number((req.query.limit as string) ?? '50');
    res.json(listAiboms(Number.isFinite(raw) ? raw : 50));
  });

  app.get('/api/aibom/:id', requireAuth, (req: Request, res: Response) => {
    const passport = getAibom(String(req.params.id));
    if (!passport) {
      res.status(404).json({ error: 'No passport with that id.', code: 'NOT_FOUND' });
      return;
    }
    res.json(passport);
  });

  // Download as a .aibom.json file the operator can hand to a downstream party.
  app.get('/api/aibom/:id/download', requireAuth, (req: Request, res: Response) => {
    const passport = getAibom(String(req.params.id));
    if (!passport) {
      res.status(404).json({ error: 'No passport with that id.', code: 'NOT_FOUND' });
      return;
    }
    const name = `${String((passport as { bomId?: string }).bomId ?? 'passport')}.aibom.json`;
    res.setHeader('Content-Type', 'application/json');
    res.setHeader('Content-Disposition', `attachment; filename="${name}"`);
    res.send(JSON.stringify(passport, null, 2));
  });

  // Verify a pasted passport. Works for passports from any node -- the seal carries the
  // issuer's public key; the fingerprint is returned for out-of-band trust comparison.
  app.post('/api/aibom/verify', requireAuth, (req: Request, res: Response) => {
    const passport = (req.body as { passport?: unknown })?.passport ?? req.body;
    res.json(verifyAibom(passport));
  });
}
