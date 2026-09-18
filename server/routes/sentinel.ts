/**
 * Sentinel routes -- read-only views over the continuous monitor, plus a manual sweep.
 *
 * Everything requires an authenticated session: the monitor's findings are security
 * telemetry and are not exposed anonymously. No route here changes system behaviour;
 * the manual sweep only runs the same observation pass the scheduler already runs.
 */

import type { Express, Request, Response } from 'express';
import { requireAuth } from '../security/guards.js';
import { recentThreats, runSentinelSweep, sentinelStatus } from '../sentinel/index.js';

export function registerSentinelRoutes(app: Express): void {
  app.get('/api/sentinel/status', requireAuth, (_req: Request, res: Response) => {
    res.json(sentinelStatus());
  });

  app.get('/api/sentinel/threats', requireAuth, (req: Request, res: Response) => {
    const raw = Number((req.query.limit as string) ?? '50');
    const limit = Number.isFinite(raw) ? Math.min(Math.max(Math.trunc(raw), 1), 200) : 50;
    res.json(recentThreats(limit));
  });

  app.post('/api/sentinel/sweep', requireAuth, (_req: Request, res: Response) => {
    const observations = runSentinelSweep();
    res.json({ ranAt: new Date().toISOString(), observations });
  });
}
