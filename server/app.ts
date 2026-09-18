/**
 * Express application assembly.
 *
 * Middleware order is load-bearing and is listed in the order it must run:
 *
 *  1. request context      -- so every later log line correlates
 *  2. security headers     -- set before any handler can respond
 *  3. CORS                 -- reject foreign origins before doing any work
 *  4. body parsing         -- bounded
 *  5. session attachment   -- populates req.session for the guards
 *  6. CSRF                 -- needs the session to compare against
 *  7. global rate limit    -- after identification so it can key on the caller
 *  8. routes
 *  9. 404 for unmatched /api
 * 10. error handler        -- last, so it catches everything above
 */

import express from 'express';
import type { NextFunction, Request, Response } from 'express';
import { CONFIG } from './config.js';
import { captureException, log, newRequestId, runWithContext } from './logger.js';
import { registerAnalysisRoutes } from './routes/analysis.js';
import { registerAuthRoutes } from './routes/auth.js';
import { registerGovernanceRoutes } from './routes/governance.js';
import { registerInferenceRoutes } from './routes/inference.js';
import { registerSystemRoutes } from './routes/system.js';
import { registerSentinelRoutes } from './routes/sentinel.js';
import { registerAibomRoutes } from './routes/aibom.js';
import { attachSession } from './security/guards.js';
import { cors, csrfProtection, rateLimit, securityHeaders } from './security/middleware.js';

export function createApp(): express.Express {
  const app = express();

  // Never advertise the framework; it narrows an attacker's search for known issues.
  app.disable('x-powered-by');
  // Express's own proxy trust is disabled: client address resolution is handled in
  // sessions.ts, which only consults X-Forwarded-For when the operator declared a hop
  // count. Leaving this enabled would let any caller spoof req.ip.
  app.set('trust proxy', false);
  app.set('etag', false);

  app.use((req: Request, res: Response, next: NextFunction) => {
    const requestId = (req.headers['x-request-id'] as string | undefined)?.slice(0, 64) || newRequestId();
    res.setHeader('x-request-id', requestId);
    runWithContext(requestId, () => {
      const started = process.hrtime.bigint();
      res.on('finish', () => {
        const durationMs = Number(process.hrtime.bigint() - started) / 1e6;
        // Only API traffic is logged: static asset requests would drown the ledger of
        // what an analyst actually did.
        if (req.path.startsWith('/api') || req.path.startsWith('/analyze') || req.path.startsWith('/verify')) {
          log.info('request', {
            method: req.method,
            path: req.path,
            status: res.statusCode,
            durationMs: Math.round(durationMs * 100) / 100,
          });
        }
      });
      next();
    });
  });

  app.use(securityHeaders);
  app.use(cors);

  app.use(express.json({ limit: CONFIG.maxJsonBytes }));
  app.use(express.urlencoded({ extended: false, limit: CONFIG.maxJsonBytes }));

  app.use(attachSession);
  app.use(csrfProtection);

  /*
   * Global ceiling on the API surface only.
   *
   * Scoping matters. Applied to every request, this limiter also counts static assets --
   * and a single page load in development pulls several hundred modules through the same
   * middleware chain, which drains the bucket before the app has even rendered and
   * returns 429 for the login request itself. Rate-limiting a file server achieves
   * nothing anyway; the expensive and authenticated routes carry their own tighter
   * limits on top of this one.
   */
  const apiLimiter = rateLimit({ capacity: 600, refillPerSecond: 10, name: 'global' });
  app.use((req, res, next) => {
    const guarded =
      req.path.startsWith('/api') || req.path.startsWith('/analyze') || req.path.startsWith('/verify');
    if (guarded) {
      apiLimiter(req, res, next);
      return;
    }
    next();
  });

  registerAuthRoutes(app);
  registerSystemRoutes(app);
  registerAnalysisRoutes(app);
  registerInferenceRoutes(app);
  registerGovernanceRoutes(app);
  registerSentinelRoutes(app);
  registerAibomRoutes(app);

  // Unmatched API paths must 404 as JSON rather than falling through to the SPA, which
  // would return an HTML page to a fetch() and produce a confusing parse error.
  app.all(/^\/api\/.*/, (req: Request, res: Response) => {
    res.status(404).json({ error: 'API resource not found.', code: 'NOT_FOUND', path: req.path });
  });

  return app;
}

/**
 * Terminal error handler. Registered after the static/SPA handlers by the caller so it
 * genuinely sits last.
 *
 * No exception message ever reaches the client: the previous build returned
 * `err.message` from several handlers, which leaks file paths, SQL fragments and library
 * internals. The message is logged with an incident id and only the id is returned.
 */
export function installErrorHandler(app: express.Express): void {
  app.use((error: unknown, req: Request, res: Response, next: NextFunction) => {
    if (res.headersSent) {
      next(error);
      return;
    }

    // A malformed JSON body is the client's error, and saying so is not a leak.
    if (error instanceof SyntaxError && 'body' in (error as never)) {
      res.status(400).json({ error: 'Request body is not valid JSON.', code: 'MALFORMED_JSON' });
      return;
    }

    const incidentId = captureException(error, `${req.method} ${req.path}`);
    res.status(500).json({
      error: 'The server encountered an error handling this request. The incident has been logged.',
      code: 'INTERNAL_ERROR',
      incidentId,
    });
  });
}
