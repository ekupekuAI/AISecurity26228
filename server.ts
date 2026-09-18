/**
 * AI Integrity Assurance Platform -- gateway entry point.
 *
 * Boot order matters: configuration is audited before anything binds a port, so a
 * production node with demo mode left on refuses to start rather than starting insecure.
 *
 * Responsibilities are split deliberately. This process owns sessions, the durable
 * evidence database, the audit ledger and the browser-facing surface. The Python engine
 * (`ml-engine/`) owns every analytical decision. The gateway can fall back to a reduced
 * set of local analysers when the engine is unreachable, but those results are marked
 * degraded and can never yield an ACCEPT.
 */

import 'dotenv/config';
import path from 'node:path';
import fs from 'node:fs';
import http from 'node:http';
import express from 'express';
import { createApp, installErrorHandler } from './server/app.js';
import { CONFIG, auditConfiguration, ensureRuntimeDirectories } from './server/config.js';
import { closeDatabase } from './server/db/index.js';
import { ensureGenesisBlock, appendAuditEvent, verifyAuditChain } from './server/db/audit.js';
import { log } from './server/logger.js';
import { bootstrapAccounts } from './server/security/accounts.js';
import { getKeyring } from './server/security/keyring.js';
import { pruneSessions } from './server/security/sessions.js';
import { checkEngineHealth } from './server/engineClient.js';

async function main(): Promise<void> {
  ensureRuntimeDirectories();

  const { fatal, warnings } = auditConfiguration();
  for (const warning of warnings) log.warn('configuration warning', { detail: warning });
  if (fatal.length > 0) {
    for (const problem of fatal) log.error('configuration refused', { detail: problem });
    process.stderr.write(
      '\nRefusing to start: the configuration above is not safe for this environment.\n\n'
    );
    process.exit(78); // EX_CONFIG
  }

  const keyring = getKeyring();
  if (!keyring.available) {
    log.warn('signing unavailable; records will be hashed but not signed', { reason: keyring.error });
  }

  bootstrapAccounts();
  ensureGenesisBlock();

  // Verify the ledger at boot. If it is broken, that happened while we were not running,
  // which is exactly the case an append-only ledger exists to surface.
  const chain = verifyAuditChain();
  if (!chain.valid) {
    log.error('AUDIT LEDGER VERIFICATION FAILED AT STARTUP', {
      brokenAt: chain.firstBrokenBlock,
      details: chain.details,
    });
    process.stderr.write(
      '\n' + '!'.repeat(78) + '\n' +
      '  AUDIT LEDGER INTEGRITY FAILURE\n' +
      `  ${chain.details}\n` +
      '  The ledger was modified outside this application. Preserve data/ai_integrity.db\n' +
      '  for forensic analysis before continuing.\n' +
      '!'.repeat(78) + '\n\n'
    );
  } else {
    log.info('audit ledger verified', { blocks: chain.chainLength, signed: chain.signedBlocks });
  }

  const app = createApp();

  /*
   * One HTTP server, created up front.
   *
   * Vite runs as middleware here rather than on its own port, so its hot-reload
   * websocket has no server of its own to attach to. Left to itself the dev client
   * dials ws://host:24678, nothing answers, and every page load logs a failed
   * WebSocket connection. Handing Vite this server makes HMR share the same port and
   * the same origin, which is also what the connect-src policy expects.
   */
  const server = http.createServer(app);

  // --- frontend -------------------------------------------------------------
  if (CONFIG.environment !== 'production') {
    const { createServer: createViteServer } = await import('vite');
    const vite = await createViteServer({
      server: { middlewareMode: true, hmr: { server } },
      appType: 'spa',
    });
    app.use(vite.middlewares);
    log.info('vite dev middleware attached');
  } else {
    const distPath = path.join(process.cwd(), 'dist');
    if (!fs.existsSync(path.join(distPath, 'index.html'))) {
      log.error('production build missing', { distPath });
      process.stderr.write('\nRefusing to start: run `npm run build` before starting in production.\n\n');
      process.exit(78);
    }

    app.use(
      express.static(distPath, {
        index: false,
        dotfiles: 'deny',
        // Hashed asset filenames are immutable; index.html must never be cached or a
        // deployed fix will not reach an open console.
        setHeaders: (res, filePath) => {
          if (/\.[0-9a-f]{8,}\./i.test(path.basename(filePath))) {
            res.setHeader('Cache-Control', 'public, max-age=31536000, immutable');
          } else {
            res.setHeader('Cache-Control', 'no-cache');
          }
        },
      })
    );

    app.get(/^\/(?!api\/).*/, (_req, res) => {
      res.setHeader('Cache-Control', 'no-store');
      res.sendFile(path.join(distPath, 'index.html'));
    });
  }

  installErrorHandler(app);

  server.listen(CONFIG.port, CONFIG.host, () => {
    const engineHint = CONFIG.engineUrl;
    process.stdout.write(
      '\n' +
        '  AI Integrity Assurance Platform\n' +
        `  console   : http://${CONFIG.host}:${CONFIG.port}\n` +
        `  engine    : ${engineHint}\n` +
        `  mode      : ${CONFIG.environment}${CONFIG.demoMode ? ' (demo data endpoints enabled)' : ''}\n` +
        `  signing   : ${keyring.available ? `Ed25519 ${keyring.id}` : 'UNAVAILABLE'}\n` +
        `  ledger    : ${chain.valid ? 'verified' : 'BROKEN - see above'}, ${chain.chainLength} block(s)\n\n`
    );

    checkEngineHealth(true)
      .then((health) => {
        if (health.status !== 'ONLINE') {
          log.warn('assurance engine is not reachable; analyses will run degraded', {
            url: health.url,
            error: health.error,
          });
          process.stdout.write(
            '  NOTE: the Python assurance engine is not reachable. Analyses will run on the\n' +
              '        gateway fallback and will be marked degraded. Start it with:\n' +
              '          python -m uvicorn app:app --app-dir ml-engine --host 127.0.0.1 --port 8000\n\n'
          );
        } else {
          log.info('assurance engine online', { url: health.url });
        }
      })
      .catch(() => undefined);
  });

  // Reject a slow-loris style connection that opens and never sends headers.
  server.headersTimeout = 65_000;
  server.requestTimeout = CONFIG.engineTimeoutMs + 60_000;
  server.keepAliveTimeout = 60_000;

  const pruner = setInterval(() => {
    const removed = pruneSessions();
    if (removed > 0) log.debug('pruned expired sessions', { removed });
  }, 60 * 60 * 1000);
  pruner.unref();

  let shuttingDown = false;
  const shutdown = (signal: string): void => {
    if (shuttingDown) return;
    shuttingDown = true;
    log.info('shutdown initiated', { signal });

    try {
      appendAuditEvent({
        eventType: 'NODE_SHUTDOWN',
        assetName: 'assurance-node',
        severity: 'INFO',
        actor: 'system',
        description: `Assurance node shutting down on ${signal}.`,
        metadata: { signal },
      });
    } catch (error) {
      log.warn('could not record shutdown event', { error: String(error) });
    }

    server.close(() => {
      closeDatabase();
      log.info('shutdown complete');
      process.exit(0);
    });

    // Do not hang forever on a stuck connection; a long analysis is already bounded by
    // requestTimeout.
    setTimeout(() => {
      log.warn('forcing shutdown after grace period');
      closeDatabase();
      process.exit(0);
    }, 15_000).unref();
  };

  process.on('SIGTERM', () => shutdown('SIGTERM'));
  process.on('SIGINT', () => shutdown('SIGINT'));

  process.on('unhandledRejection', (reason) => {
    log.error('unhandled promise rejection', { reason: String(reason) });
  });
  process.on('uncaughtException', (error) => {
    log.error('uncaught exception', { name: error.name, message: error.message, stack: error.stack });
    // An uncaught exception leaves the process in an unknown state; a supervisor should
    // restart it rather than letting it limp on.
    shutdown('uncaughtException');
  });
}

main().catch((error) => {
  log.error('fatal startup error', {
    message: error instanceof Error ? error.message : String(error),
    stack: error instanceof Error ? error.stack : undefined,
  });
  process.exit(1);
});
