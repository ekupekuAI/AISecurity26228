/**
 * Authentication and authorisation guards.
 *
 * `requireCapability` replaces the previous `requireAdmin`, which decided privilege from
 * a clearance string. That conflated two different things: clearance is *how sensitive
 * the data you may see is*, capability is *what you may do*. A Level-4 inspector should
 * be able to read everything and still not be the account that repoints the analysis
 * engine. Capabilities are an explicit grant list per role, so adding a privileged action
 * never silently extends to every senior role.
 */

import type { NextFunction, Request, Response } from 'express';
import { hasCapability } from './accounts.js';
import { clientAddress, resolveSession, readSessionToken } from './sessions.js';
import type { ActiveSession } from './sessions.js';
import { log, setActor } from '../logger.js';
import { appendAuditEvent } from '../db/audit.js';

declare global {
  // eslint-disable-next-line @typescript-eslint/no-namespace
  namespace Express {
    interface Request {
      session?: ActiveSession;
    }
  }
}

/**
 * Attach a session when one is present and valid. Never rejects -- routes decide whether
 * they need authentication, so that a public endpoint still knows who is calling.
 */
export function attachSession(req: Request, _res: Response, next: NextFunction): void {
  req.clientIp = clientAddress(req);

  const token = readSessionToken(req);
  if (!token) {
    next();
    return;
  }

  const session = resolveSession(token);
  if (session) {
    req.session = session;
    setActor(session.user.username);
  }
  next();
}

export function requireAuth(req: Request, res: Response, next: NextFunction): void {
  if (!req.session) {
    res.status(401).json({
      error: 'Authentication required.',
      code: 'UNAUTHENTICATED',
    });
    return;
  }

  // A forced password change must be completed before anything else is reachable,
  // otherwise a bootstrap credential stays usable indefinitely.
  if (req.session.user.mustChangePassword && !req.path.startsWith('/api/auth/')) {
    res.status(403).json({
      error: 'Password change required before this account may be used.',
      code: 'PASSWORD_CHANGE_REQUIRED',
    });
    return;
  }

  next();
}

export function requireCapability(capability: string) {
  return (req: Request, res: Response, next: NextFunction): void => {
    const session = req.session;
    if (!session) {
      res.status(401).json({ error: 'Authentication required.', code: 'UNAUTHENTICATED' });
      return;
    }

    if (!hasCapability(session.user, capability)) {
      // A denied privileged action is security-relevant on its own: it is what an
      // account compromise or a mistaken grant looks like from the outside.
      log.warn('capability denied', {
        capability,
        role: session.user.role,
        path: req.path,
      });
      appendAuditEvent({
        eventType: 'AUTHORIZATION_DENIED',
        assetName: req.path,
        severity: 'MEDIUM',
        actor: session.user.username,
        description:
          `${session.user.name} (${session.user.role}) was denied '${capability}' on ${req.method} ${req.path}.`,
        metadata: { capability, role: session.user.role, ip: req.clientIp },
      });
      res.status(403).json({
        error: `Your role (${session.user.role}) does not hold the '${capability}' capability.`,
        code: 'FORBIDDEN',
        requiredCapability: capability,
      });
      return;
    }

    next();
  };
}

/** Convenience for handlers that have already passed `requireAuth`. */
export function actorOf(req: Request): string {
  return req.session?.user.username ?? 'anonymous';
}

/**
 * The owning user's stable id, used to scope every per-user read and write. Returns
 * undefined only when unauthenticated, which the read repositories treat as "no scope";
 * routes that serve per-user data always run behind `requireAuth`, so a real request
 * always carries an id here.
 */
export function ownerOf(req: Request): string | undefined {
  return req.session?.user.id;
}
