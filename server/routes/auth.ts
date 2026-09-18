/**
 * Authentication routes.
 *
 * The endpoint that previously minted an unauthenticated `LEVEL_4_TOP_SECRET` session is
 * gone. Its replacement, `/api/auth/demo`, exists only when demo mode is on, is rate
 * limited like a real login, issues a `READ_ONLY_OBSERVER`, and writes an audit block
 * every time it is used.
 */

import type { Express, Request, Response } from 'express';
import { CONFIG } from '../config.js';
import { appendAuditEvent } from '../db/audit.js';
import { log } from '../logger.js';
import {
  authenticate,
  changePassword,
  getDemoObserver,
  hasCapability,
  ROLE_CAPABILITIES,
} from '../security/accounts.js';
import { requireAuth } from '../security/guards.js';
import { rateLimit } from '../security/middleware.js';
import { checkPasswordPolicy, verifyPassword } from '../security/passwords.js';
import {
  clearSessionCookie,
  createSession,
  revokeAllSessionsForUser,
  revokeSession,
  setSessionCookie,
} from '../security/sessions.js';
import { changePasswordSchema, loginSchema, validate, validated } from '../security/validation.js';
import { db } from '../db/index.js';

/**
 * Deliberately tight. Credential stuffing is a volume attack, and five attempts per
 * minute is far more than a human needs while being useless to a script.
 */
const loginLimiter = rateLimit({ capacity: 5, refillPerSecond: 5 / 60, name: 'login' });

function publicUser(session: { user: Record<string, unknown> }) {
  const user = session.user as Record<string, unknown>;
  return {
    id: user.id,
    name: user.name,
    username: user.username,
    email: user.email,
    role: user.role,
    clearanceLevel: user.clearanceLevel,
    badgeId: user.badgeId,
    lastLogin: user.lastLogin,
    isDemoAccount: user.isDemoAccount,
    mustChangePassword: user.mustChangePassword,
    capabilities: [...(ROLE_CAPABILITIES[user.role as keyof typeof ROLE_CAPABILITIES] ?? [])],
  };
}

export function registerAuthRoutes(app: Express): void {
  app.post('/api/auth/login', loginLimiter, validate(loginSchema), (req: Request, res: Response) => {
    const { identifier, password } = validated<{ identifier: string; password: string }>(req);
    const ip = req.clientIp ?? 'unknown';

    const outcome = authenticate(identifier, password, ip);

    if (!outcome.ok || !outcome.user) {
      if (outcome.reason === 'LOCKED') {
        res.status(429).json({
          error: 'Too many failed attempts. This account is temporarily locked.',
          code: 'ACCOUNT_LOCKED',
          retryAfterSeconds: outcome.retryAfterSeconds,
        });
        return;
      }
      // One message for every failure mode: distinguishing "no such user" from "wrong
      // password" hands an attacker a free account-enumeration oracle.
      res.status(401).json({
        error: 'Authentication failed. Check the analyst identifier and security key.',
        code: 'INVALID_CREDENTIALS',
      });
      return;
    }

    const session = createSession(outcome.user.id, req);
    setSessionCookie(res, session.token);

    res.json({
      success: true,
      user: publicUser({ user: outcome.user as unknown as Record<string, unknown> }),
      csrfToken: session.csrfToken,
      expiresAt: session.expiresAt,
      // Returned for non-browser clients only. Browsers use the httpOnly cookie and
      // should never persist this.
      apiToken: session.token,
    });
  });

  /**
   * Read-only evaluation session. Not an authentication bypass: demo mode is refused in
   * production by `auditConfiguration`, the role carries no write capability, and every
   * use is recorded.
   */
  app.post('/api/auth/demo', loginLimiter, (req: Request, res: Response) => {
    if (!CONFIG.demoMode) {
      res.status(404).json({
        error: 'Demo sessions are not available on this node.',
        code: 'DEMO_DISABLED',
      });
      return;
    }

    const observer = getDemoObserver();
    if (!observer) {
      res.status(503).json({ error: 'Demo observer account is not provisioned.', code: 'DEMO_UNAVAILABLE' });
      return;
    }

    const session = createSession(observer.id, req);
    setSessionCookie(res, session.token);

    appendAuditEvent({
      eventType: 'DEMO_SESSION_STARTED',
      assetName: observer.username,
      severity: 'INFO',
      actor: observer.username,
      description: `Read-only evaluation session started from ${req.clientIp}. No write capability is granted.`,
      metadata: { ip: req.clientIp, role: observer.role },
    });

    res.json({
      success: true,
      user: publicUser({ user: observer as unknown as Record<string, unknown> }),
      csrfToken: session.csrfToken,
      expiresAt: session.expiresAt,
      apiToken: session.token,
      notice:
        'Read-only evaluation session. Analysis, sealing and configuration are unavailable; ' +
        'sign in with an operational account to perform those actions.',
    });
  });

  app.get('/api/auth/me', (req: Request, res: Response) => {
    if (!req.session) {
      res.status(401).json({ authenticated: false, code: 'UNAUTHENTICATED' });
      return;
    }
    res.json({
      authenticated: true,
      user: publicUser(req.session as unknown as { user: Record<string, unknown> }),
      csrfToken: req.session.csrfToken,
      expiresAt: req.session.expiresAt,
      demoMode: CONFIG.demoMode,
    });
  });

  app.post('/api/auth/logout', (req: Request, res: Response) => {
    if (req.session) {
      revokeSession(req.session.sessionId, 'logout');
      appendAuditEvent({
        eventType: 'SESSION_ENDED',
        assetName: req.session.user.username,
        severity: 'INFO',
        actor: req.session.user.username,
        description: 'Analyst signed out.',
        metadata: { ip: req.clientIp },
      });
    }
    clearSessionCookie(res);
    res.json({ success: true });
  });

  app.post(
    '/api/auth/change-password',
    requireAuth,
    rateLimit({ capacity: 5, refillPerSecond: 5 / 300, name: 'change-password' }),
    validate(changePasswordSchema),
    (req: Request, res: Response) => {
      const session = req.session!;
      const { currentPassword, newPassword } = validated<{ currentPassword: string; newPassword: string }>(req);

      const row = db.prepare(`SELECT * FROM users WHERE id = ?`).get(session.user.id) as
        | Record<string, unknown>
        | undefined;
      if (!row) {
        res.status(404).json({ error: 'Account not found.', code: 'NOT_FOUND' });
        return;
      }

      let kdf;
      try {
        kdf = JSON.parse(String(row.kdf_params ?? '{}'));
      } catch {
        kdf = undefined;
      }

      if (!verifyPassword(currentPassword, String(row.password_hash), String(row.password_salt), kdf)) {
        log.warn('password change rejected: current password incorrect', { userId: session.user.id });
        res.status(401).json({ error: 'Current password is incorrect.', code: 'INVALID_CREDENTIALS' });
        return;
      }

      const policy = checkPasswordPolicy(newPassword, [
        session.user.username,
        session.user.name,
        session.user.email,
      ]);
      if (!policy.ok) {
        res.status(400).json({
          error: 'New password does not meet policy.',
          code: 'WEAK_PASSWORD',
          problems: policy.problems,
        });
        return;
      }

      if (newPassword === currentPassword) {
        res.status(400).json({ error: 'New password must differ from the current one.', code: 'WEAK_PASSWORD' });
        return;
      }

      changePassword(session.user.id, newPassword);

      // Every other session for this account is invalidated: if the password was changed
      // because it may have leaked, leaving old sessions live defeats the purpose.
      const revoked = revokeAllSessionsForUser(session.user.id, 'password-changed');
      clearSessionCookie(res);

      appendAuditEvent({
        eventType: 'PASSWORD_CHANGED',
        assetName: session.user.username,
        severity: 'INFO',
        actor: session.user.username,
        description: `Password changed; ${revoked} session(s) invalidated.`,
        metadata: { ip: req.clientIp, revokedSessions: revoked },
      });

      res.json({
        success: true,
        message: 'Password updated. All sessions have been signed out; please sign in again.',
      });
    }
  );

  app.get('/api/auth/capabilities', requireAuth, (req: Request, res: Response) => {
    const session = req.session!;
    res.json({
      role: session.user.role,
      clearanceLevel: session.user.clearanceLevel,
      capabilities: [...(ROLE_CAPABILITIES[session.user.role] ?? [])],
      checks: Object.fromEntries(
        ['analysis:run', 'inference:seal', 'governance:decide', 'system:configure', 'demo:manage'].map((cap) => [
          cap,
          hasCapability(session.user, cap),
        ])
      ),
    });
  });
}
