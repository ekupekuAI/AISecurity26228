/**
 * Server-side sessions, httpOnly cookies and CSRF defence.
 *
 * The previous design put a self-contained HMAC token in `localStorage`. Two problems
 * made that unsuitable here:
 *
 *  - **Any XSS reads it.** `localStorage` is script-accessible by definition, so one
 *    injected script exfiltrates a valid Level-4 session. An httpOnly cookie is not
 *    readable from JavaScript at all.
 *  - **It cannot be revoked.** A self-contained token is valid until it expires; there is
 *    no way to end a compromised session. Sessions here are rows, so revocation is a
 *    write.
 *
 * Cookies bring CSRF exposure, so this uses the double-submit pattern: a random CSRF
 * token is stored in the session row and returned to the client, which must echo it in a
 * header on every state-changing request. An attacker's cross-origin form can make the
 * browser send the cookie but cannot read the token to echo it. `SameSite=Strict` is a
 * second, independent barrier.
 *
 * Only a SHA-256 of the session token is stored, so a database read does not yield
 * usable credentials.
 */

import crypto from 'node:crypto';
import type { Request, Response } from 'express';
import { CONFIG } from '../config.js';
import { db } from '../db/index.js';
import { log } from '../logger.js';

export const SESSION_COOKIE = '__Host-aia_session';
export const CSRF_HEADER = 'x-aia-csrf';

export type UserRole =
  | 'LEAD_ASSURANCE_ENGINEER'
  | 'CYBER_SECURITY_AUDITOR'
  | 'AI_MODEL_VALIDATOR'
  | 'DEFENSE_INSPECTOR'
  | 'READ_ONLY_OBSERVER';

export type ClearanceLevel = 'LEVEL_4_TOP_SECRET' | 'LEVEL_3_CONFIDENTIAL' | 'LEVEL_2_OPERATIONAL';

export interface SessionUser {
  id: string;
  name: string;
  email: string;
  username: string;
  role: UserRole;
  clearanceLevel: ClearanceLevel;
  badgeId: string;
  lastLogin: string | null;
  isDemoAccount: boolean;
  mustChangePassword: boolean;
}

export interface ActiveSession {
  sessionId: string;
  user: SessionUser;
  csrfToken: string;
  expiresAt: string;
}

function hashToken(token: string): string {
  return crypto.createHash('sha256').update(token).digest('hex');
}

function rowToUser(row: Record<string, unknown>): SessionUser {
  return {
    id: String(row.id),
    name: String(row.name),
    email: String(row.email),
    username: String(row.username),
    role: String(row.role) as UserRole,
    clearanceLevel: String(row.clearance_level) as ClearanceLevel,
    badgeId: String(row.badge_id),
    lastLogin: (row.last_login_at as string | null) ?? null,
    isDemoAccount: Boolean(row.is_demo_account),
    mustChangePassword: Boolean(row.must_change_password),
  };
}

export function createSession(
  userId: string,
  request: Request
): { token: string; csrfToken: string; sessionId: string; expiresAt: string } {
  // 32 bytes from the OS CSPRNG: not guessable, and never derived from user data.
  const token = crypto.randomBytes(32).toString('base64url');
  const csrfToken = crypto.randomBytes(32).toString('base64url');
  const sessionId = crypto.randomBytes(16).toString('hex');
  const now = new Date();
  const expiresAt = new Date(now.getTime() + CONFIG.sessionTtlSeconds * 1000).toISOString();

  db.prepare(
    `INSERT INTO sessions (id, user_id, token_hash, csrf_token, ip_address, user_agent,
                           created_at, last_seen_at, expires_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`
  ).run(
    sessionId,
    userId,
    hashToken(token),
    csrfToken,
    clientAddress(request),
    String(request.headers['user-agent'] ?? '').slice(0, 256),
    now.toISOString(),
    now.toISOString(),
    expiresAt
  );

  return { token, csrfToken, sessionId, expiresAt };
}

export function setSessionCookie(res: Response, token: string): void {
  /*
   * `__Host-` prefix: the browser refuses the cookie unless it is Secure, path=/ and has
   * no Domain attribute. That blocks a subdomain from overwriting it.
   *
   * `Secure` is required by the prefix, so over plain HTTP (a localhost demo) the prefix
   * must be dropped or the cookie is silently rejected and nobody can log in.
   */
  const secure = CONFIG.isProduction || Boolean(CONFIG.appUrl?.startsWith('https://'));
  const name = secure ? SESSION_COOKIE : 'aia_session';

  res.cookie?.(name, token, {
    httpOnly: true,
    secure,
    sameSite: 'strict',
    path: '/',
    maxAge: CONFIG.sessionTtlSeconds * 1000,
  });

  if (!res.cookie) {
    // express.Response always has .cookie; this is belt-and-braces for a trimmed mock.
    const attributes = [
      `${name}=${token}`,
      'HttpOnly',
      'SameSite=Strict',
      'Path=/',
      `Max-Age=${CONFIG.sessionTtlSeconds}`,
      secure ? 'Secure' : '',
    ].filter(Boolean);
    res.setHeader('Set-Cookie', attributes.join('; '));
  }
}

export function clearSessionCookie(res: Response): void {
  for (const name of [SESSION_COOKIE, 'aia_session']) {
    res.cookie?.(name, '', { httpOnly: true, sameSite: 'strict', path: '/', maxAge: 0 });
  }
}

export function readSessionToken(req: Request): string | null {
  const header = req.headers.cookie;
  if (header) {
    for (const part of header.split(';')) {
      const index = part.indexOf('=');
      if (index < 0) continue;
      const key = part.slice(0, index).trim();
      if (key === SESSION_COOKIE || key === 'aia_session') {
        return decodeURIComponent(part.slice(index + 1).trim());
      }
    }
  }

  // A bearer token is accepted for non-browser API clients (scripted pipelines feeding
  // inference records). Browsers use the cookie, and only the cookie path needs CSRF
  // protection because only the cookie is attached automatically.
  const authorization = req.headers.authorization;
  if (authorization?.startsWith('Bearer ')) {
    const token = authorization.slice(7).trim();
    if (token) return token;
  }

  return null;
}

export function resolveSession(token: string): ActiveSession | null {
  const row = db
    .prepare(
      `SELECT s.id AS session_id, s.csrf_token, s.expires_at, s.last_seen_at, s.revoked_at, u.*
       FROM sessions s JOIN users u ON u.id = s.user_id
       WHERE s.token_hash = ?`
    )
    .get(hashToken(token)) as Record<string, unknown> | undefined;

  if (!row) return null;
  if (row.revoked_at) return null;
  if (Boolean(row.disabled)) return null;

  const now = Date.now();
  if (new Date(String(row.expires_at)).getTime() <= now) {
    revokeSession(String(row.session_id), 'expired');
    return null;
  }

  // Idle timeout, separate from absolute expiry: an unattended console in an operations
  // room should not stay authenticated for the full session lifetime.
  const lastSeen = new Date(String(row.last_seen_at)).getTime();
  if (now - lastSeen > CONFIG.sessionIdleSeconds * 1000) {
    revokeSession(String(row.session_id), 'idle-timeout');
    return null;
  }

  db.prepare(`UPDATE sessions SET last_seen_at = ? WHERE id = ?`).run(
    new Date(now).toISOString(),
    String(row.session_id)
  );

  return {
    sessionId: String(row.session_id),
    user: rowToUser(row),
    csrfToken: String(row.csrf_token),
    expiresAt: String(row.expires_at),
  };
}

export function revokeSession(sessionId: string, reason = 'logout'): void {
  db.prepare(`UPDATE sessions SET revoked_at = ? WHERE id = ? AND revoked_at IS NULL`).run(
    new Date().toISOString(),
    sessionId
  );
  log.info('session revoked', { sessionId, reason });
}

export function revokeAllSessionsForUser(userId: string, reason: string): number {
  const result = db
    .prepare(`UPDATE sessions SET revoked_at = ? WHERE user_id = ? AND revoked_at IS NULL`)
    .run(new Date().toISOString(), userId);
  const count = Number(result.changes);
  if (count > 0) log.info('all sessions revoked for user', { userId, reason, count });
  return count;
}

/** Remove sessions that expired long enough ago to be of no forensic interest. */
export function pruneSessions(): number {
  const cutoff = new Date(Date.now() - 7 * 24 * 60 * 60 * 1000).toISOString();
  const result = db.prepare(`DELETE FROM sessions WHERE expires_at < ?`).run(cutoff);
  return Number(result.changes);
}

/**
 * The client address to attribute a request to.
 *
 * `X-Forwarded-For` is only consulted when the operator has declared how many proxies sit
 * in front. Trusting it unconditionally -- as the previous rate limiter did -- means any
 * caller can rotate their apparent address by editing a header, which defeats per-IP
 * limiting entirely.
 */
export function clientAddress(req: Request): string {
  if (CONFIG.trustProxyHops > 0) {
    const forwarded = req.headers['x-forwarded-for'];
    const chain = (Array.isArray(forwarded) ? forwarded.join(',') : forwarded ?? '')
      .split(',')
      .map((part) => part.trim())
      .filter(Boolean);
    if (chain.length > 0) {
      // Count back from the right: entries to the left can be forged by the client.
      const index = Math.max(0, chain.length - CONFIG.trustProxyHops);
      return chain[index] ?? chain[chain.length - 1];
    }
  }
  return req.socket.remoteAddress ?? 'unknown';
}

/** Constant-time CSRF comparison; a length check first because timingSafeEqual throws. */
export function csrfTokenMatches(expected: string, presented: string | undefined): boolean {
  if (!presented || presented.length !== expected.length) return false;
  try {
    return crypto.timingSafeEqual(Buffer.from(presented), Buffer.from(expected));
  } catch {
    return false;
  }
}
