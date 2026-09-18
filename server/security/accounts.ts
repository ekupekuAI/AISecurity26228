/**
 * Account management, authentication and lockout.
 *
 * The single most serious defect in the previous build lived here in spirit: an
 * unauthenticated `POST /api/auth/quick-role` minted a `LEVEL_4_TOP_SECRET` session for
 * whatever role the caller named, and `requireAdmin` accepted it. That is a complete
 * authentication bypass, and the frontend called it automatically on boot, so the console
 * had no login at all.
 *
 * The replacement keeps a convenient demo path but makes it safe by construction:
 *  - It exists only when `AIA_DEMO_MODE` is on, which is refused in production.
 *  - It issues a `READ_ONLY_OBSERVER` at `LEVEL_2_OPERATIONAL` -- never an administrator.
 *  - The account is flagged in the database and the audit ledger records every use.
 *
 * Credentials are never hardcoded in a production path. A bootstrap administrator is
 * created from the environment, or generated once and printed to the operator's console
 * so it can be recorded and rotated.
 */

import crypto from 'node:crypto';
import { CONFIG } from '../config.js';
import { db, transaction } from '../db/index.js';
import { appendAuditEvent } from '../db/audit.js';
import { log } from '../logger.js';
import { CURRENT_KDF, generatePassword, hashPassword, needsRehash, verifyPassword } from './passwords.js';
import type { ClearanceLevel, SessionUser, UserRole } from './sessions.js';

/** Escalating delay after repeated failures, capped so an account is never bricked. */
const LOCKOUT_THRESHOLD = 5;
const LOCKOUT_WINDOW_MS = 15 * 60 * 1000;
const MAX_LOCKOUT_MS = 30 * 60 * 1000;

export const ROLE_CLEARANCE: Record<UserRole, ClearanceLevel> = {
  LEAD_ASSURANCE_ENGINEER: 'LEVEL_4_TOP_SECRET',
  DEFENSE_INSPECTOR: 'LEVEL_4_TOP_SECRET',
  CYBER_SECURITY_AUDITOR: 'LEVEL_3_CONFIDENTIAL',
  AI_MODEL_VALIDATOR: 'LEVEL_3_CONFIDENTIAL',
  READ_ONLY_OBSERVER: 'LEVEL_2_OPERATIONAL',
};

/**
 * Capabilities per role. Expressed as an explicit grant list rather than a clearance
 * comparison so that "can this role do this" is answerable by reading one table, and so
 * a new privileged action cannot be silently inherited by every senior role.
 */
export const ROLE_CAPABILITIES: Record<UserRole, ReadonlySet<string>> = {
  LEAD_ASSURANCE_ENGINEER: new Set([
    'analysis:run', 'analysis:read', 'inference:seal', 'inference:verify',
    'governance:decide', 'report:generate', 'finding:acknowledge',
    'system:configure', 'demo:manage', 'audit:verify',
  ]),
  DEFENSE_INSPECTOR: new Set([
    'analysis:run', 'analysis:read', 'inference:verify', 'governance:decide',
    'report:generate', 'finding:acknowledge', 'system:configure', 'demo:manage', 'audit:verify',
  ]),
  CYBER_SECURITY_AUDITOR: new Set([
    'analysis:run', 'analysis:read', 'inference:seal', 'inference:verify',
    'report:generate', 'finding:acknowledge', 'audit:verify',
  ]),
  AI_MODEL_VALIDATOR: new Set([
    'analysis:run', 'analysis:read', 'inference:verify', 'report:generate',
    'finding:acknowledge', 'audit:verify',
  ]),
  READ_ONLY_OBSERVER: new Set(['analysis:read', 'audit:verify', 'report:generate']),
};

export function hasCapability(user: SessionUser, capability: string): boolean {
  return ROLE_CAPABILITIES[user.role]?.has(capability) ?? false;
}

export interface AuthOutcome {
  ok: boolean;
  user?: SessionUser;
  reason?: 'INVALID_CREDENTIALS' | 'LOCKED' | 'DISABLED';
  retryAfterSeconds?: number;
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

export function createUser(params: {
  username: string;
  email: string;
  name: string;
  role: UserRole;
  password: string;
  badgeId?: string;
  isDemoAccount?: boolean;
  mustChangePassword?: boolean;
}): SessionUser {
  const { hash, salt, params: kdf } = hashPassword(params.password);
  const id = `usr_${crypto.randomBytes(9).toString('hex')}`;
  const badgeId = params.badgeId ?? `AIA-${crypto.randomInt(1000, 9999)}-${params.role.slice(0, 2)}`;

  db.prepare(
    `INSERT INTO users (id, username, email, name, role, clearance_level, badge_id,
                        password_hash, password_salt, kdf_params, is_demo_account,
                        must_change_password, created_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
  ).run(
    id,
    params.username.trim().toLowerCase(),
    params.email.trim().toLowerCase(),
    params.name,
    params.role,
    ROLE_CLEARANCE[params.role],
    badgeId,
    hash,
    salt,
    JSON.stringify(kdf),
    params.isDemoAccount ? 1 : 0,
    params.mustChangePassword ? 1 : 0,
    new Date().toISOString()
  );

  return {
    id,
    username: params.username.trim().toLowerCase(),
    email: params.email.trim().toLowerCase(),
    name: params.name,
    role: params.role,
    clearanceLevel: ROLE_CLEARANCE[params.role],
    badgeId,
    lastLogin: null,
    isDemoAccount: Boolean(params.isDemoAccount),
    mustChangePassword: Boolean(params.mustChangePassword),
  };
}

function lockoutState(identifier: string): { locked: boolean; retryAfterSeconds: number } {
  const since = new Date(Date.now() - LOCKOUT_WINDOW_MS).toISOString();
  const row = db
    .prepare(
      `SELECT COUNT(*) AS failures, MAX(attempted_at) AS last_attempt
       FROM login_attempts
       WHERE identifier = ? AND successful = 0 AND attempted_at > ?`
    )
    .get(identifier, since) as { failures: number; last_attempt: string | null };

  const failures = Number(row.failures ?? 0);
  if (failures < LOCKOUT_THRESHOLD) return { locked: false, retryAfterSeconds: 0 };

  // Exponential backoff past the threshold, capped.
  const penaltyMs = Math.min(MAX_LOCKOUT_MS, 2 ** (failures - LOCKOUT_THRESHOLD) * 30_000);
  const lastAttempt = row.last_attempt ? new Date(row.last_attempt).getTime() : 0;
  const unlockAt = lastAttempt + penaltyMs;
  const remaining = unlockAt - Date.now();

  return remaining > 0
    ? { locked: true, retryAfterSeconds: Math.ceil(remaining / 1000) }
    : { locked: false, retryAfterSeconds: 0 };
}

function recordAttempt(identifier: string, ip: string, successful: boolean): void {
  db.prepare(`INSERT INTO login_attempts (identifier, ip_address, successful, attempted_at) VALUES (?, ?, ?, ?)`)
    .run(identifier, ip, successful ? 1 : 0, new Date().toISOString());

  // Keep the table bounded; a year of failed logins is not useful and the audit ledger
  // already holds the security-relevant record.
  db.prepare(
    `DELETE FROM login_attempts WHERE attempted_at < ?`
  ).run(new Date(Date.now() - 30 * 24 * 60 * 60 * 1000).toISOString());
}

export function authenticate(identifier: string, password: string, ip: string): AuthOutcome {
  const key = identifier.trim().toLowerCase();

  const lock = lockoutState(key);
  if (lock.locked) {
    appendAuditEvent({
      eventType: 'AUTH_LOCKED_OUT',
      assetName: key,
      severity: 'HIGH',
      actor: key,
      description: `Authentication refused: account temporarily locked after repeated failures from ${ip}.`,
      metadata: { retryAfterSeconds: lock.retryAfterSeconds, ip },
    });
    return { ok: false, reason: 'LOCKED', retryAfterSeconds: lock.retryAfterSeconds };
  }

  const row = db.prepare(`SELECT * FROM users WHERE username = ? OR email = ?`).get(key, key) as
    | Record<string, unknown>
    | undefined;

  if (!row) {
    // Spend comparable time on a missing account so response timing does not reveal
    // which usernames exist.
    verifyPassword(password, '0'.repeat(128), 'decoy-salt', CURRENT_KDF);
    recordAttempt(key, ip, false);
    return { ok: false, reason: 'INVALID_CREDENTIALS' };
  }

  if (Boolean(row.disabled)) {
    recordAttempt(key, ip, false);
    return { ok: false, reason: 'DISABLED' };
  }

  let kdf = CURRENT_KDF;
  try {
    const parsed = JSON.parse(String(row.kdf_params ?? '{}'));
    if (parsed?.N) kdf = parsed;
  } catch {
    // Absent or corrupt parameters: fall back to the current defaults.
  }

  if (!verifyPassword(password, String(row.password_hash), String(row.password_salt), kdf)) {
    recordAttempt(key, ip, false);
    const after = lockoutState(key);
    appendAuditEvent({
      eventType: 'AUTH_FAILED',
      assetName: key,
      severity: after.locked ? 'HIGH' : 'MEDIUM',
      actor: key,
      description: `Failed authentication attempt from ${ip}.`,
      metadata: { ip, nowLocked: after.locked },
    });
    return { ok: false, reason: 'INVALID_CREDENTIALS' };
  }

  recordAttempt(key, ip, true);

  // Upgrade an old hash now that we hold the plaintext and know it is correct.
  if (needsRehash(kdf)) {
    const upgraded = hashPassword(password);
    db.prepare(`UPDATE users SET password_hash = ?, password_salt = ?, kdf_params = ? WHERE id = ?`).run(
      upgraded.hash,
      upgraded.salt,
      JSON.stringify(upgraded.params),
      String(row.id)
    );
    log.info('password hash upgraded to current KDF parameters', { userId: String(row.id) });
  }

  db.prepare(`UPDATE users SET last_login_at = ?, failed_attempts = 0 WHERE id = ?`).run(
    new Date().toISOString(),
    String(row.id)
  );

  const user = rowToUser(row);
  appendAuditEvent({
    eventType: 'AUTH_SUCCESS',
    assetName: user.username,
    severity: 'INFO',
    actor: user.username,
    description: `${user.name} (${user.role}, ${user.clearanceLevel}) authenticated from ${ip}.`,
    metadata: { ip, role: user.role, badgeId: user.badgeId },
  });

  return { ok: true, user };
}

export function changePassword(userId: string, newPassword: string): void {
  const { hash, salt, params } = hashPassword(newPassword);
  db.prepare(
    `UPDATE users SET password_hash = ?, password_salt = ?, kdf_params = ?, must_change_password = 0 WHERE id = ?`
  ).run(hash, salt, JSON.stringify(params), userId);
}

export function getDemoObserver(): SessionUser | null {
  if (!CONFIG.demoMode) return null;
  const row = db.prepare(`SELECT * FROM users WHERE is_demo_account = 1 AND role = 'READ_ONLY_OBSERVER' LIMIT 1`).get() as
    | Record<string, unknown>
    | undefined;
  return row ? rowToUser(row) : null;
}

export function listUsers(): Array<Omit<SessionUser, 'mustChangePassword'> & { disabled: boolean }> {
  const rows = db.prepare(`SELECT * FROM users ORDER BY created_at ASC`).all() as Array<Record<string, unknown>>;
  return rows.map((row) => ({ ...rowToUser(row), disabled: Boolean(row.disabled) }));
}

/**
 * Create the accounts the node needs on first boot.
 *
 * Exactly one privileged account, and its password is never a literal in this file. If
 * the operator supplied one it is used; otherwise one is generated and printed once, so
 * there is no shared default credential to look up.
 */
export function bootstrapAccounts(): void {
  transaction(() => {
    const count = (db.prepare(`SELECT COUNT(*) AS c FROM users`).get() as { c: number }).c;

    if (Number(count) === 0) {
      const username = CONFIG.bootstrapAdminUser || 'assurance.lead';
      const supplied = CONFIG.bootstrapAdminPassword;
      const password = supplied || generatePassword(28);

      createUser({
        username,
        email: `${username}@assurance.local`,
        name: 'Lead Assurance Engineer',
        role: 'LEAD_ASSURANCE_ENGINEER',
        password,
        badgeId: 'AIA-0001-TS',
        mustChangePassword: !supplied,
      });

      if (!supplied) {
        // Printed once, outside the JSON log, so it is visible to the operator standing
        // at the console and is not captured by a log shipper.
        process.stdout.write(
          '\n' +
            '='.repeat(78) + '\n' +
            '  INITIAL ADMINISTRATOR CREDENTIAL - shown once, not stored in plaintext\n' +
            '='.repeat(78) + '\n' +
            `  username : ${username}\n` +
            `  password : ${password}\n` +
            '  This account must change its password at first login.\n' +
            '  Set AIA_BOOTSTRAP_USER / AIA_BOOTSTRAP_PASSWORD to control this.\n' +
            '='.repeat(78) + '\n\n'
        );
      }

      appendAuditEvent({
        eventType: 'ACCOUNT_BOOTSTRAPPED',
        assetName: username,
        severity: 'INFO',
        actor: 'system',
        description: `Initial administrator account '${username}' created on first boot.`,
        metadata: { role: 'LEAD_ASSURANCE_ENGINEER', passwordSource: supplied ? 'environment' : 'generated' },
      });
    }

    // The demo observer exists only in demo mode, and only ever read-only.
    if (CONFIG.demoMode) {
      const existing = db.prepare(`SELECT id FROM users WHERE username = 'demo.observer'`).get();
      if (!existing) {
        createUser({
          username: 'demo.observer',
          email: 'demo.observer@assurance.local',
          name: 'Evaluation Observer',
          role: 'READ_ONLY_OBSERVER',
          password: generatePassword(32),
          badgeId: 'AIA-DEMO-RO',
          isDemoAccount: true,
        });
        log.info('demo observer account created (read-only, demo mode only)');
      }
    }
  });
}
