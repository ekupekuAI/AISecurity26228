/**
 * AI Integrity Assurance Platform - Authentication & Authorization Engine
 * Secure password hashing using native scrypt + random salts.
 * Timing-attack resistant verification with timingSafeEqual.
 * Cryptographically signed HMAC-SHA256 session tokens.
 * Role-Based Access Control (RBAC) & Clearance Tiers.
 */

import crypto from 'node:crypto';
import type { Request, Response, NextFunction } from 'express';
import { db } from './db.js';
import { AuthUser, UserRole } from '../src/types.js';

// Extend Express Request interface to carry authenticated user
declare global {
  namespace Express {
    interface Request {
      user?: AuthUser;
    }
  }
}

// Persistent or securely generated session signing secret
const AUTH_SECRET = process.env.AUTH_SECRET || crypto.randomBytes(32).toString('hex');

// Ensure users table exists in SQLite
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    username TEXT NOT NULL UNIQUE,
    email TEXT NOT NULL UNIQUE,
    name TEXT NOT NULL,
    role TEXT NOT NULL,
    clearance_level TEXT NOT NULL,
    badge_id TEXT NOT NULL,
    password_hash TEXT NOT NULL,
    password_salt TEXT NOT NULL,
    created_at TEXT NOT NULL,
    last_login_at TEXT
  );
`);

/**
 * Hash a password using OWASP-compliant memory-hard scrypt algorithm with cryptographically random salt.
 */
export function hashPassword(password: string): { hash: string; salt: string } {
  const salt = crypto.randomBytes(16).toString('hex');
  const derivedKey = crypto.scryptSync(password, salt, 64);
  return {
    hash: derivedKey.toString('hex'),
    salt,
  };
}

/**
 * Verify password using timing-safe comparison to prevent timing side-channel attacks.
 */
export function verifyPassword(password: string, hash: string, salt: string): boolean {
  try {
    const derivedKey = crypto.scryptSync(password, salt, 64);
    const keyBuffer = Buffer.from(derivedKey.toString('hex'), 'hex');
    const hashBuffer = Buffer.from(hash, 'hex');

    if (keyBuffer.length !== hashBuffer.length) {
      return false;
    }

    return crypto.timingSafeEqual(keyBuffer, hashBuffer);
  } catch {
    return false;
  }
}

/**
 * Generate a cryptographically signed HMAC-SHA256 session token (valid for 24 hours).
 */
export function createSessionToken(user: AuthUser): string {
  const payload = {
    sub: user.id,
    name: user.name,
    email: user.email,
    role: user.role,
    clearanceLevel: user.clearanceLevel,
    badgeId: user.badgeId,
    iat: Math.floor(Date.now() / 1000),
    exp: Math.floor(Date.now() / 1000) + 24 * 60 * 60, // 24 hours
  };

  const payloadB64 = Buffer.from(JSON.stringify(payload)).toString('base64url');
  const signature = crypto
    .createHmac('sha256', AUTH_SECRET)
    .update(payloadB64)
    .digest('base64url');

  return `${payloadB64}.${signature}`;
}

/**
 * Verify and decode an HMAC-SHA256 session token.
 */
export function verifySessionToken(token: string): AuthUser | null {
  try {
    const parts = token.split('.');
    if (parts.length !== 2) return null;

    const [payloadB64, signature] = parts;
    const expectedSignature = crypto
      .createHmac('sha256', AUTH_SECRET)
      .update(payloadB64)
      .digest('base64url');

    // Timing-safe signature comparison
    if (
      signature.length !== expectedSignature.length ||
      !crypto.timingSafeEqual(Buffer.from(signature), Buffer.from(expectedSignature))
    ) {
      return null;
    }

    const payload = JSON.parse(Buffer.from(payloadB64, 'base64url').toString('utf8'));
    const now = Math.floor(Date.now() / 1000);

    if (payload.exp && payload.exp < now) {
      return null; // Expired
    }

    return {
      id: payload.sub,
      name: payload.name,
      email: payload.email,
      role: payload.role as UserRole,
      clearanceLevel: payload.clearanceLevel,
      badgeId: payload.badgeId,
      lastLogin: new Date().toISOString(),
      token,
    };
  } catch {
    return null;
  }
}

/**
 * Pre-seed standard defense clearance users with hashed credentials if not already present.
 */
export function seedDefaultDefenseUsers(): void {
  const checkStmt = db.prepare(`SELECT COUNT(*) as count FROM users`);
  const count = (checkStmt.get() as any)?.count || 0;

  if (count === 0) {
    const defaultAccounts = [
      {
        id: 'usr_elena_vance',
        username: 'dr.vance',
        email: 'elena.vance@defense.gov',
        name: 'Dr. Elena Vance',
        role: 'LEAD_ASSURANCE_ENGINEER',
        clearanceLevel: 'LEVEL_4_TOP_SECRET',
        badgeId: 'AIA-9902-TS',
        passwordPlain: 'Assurance@Lead2026!',
      },
      {
        id: 'usr_marcus_kane',
        username: 'marcus.kane',
        email: 'marcus.kane@defense.gov',
        name: 'Marcus Kane',
        role: 'CYBER_SECURITY_AUDITOR',
        clearanceLevel: 'LEVEL_3_CONFIDENTIAL',
        badgeId: 'AIA-4401-CF',
        passwordPlain: 'Crypto@Audit2026!',
      },
      {
        id: 'usr_priya_sharma',
        username: 'priya.sharma',
        email: 'priya.sharma@defense.gov',
        name: 'Dr. Priya Sharma',
        role: 'AI_MODEL_VALIDATOR',
        clearanceLevel: 'LEVEL_3_CONFIDENTIAL',
        badgeId: 'AIA-7718-CF',
        passwordPlain: 'Neural@Model2026!',
      },
      {
        id: 'usr_raymond_shaw',
        username: 'col.shaw',
        email: 'raymond.shaw@defense.gov',
        name: 'Col. Raymond Shaw',
        role: 'DEFENSE_INSPECTOR',
        clearanceLevel: 'LEVEL_4_TOP_SECRET',
        badgeId: 'AIA-1100-CMD',
        passwordPlain: 'Defense@Command2026!',
      },
    ];

    const insertStmt = db.prepare(`
      INSERT INTO users (id, username, email, name, role, clearance_level, badge_id, password_hash, password_salt, created_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);

    for (const acc of defaultAccounts) {
      const { hash, salt } = hashPassword(acc.passwordPlain);
      insertStmt.run(
        acc.id,
        acc.username,
        acc.email,
        acc.name,
        acc.role,
        acc.clearanceLevel,
        acc.badgeId,
        hash,
        salt,
        new Date().toISOString()
      );
    }
  }
}

// Run initial seeding
seedDefaultDefenseUsers();

/**
 * Authenticate user with username/email and password.
 */
export function authenticateUser(identifier: string, passwordPlain: string): AuthUser | null {
  const stmt = db.prepare(`
    SELECT * FROM users
    WHERE username = ? OR email = ?
  `);
  const row = stmt.get(identifier.trim().toLowerCase(), identifier.trim().toLowerCase()) as Record<string, unknown> | undefined;

  if (!row) return null;

  const valid = verifyPassword(passwordPlain, row.password_hash as string, row.password_salt as string);
  if (!valid) return null;

  // Update last login
  db.prepare(`UPDATE users SET last_login_at = ? WHERE id = ?`).run(new Date().toISOString(), row.id as string);

  const user: AuthUser = {
    id: row.id as string,
    name: row.name as string,
    email: row.email as string,
    role: row.role as UserRole,
    clearanceLevel: row.clearance_level as any,
    badgeId: row.badge_id as string,
    lastLogin: new Date().toISOString(),
  };

  user.token = createSessionToken(user);
  return user;
}

/**
 * Create a quick evaluation user session by role.
 */
export function createQuickRoleSession(role: UserRole): AuthUser {
  const stmt = db.prepare(`SELECT * FROM users WHERE role = ? LIMIT 1`);
  const row = stmt.get(role) as Record<string, unknown> | undefined;

  if (row) {
    const user: AuthUser = {
      id: row.id as string,
      name: row.name as string,
      email: row.email as string,
      role: row.role as UserRole,
      clearanceLevel: row.clearance_level as any,
      badgeId: row.badge_id as string,
      lastLogin: new Date().toISOString(),
    };
    user.token = createSessionToken(user);
    return user;
  }

  // Fallback if not found
  const fallbackUser: AuthUser = {
    id: `usr_${Date.now()}`,
    name: 'Defense Analyst',
    email: 'analyst@defense.gov',
    role,
    clearanceLevel: role.includes('INSPECTOR') || role.includes('LEAD') ? 'LEVEL_4_TOP_SECRET' : 'LEVEL_3_CONFIDENTIAL',
    badgeId: 'AIA-GUEST',
    lastLogin: new Date().toISOString(),
  };
  fallbackUser.token = createSessionToken(fallbackUser);
  return fallbackUser;
}

// --- Express Middleware ---

/**
 * Middleware: Extract and verify Bearer token from Authorization header.
 * Attaches decoded user to req.user if present and valid.
 */
export function authenticateToken(req: Request, res: Response, next: NextFunction): void {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    next();
    return;
  }

  const token = authHeader.substring(7).trim();
  const user = verifySessionToken(token);
  if (user) {
    req.user = user;
  }
  next();
}

/**
 * Middleware: Require an authenticated session (HTTP 401 if missing or invalid).
 */
export function requireAuth(req: Request, res: Response, next: NextFunction): void {
  if (!req.user) {
    res.status(401).json({
      error: 'Authentication required. Missing or invalid defense authorization token.',
      code: 'UNAUTHENTICATED',
    });
    return;
  }
  next();
}

/**
 * Middleware: Require a minimum clearance level (HTTP 403 if insufficient).
 */
export function requireClearance(minLevel: 'LEVEL_3_CONFIDENTIAL' | 'LEVEL_4_TOP_SECRET') {
  return (req: Request, res: Response, next: NextFunction): void => {
    if (!req.user) {
      res.status(401).json({
        error: 'Authentication required to evaluate security clearance.',
        code: 'UNAUTHENTICATED',
      });
      return;
    }

    if (minLevel === 'LEVEL_4_TOP_SECRET' && req.user.clearanceLevel !== 'LEVEL_4_TOP_SECRET') {
      res.status(403).json({
        error: 'Access denied: Requires LEVEL 4 TOP SECRET defense clearance.',
        code: 'INSUFFICIENT_CLEARANCE',
      });
      return;
    }

    next();
  };
}

/**
 * Middleware: Protect administrative & system configuration routes.
 */
export function requireAdmin(req: Request, res: Response, next: NextFunction): void {
  if (!req.user) {
    res.status(401).json({
      error: 'Administrative action requires valid defense authentication.',
      code: 'UNAUTHENTICATED',
    });
    return;
  }

  const isPrivileged =
    req.user.clearanceLevel === 'LEVEL_4_TOP_SECRET' ||
    req.user.role === 'DEFENSE_INSPECTOR' ||
    req.user.role === 'LEAD_ASSURANCE_ENGINEER';

  if (!isPrivileged) {
    res.status(403).json({
      error: 'Access denied: Requires Administrator or Lead Assurance Inspector privileges.',
      code: 'FORBIDDEN',
    });
    return;
  }

  next();
}
