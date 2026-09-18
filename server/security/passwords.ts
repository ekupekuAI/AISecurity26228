/**
 * Password hashing and verification.
 *
 * scrypt with explicit, recorded parameters. Node's defaults (N=16384, r=8, p=1) are
 * below current guidance, and more importantly they are *implicit*: a checkpoint hashed
 * under one default cannot be verified after the default changes. Storing the parameters
 * alongside each hash makes the cost factor upgradable without invalidating existing
 * accounts.
 *
 * N=2^17 with r=8 needs ~128 MB per hash, which is the point -- it is what makes
 * offline cracking of a stolen database expensive. `maxmem` is raised to match, because
 * Node otherwise refuses the allocation.
 */

import crypto from 'node:crypto';

export interface KdfParams {
  algorithm: 'scrypt';
  N: number;
  r: number;
  p: number;
  keyLength: number;
}

export const CURRENT_KDF: KdfParams = {
  algorithm: 'scrypt',
  N: 1 << 17, // 131072
  r: 8,
  p: 1,
  keyLength: 64,
};

function derive(password: string, salt: string, params: KdfParams): Buffer {
  return crypto.scryptSync(password.normalize('NFKC'), salt, params.keyLength, {
    N: params.N,
    r: params.r,
    p: params.p,
    // scrypt needs roughly 128 * N * r bytes; without headroom Node throws.
    maxmem: 256 * params.N * params.r,
  });
}

export function hashPassword(password: string): { hash: string; salt: string; params: KdfParams } {
  const salt = crypto.randomBytes(16).toString('hex');
  return {
    hash: derive(password, salt, CURRENT_KDF).toString('hex'),
    salt,
    params: CURRENT_KDF,
  };
}

/**
 * Verify in constant time relative to the *content* of the hash.
 *
 * `timingSafeEqual` throws on a length mismatch, which would itself leak, so lengths are
 * compared first and a mismatch returns false without the comparison.
 */
export function verifyPassword(password: string, storedHash: string, salt: string, params?: KdfParams): boolean {
  try {
    const derived = derive(password, salt, params ?? CURRENT_KDF);
    const expected = Buffer.from(storedHash, 'hex');
    if (derived.length !== expected.length) return false;
    return crypto.timingSafeEqual(derived, expected);
  } catch {
    return false;
  }
}

/** A hash produced under older parameters should be upgraded on the next successful login. */
export function needsRehash(params: KdfParams | null | undefined): boolean {
  if (!params) return true;
  return params.N < CURRENT_KDF.N || params.r < CURRENT_KDF.r || params.keyLength < CURRENT_KDF.keyLength;
}

export interface PasswordPolicyResult {
  ok: boolean;
  problems: string[];
}

/**
 * Length-first policy, following NIST SP 800-63B: length and a blocklist of predictable
 * values do far more than composition rules, which mostly produce `Password1!`.
 */
export function checkPasswordPolicy(password: string, context: string[] = []): PasswordPolicyResult {
  const problems: string[] = [];

  if (password.length < 12) problems.push('Must be at least 12 characters.');
  if (password.length > 256) problems.push('Must be at most 256 characters.');

  const lowered = password.toLowerCase();
  for (const term of context) {
    if (term && term.length >= 4 && lowered.includes(term.toLowerCase())) {
      problems.push('Must not contain your username, name or email.');
      break;
    }
  }

  const COMMON = [
    'password', 'passw0rd', '123456', 'qwerty', 'letmein', 'welcome', 'admin',
    'defense', 'defence', 'assurance', 'changeme', 'iloveyou', 'monkey', 'dragon',
  ];
  if (COMMON.some((term) => lowered.includes(term))) {
    problems.push('Contains a commonly used or guessable term.');
  }

  if (/^(.)\1+$/.test(password)) problems.push('Must not be a single repeated character.');

  // Sequential runs like "abcdef" or "123456" are trivially enumerated.
  let run = 1;
  for (let i = 1; i < password.length; i += 1) {
    if (password.charCodeAt(i) === password.charCodeAt(i - 1) + 1) {
      run += 1;
      if (run >= 5) {
        problems.push('Must not contain a long sequential run of characters.');
        break;
      }
    } else {
      run = 1;
    }
  }

  return { ok: problems.length === 0, problems };
}

/** A random password that satisfies the policy, for bootstrapping an account. */
export function generatePassword(length = 24): string {
  const alphabet = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789-_@#%+=';
  const bytes = crypto.randomBytes(length * 2);
  let out = '';
  for (let i = 0; out.length < length && i < bytes.length; i += 1) {
    // Rejection sampling: taking `byte % alphabet.length` would bias toward early
    // characters, which shrinks the effective keyspace.
    const index = bytes[i];
    if (index < Math.floor(256 / alphabet.length) * alphabet.length) {
      out += alphabet[index % alphabet.length];
    }
  }
  return out;
}
