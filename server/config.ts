/**
 * Gateway configuration, resolved once at boot and validated.
 *
 * Fail-fast is the policy: a production boot with a missing secret aborts rather than
 * generating an ephemeral one. An ephemeral secret looks like it works -- until the
 * process restarts and every session silently dies, or until a second instance issues
 * tokens the first will not accept. Both are worse than refusing to start.
 */

import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';

export type Environment = 'production' | 'development' | 'test';

function envString(name: string, fallback = ''): string {
  const raw = process.env[name];
  return raw === undefined || raw.trim() === '' ? fallback : raw.trim();
}

function envInt(name: string, fallback: number): number {
  const raw = process.env[name];
  if (raw === undefined || raw.trim() === '') return fallback;
  const parsed = Number.parseInt(raw, 10);
  return Number.isFinite(parsed) ? parsed : fallback;
}

function envBool(name: string, fallback = false): boolean {
  const raw = process.env[name];
  if (raw === undefined || raw.trim() === '') return fallback;
  return ['1', 'true', 'yes', 'on'].includes(raw.trim().toLowerCase());
}

const environment = (envString('NODE_ENV', 'development') as Environment) ?? 'development';
const isProduction = environment === 'production';

const dataDir = path.resolve(envString('AIA_DATA_DIR', path.join(process.cwd(), 'data')));
const secretsDir = path.join(dataDir, 'keys');

/**
 * Resolve a long-lived secret.
 *
 * Order: environment, then a 0600 file under the data directory, then generate and
 * persist. Generating is acceptable for a single-node air-gapped install -- the operator
 * never has to invent a secret -- but it is written to disk so restarts are survivable,
 * and in production the file's absence is logged loudly.
 */
function resolvePersistentSecret(envName: string, fileName: string): string {
  const fromEnv = envString(envName);
  if (fromEnv) {
    if (fromEnv.length < 32) {
      throw new Error(
        `${envName} must be at least 32 characters. Generate one with: ` +
          `node -e "console.log(require('crypto').randomBytes(48).toString('base64url'))"`
      );
    }
    return fromEnv;
  }

  fs.mkdirSync(secretsDir, { recursive: true, mode: 0o700 });
  const secretPath = path.join(secretsDir, fileName);

  if (fs.existsSync(secretPath)) {
    const existing = fs.readFileSync(secretPath, 'utf8').trim();
    if (existing.length >= 32) return existing;
  }

  const generated = crypto.randomBytes(48).toString('base64url');
  // Written with the mode set at creation so it is never briefly world-readable.
  fs.writeFileSync(secretPath, generated, { mode: 0o600, flag: 'w' });
  try {
    fs.chmodSync(secretPath, 0o600);
  } catch {
    // Windows ignores POSIX modes; the directory ACL applies instead.
  }
  return generated;
}

/**
 * Only loopback and private-range hosts may be used for the ML engine.
 *
 * Without this, an operator (or anyone who reaches the config endpoint) can repoint the
 * engine URL at an external host and every uploaded dataset and checkpoint is exfiltrated
 * on the next analysis. On an air-gapped node there is no legitimate reason for this URL
 * to leave the machine or its subnet.
 */
export function isAllowedEngineUrl(raw: string): { ok: true; url: URL } | { ok: false; reason: string } {
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    return { ok: false, reason: 'Not a valid absolute URL.' };
  }

  if (url.protocol !== 'http:' && url.protocol !== 'https:') {
    return { ok: false, reason: `Protocol ${url.protocol} is not permitted; use http or https.` };
  }
  if (url.username || url.password) {
    return { ok: false, reason: 'Credentials embedded in the URL are not permitted.' };
  }

  const host = url.hostname.toLowerCase().replace(/^\[|\]$/g, '');

  if (host === 'localhost' || host === '127.0.0.1' || host === '::1' || host === '0.0.0.0') {
    return { ok: true, url };
  }

  // IPv4 private ranges, which cover an intranet deployment where the engine runs on a
  // separate host inside the same enclave.
  const v4 = host.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
  if (v4) {
    const [a, b] = [Number(v4[1]), Number(v4[2])];
    if (a === 127) return { ok: true, url };
    if (a === 10) return { ok: true, url };
    if (a === 192 && b === 168) return { ok: true, url };
    if (a === 172 && b >= 16 && b <= 31) return { ok: true, url };
    return { ok: false, reason: `${host} is a public address. The engine must live on loopback or a private range.` };
  }

  // IPv6 unique-local (fc00::/7) and link-local (fe80::/10).
  if (/^f[cd][0-9a-f]{2}:/i.test(host) || /^fe[89ab][0-9a-f]:/i.test(host)) {
    return { ok: true, url };
  }

  const extraHosts = envString('AIA_ENGINE_ALLOWED_HOSTS')
    .split(',')
    .map((h) => h.trim().toLowerCase())
    .filter(Boolean);
  if (extraHosts.includes(host)) {
    return { ok: true, url };
  }

  return {
    ok: false,
    reason:
      `Host '${host}' is not loopback, private-range, or explicitly allowed. ` +
      'Add it to AIA_ENGINE_ALLOWED_HOSTS if this is an intentional intranet deployment.',
  };
}

const defaultEngineUrl = envString('ML_SERVICE_URL', 'http://127.0.0.1:8000');
const engineCheck = isAllowedEngineUrl(defaultEngineUrl);
if (!engineCheck.ok) {
  throw new Error(`ML_SERVICE_URL is rejected: ${engineCheck.reason}`);
}

export const CONFIG = {
  environment,
  isProduction,
  port: envInt('PORT', 3000),
  /**
   * Binding to 0.0.0.0 exposes the console to the whole network. That is occasionally
   * what an intranet deployment wants, but it must be a deliberate choice, so the
   * default is loopback.
   */
  host: envString('HOST', '127.0.0.1'),

  dataDir,
  databasePath: path.join(dataDir, 'ai_integrity.db'),
  uploadTempDir: path.join(dataDir, 'uploads'),

  sessionSecret: resolvePersistentSecret('AUTH_SECRET', 'session.secret'),
  sessionTtlSeconds: envInt('AIA_SESSION_TTL', 8 * 60 * 60),
  /** Idle timeout: a console left unattended in an operations room must not stay live. */
  sessionIdleSeconds: envInt('AIA_SESSION_IDLE', 45 * 60),

  engineUrl: defaultEngineUrl,
  engineToken: envString('AIA_SERVICE_TOKEN'),
  engineTimeoutMs: envInt('AIA_ENGINE_TIMEOUT_MS', 15 * 60 * 1000),
  engineHealthTimeoutMs: envInt('AIA_ENGINE_HEALTH_TIMEOUT_MS', 1500),

  maxUploadBytes: envInt('AIA_MAX_UPLOAD_BYTES', 1024 * 1024 * 1024),
  maxJsonBytes: envInt('AIA_MAX_JSON_BYTES', 2 * 1024 * 1024),

  /**
   * Demo mode enables the evaluation-seeding endpoints and the read-only demo login.
   * It is refused in production unless explicitly forced, because those endpoints exist
   * to make a demonstration convenient, not to be reachable on a deployed node.
   */
  demoMode: envBool('AIA_DEMO_MODE', !isProduction),

  /**
   * Number of proxies in front of this server. Zero means X-Forwarded-For is ignored
   * entirely -- which is correct, because an attacker can otherwise set that header and
   * bypass every per-IP rate limit.
   */
  trustProxyHops: envInt('AIA_TRUST_PROXY_HOPS', 0),

  appUrl: envString('APP_URL'),

  bootstrapAdminUser: envString('AIA_BOOTSTRAP_USER'),
  bootstrapAdminPassword: envString('AIA_BOOTSTRAP_PASSWORD'),
} as const;

export function ensureRuntimeDirectories(): void {
  fs.mkdirSync(CONFIG.dataDir, { recursive: true });
  fs.mkdirSync(CONFIG.uploadTempDir, { recursive: true });
}

/**
 * Configuration problems that should stop a production boot, or at least be shouted
 * about in development. Returned rather than thrown so the caller can log them all.
 */
export function auditConfiguration(): { fatal: string[]; warnings: string[] } {
  const fatal: string[] = [];
  const warnings: string[] = [];

  if (CONFIG.isProduction) {
    if (!process.env.AUTH_SECRET) {
      warnings.push(
        'AUTH_SECRET is not set; a persistent secret was generated under data/keys/. Set it ' +
          'explicitly before running more than one instance.'
      );
    }
    if (CONFIG.demoMode) {
      fatal.push(
        'AIA_DEMO_MODE is enabled in production. Demo seeding endpoints and the demo login ' +
          'must not be reachable on a deployed node.'
      );
    }
    if (CONFIG.host === '0.0.0.0' && !CONFIG.appUrl) {
      warnings.push(
        'Server binds 0.0.0.0 with no APP_URL configured. Set APP_URL so CORS and cookie ' +
          'policy match the real origin.'
      );
    }
    if (!CONFIG.engineToken) {
      warnings.push(
        'AIA_SERVICE_TOKEN is not set. The gateway->engine hop relies on loopback isolation ' +
          'alone, which is only sufficient when both run on the same host.'
      );
    }
    if (CONFIG.appUrl && !CONFIG.appUrl.startsWith('https://')) {
      // The session cookie is issued Secure with a __Host- prefix in production, so a
      // browser reaching this node over plain http silently discards it: sign-in returns
      // 200 and the very next request is 401, which looks like a broken login rather
      // than a missing TLS terminator. Say so at boot instead.
      warnings.push(
        `APP_URL is ${CONFIG.appUrl}, which is not https. The production session cookie is ` +
          'issued Secure with a __Host- prefix, and a browser will discard it over plain ' +
          'http -- sign-in will appear to succeed and then immediately fail. Put a TLS ' +
          'terminator in front of this node, or run it in development mode for local use.'
      );
    } else if (!CONFIG.appUrl) {
      warnings.push(
        'APP_URL is not set. In production the session cookie is issued Secure with a ' +
          '__Host- prefix, so the console must be reached over https or the browser will ' +
          'discard it and sign-in will fail on the next request.'
      );
    }
  }

  return { fatal, warnings };
}
