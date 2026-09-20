/**
 * Client for the Python assurance engine.
 *
 * Two things this file is careful about.
 *
 * **SSRF.** The engine URL is operator-configurable, which makes it an exfiltration
 * primitive if unconstrained: repoint it at an external host and every uploaded dataset
 * and checkpoint is shipped there on the next analysis. `isAllowedEngineUrl` restricts it
 * to loopback and private ranges, and the check runs again at call time rather than only
 * at configuration time -- a value that was validated once and stored can still be
 * changed by another path.
 *
 * **Honest degradation.** When the engine is unreachable the gateway falls back to a
 * small set of TypeScript analysers. Those cannot do embeddings, trigger inversion or
 * Mahalanobis scoring, so a fallback result is *explicitly marked degraded* and carries a
 * finding saying so. Silently returning a thin result that looks like a full one is how
 * an assurance tool ends up certifying an asset nobody actually inspected.
 */

import { Buffer } from 'node:buffer';
import { CONFIG, isAllowedEngineUrl } from './config.js';
import { log } from './logger.js';
import { currentRequestId } from './logger.js';

let engineUrl = CONFIG.engineUrl;

export type EngineStatus = 'ONLINE' | 'OFFLINE' | 'DEGRADED';

export interface EngineHealth {
  status: EngineStatus;
  url: string;
  details?: Record<string, unknown>;
  error?: string;
  checkedAt: string;
}

let cachedHealth: EngineHealth | null = null;
let cachedAt = 0;
const HEALTH_CACHE_MS = 3000;

export function getEngineUrl(): string {
  return engineUrl;
}

export function setEngineUrl(next: string): { ok: boolean; reason?: string } {
  const verdict = isAllowedEngineUrl(next);
  if (!verdict.ok) return { ok: false, reason: verdict.reason };
  engineUrl = next.trim().replace(/\/+$/, '');
  cachedHealth = null;
  log.info('engine url updated', { engineUrl });
  return { ok: true };
}

function headers(extra: Record<string, string> = {}): Record<string, string> {
  const base: Record<string, string> = { 'x-request-id': currentRequestId(), ...extra };
  if (CONFIG.engineToken) base['x-aia-service-token'] = CONFIG.engineToken;
  return base;
}

async function request(path: string, init: RequestInit, timeoutMs: number): Promise<Response> {
  // Re-validate every call. Cheap, and it closes the window where the URL was mutated
  // through a path that skipped the setter.
  const verdict = isAllowedEngineUrl(engineUrl);
  if (!verdict.ok) {
    throw new Error(`Engine URL is not permitted: ${verdict.reason}`);
  }

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    return await fetch(`${engineUrl}${path}`, {
      ...init,
      signal: controller.signal,
      // A redirect could walk the request off the allowlisted host, so they are refused
      // rather than followed.
      redirect: 'error',
    });
  } finally {
    clearTimeout(timer);
  }
}

/**
 * A connection-level failure is one where the request never reached the engine: the socket
 * was refused or reset, typically because the engine is mid-restart. Those are worth one
 * quick retry. A timeout (AbortError) is deliberately NOT retried -- the request may have
 * reached a busy engine that is still working, and hammering it would only make things
 * worse. An HTTP error never gets here; it is surfaced as EngineUnavailableError instead.
 */
function isConnectionError(error: unknown): boolean {
  if (!error || typeof error !== 'object') return false;
  const e = error as { name?: string; cause?: { code?: string } };
  if (e.name === 'AbortError') return false;
  const code = e.cause?.code;
  return (
    e.name === 'TypeError' ||
    code === 'ECONNREFUSED' ||
    code === 'ECONNRESET' ||
    code === 'ENOTFOUND' ||
    code === 'UND_ERR_SOCKET' ||
    code === 'UND_ERR_CONNECT_TIMEOUT'
  );
}

async function requestWithRetry(path: string, init: RequestInit, timeoutMs: number, attempts = 2): Promise<Response> {
  let lastError: unknown;
  for (let attempt = 0; attempt < attempts; attempt += 1) {
    try {
      return await request(path, init, timeoutMs);
    } catch (error) {
      lastError = error;
      if (attempt < attempts - 1 && isConnectionError(error)) {
        log.warn('engine connection failed; retrying', { path, attempt: attempt + 1 });
        await new Promise((resolve) => setTimeout(resolve, 400 * (attempt + 1)));
        continue;
      }
      throw error;
    }
  }
  throw lastError;
}

export async function checkEngineHealth(force = false): Promise<EngineHealth> {
  const now = Date.now();
  if (!force && cachedHealth && now - cachedAt < HEALTH_CACHE_MS) return cachedHealth;

  const checkedAt = new Date().toISOString();
  try {
    const response = await requestWithRetry('/health', { method: 'GET', headers: headers() }, CONFIG.engineHealthTimeoutMs);
    if (response.ok) {
      const details = (await response.json()) as Record<string, unknown>;
      cachedHealth = { status: 'ONLINE', url: engineUrl, details, checkedAt };
    } else {
      cachedHealth = {
        status: 'DEGRADED',
        url: engineUrl,
        error: `Engine responded ${response.status}`,
        checkedAt,
      };
    }
  } catch (error) {
    cachedHealth = {
      status: 'OFFLINE',
      url: engineUrl,
      error: error instanceof Error ? error.message : String(error),
      checkedAt,
    };
  }

  cachedAt = now;
  return cachedHealth;
}

/**
 * The last engine-health snapshot, read synchronously (no await) by the Sentinel
 * operational sensor. Null until the first health check runs.
 */
export function getCachedEngineHealth(): EngineHealth | null {
  return cachedHealth;
}

export class EngineUnavailableError extends Error {
  constructor(public readonly detail: string) {
    super(`Assurance engine unavailable: ${detail}`);
    this.name = 'EngineUnavailableError';
  }
}

/** Build a multipart body by hand so the file bytes are laid out exactly once. */
function multipart(filename: string, content: Buffer, field = 'file'): { body: Buffer; contentType: string } {
  const boundary = `----aia${Date.now().toString(36)}${Math.random().toString(36).slice(2, 10)}`;
  const safeName = filename.replace(/["\\\r\n]/g, '_');
  const head = Buffer.from(
    `--${boundary}\r\n` +
      `Content-Disposition: form-data; name="${field}"; filename="${safeName}"\r\n` +
      `Content-Type: application/octet-stream\r\n\r\n`,
    'utf8'
  );
  const tail = Buffer.from(`\r\n--${boundary}--\r\n`, 'utf8');
  return {
    body: Buffer.concat([head, content, tail]),
    contentType: `multipart/form-data; boundary=${boundary}`,
  };
}

export async function analyzeDatasetRemote(filename: string, content: Buffer): Promise<Record<string, unknown>> {
  const { body, contentType } = multipart(filename, content);
  const response = await requestWithRetry(
    '/analyze/dataset',
    { method: 'POST', headers: headers({ 'content-type': contentType }), body },
    CONFIG.engineTimeoutMs
  );
  if (!response.ok) {
    throw new EngineUnavailableError(`dataset analysis returned ${response.status}`);
  }
  return (await response.json()) as Record<string, unknown>;
}

export async function analyzeModelRemote(filename: string, content: Buffer): Promise<Record<string, unknown>> {
  const { body, contentType } = multipart(filename, content);
  const response = await requestWithRetry(
    '/analyze/model',
    { method: 'POST', headers: headers({ 'content-type': contentType }), body },
    CONFIG.engineTimeoutMs
  );
  if (!response.ok) {
    throw new EngineUnavailableError(`model analysis returned ${response.status}`);
  }
  return (await response.json()) as Record<string, unknown>;
}

export async function analyzeShiftRemote(payload: Record<string, unknown>): Promise<Record<string, unknown>> {
  const response = await request(
    '/analyze/distribution-shift',
    { method: 'POST', headers: headers({ 'content-type': 'application/json' }), body: JSON.stringify(payload) },
    60_000
  );
  if (!response.ok) {
    throw new EngineUnavailableError(`distribution-shift analysis returned ${response.status}`);
  }
  return (await response.json()) as Record<string, unknown>;
}

export async function enginePublicKey(): Promise<Record<string, unknown> | null> {
  try {
    const response = await request('/provenance/public-key', { method: 'GET', headers: headers() }, 5000);
    if (!response.ok) return null;
    return (await response.json()) as Record<string, unknown>;
  } catch {
    return null;
  }
}

/**
 * Mark a result as produced by the degraded local fallback.
 *
 * The added finding is deliberately MEDIUM rather than INFO: an assessment that skipped
 * trigger inversion, embedding analytics and OOD scoring is not a clean bill of health,
 * and the governance engine treats a coverage gap as grounds for REVIEW rather than
 * ACCEPT.
 */
export function markDegraded(result: Record<string, unknown>, reason: string): Record<string, unknown> {
  const findings = Array.isArray(result.findings) ? [...(result.findings as unknown[])] : [];
  findings.unshift({
    id: `FIND-DEGRADED-${Date.now().toString(36).toUpperCase()}`,
    findingId: 'SYS-DEGRADED-ANALYSIS',
    category: 'MODEL',
    severity: 'MEDIUM',
    confidence: 1.0,
    affectedAsset: String(result.filename ?? 'submitted asset'),
    explanation:
      'This assessment ran on the gateway fallback analysers because the Python assurance ' +
      `engine was unreachable (${reason}). Perceptual near-duplicate matching, embedding-based ` +
      'label-consistency checking, Mahalanobis out-of-distribution scoring, behavioural trigger ' +
      'batteries and Neural Cleanse trigger inversion were all skipped. Only hashing, container ' +
      'structure and static checks were performed.',
    evidence: { engineUrl: engineUrl, reason, degradedAt: new Date().toISOString() },
    recommendation:
      'Restore the assurance engine and re-run this analysis before making any release decision. ' +
      'Do not treat this result as a completed assessment.',
    detector: 'server/engineClient.markDegraded',
    threshold: 'engine reachability',
    references: [],
    timestamp: new Date().toISOString(),
  });

  return {
    ...result,
    findings,
    engine: 'node-fallback',
    degraded: true,
    degradedReason: reason,
    coverageGaps: [
      ...(Array.isArray(result.coverageGaps) ? (result.coverageGaps as string[]) : []),
      'python-engine-unavailable',
    ],
  };
}
