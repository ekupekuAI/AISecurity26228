/**
 * Structured JSON logging with request correlation.
 *
 * Two rules, both of which exist because logs on an assurance node are themselves
 * evidence:
 *
 *  - Never log a secret, a token, a password, a session id or a raw request body. The
 *    redactor runs over every field rather than trusting call sites to remember.
 *  - Never put a raw exception message in a response. Log it here with an id and return
 *    the id, so an operator can correlate without the error text leaking internals to a
 *    caller.
 */

import { AsyncLocalStorage } from 'node:async_hooks';
import crypto from 'node:crypto';
import { CONFIG } from './config.js';
import { recordError } from './db/errors.js';

type Level = 'debug' | 'info' | 'warn' | 'error';

const LEVELS: Record<Level, number> = { debug: 10, info: 20, warn: 30, error: 40 };
const MIN_LEVEL = LEVELS[(process.env.LOG_LEVEL as Level) ?? (CONFIG.isProduction ? 'info' : 'debug')] ?? 20;

const context = new AsyncLocalStorage<{ requestId: string; actor?: string }>();

const SENSITIVE_KEY = /pass(word|phrase)?|secret|token|cookie|authorization|session|nonce_key|private/i;

function redact(value: unknown, depth = 0): unknown {
  if (depth > 6) return '[depth-limit]';
  if (value === null || value === undefined) return value;
  if (typeof value === 'string') return value.length > 2000 ? `${value.slice(0, 2000)}...[truncated]` : value;
  if (typeof value === 'number' || typeof value === 'boolean') return value;
  if (Array.isArray(value)) return value.slice(0, 50).map((item) => redact(item, depth + 1));
  if (value instanceof Error) return { name: value.name, message: value.message };
  if (typeof value === 'object') {
    const out: Record<string, unknown> = {};
    for (const [key, inner] of Object.entries(value as Record<string, unknown>)) {
      out[key] = SENSITIVE_KEY.test(key) ? '[redacted]' : redact(inner, depth + 1);
    }
    return out;
  }
  return String(value);
}

function emit(level: Level, message: string, fields: Record<string, unknown> = {}): void {
  if (LEVELS[level] < MIN_LEVEL) return;
  const store = context.getStore();
  const line = {
    ts: new Date().toISOString(),
    level: level.toUpperCase(),
    msg: message,
    requestId: store?.requestId ?? '-',
    actor: store?.actor,
    ...(redact(fields) as Record<string, unknown>),
  };
  const serialised = JSON.stringify(line);
  if (level === 'error' || level === 'warn') process.stderr.write(`${serialised}\n`);
  else process.stdout.write(`${serialised}\n`);
}

export const log = {
  debug: (message: string, fields?: Record<string, unknown>) => emit('debug', message, fields),
  info: (message: string, fields?: Record<string, unknown>) => emit('info', message, fields),
  warn: (message: string, fields?: Record<string, unknown>) => emit('warn', message, fields),
  error: (message: string, fields?: Record<string, unknown>) => emit('error', message, fields),
};

export function newRequestId(): string {
  return crypto.randomBytes(8).toString('hex');
}

export function runWithContext<T>(requestId: string, fn: () => T): T {
  return context.run({ requestId }, fn);
}

export function setActor(actor: string): void {
  const store = context.getStore();
  if (store) store.actor = actor;
}

export function currentRequestId(): string {
  return context.getStore()?.requestId ?? '-';
}

/**
 * Log an exception in full and return a correlation id for the response. The caller
 * returns the id; the message never crosses the wire.
 */
export function captureException(error: unknown, where: string, fields?: Record<string, unknown>): string {
  const incidentId = crypto.randomBytes(6).toString('hex').toUpperCase();
  const err = error instanceof Error ? error : new Error(String(error));
  log.error('unhandled exception', {
    incidentId,
    where,
    name: err.name,
    message: err.message,
    stack: CONFIG.isProduction ? undefined : err.stack,
    ...fields,
  });
  // Also persist it so the Sentinel operational sensor can count server faults; stderr
  // alone is invisible to every monitor. Best-effort and never throws.
  recordError(where, err.name, err.message, typeof fields?.httpStatus === 'number' ? fields.httpStatus : undefined);
  return incidentId;
}
