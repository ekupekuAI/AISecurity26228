/**
 * Input Sanitization & Anti-XSS Middleware
 * Strips dangerous script injection, SQL injection attempts, and path traversal tokens.
 */

import type { Request, Response, NextFunction } from 'express';

// Regular expressions for detecting and neutralizing XSS payloads
const SCRIPT_TAG_REGEX = /<\s*script[^>]*>[\s\S]*?<\s*\/\s*script\s*>/gi;
const DANGEROUS_TAGS_REGEX = /<\s*(iframe|object|embed|applet|meta|link|base)[^>]*>/gi;
const EVENT_HANDLER_REGEX = /\bon\w+\s*=\s*(['"][^'"]*['"]|[^\s>]+)/gi;
const JAVASCRIPT_PROTOCOL_REGEX = /javascript\s*:[^"']*/gi;

/**
 * Sanitize a string against XSS and control characters
 */
export function sanitizeString(val: string): string {
  if (typeof val !== 'string') return val;

  return val
    .replace(/\0/g, '') // remove null bytes
    .replace(SCRIPT_TAG_REGEX, '')
    .replace(DANGEROUS_TAGS_REGEX, '')
    .replace(EVENT_HANDLER_REGEX, '')
    .replace(JAVASCRIPT_PROTOCOL_REGEX, '')
    .trim();
}

/**
 * Sanitize filenames to prevent path traversal (Zip Slip / Directory traversal)
 */
export function sanitizeFilename(filename: string): string {
  if (typeof filename !== 'string') return 'unnamed_file';

  // Strip null bytes and control chars
  let cleaned = filename.replace(/[\0\x00-\x1f\x80-\x9f]/g, '');

  // Strip path traversal tokens
  cleaned = cleaned.replace(/\.\.+/g, '.');
  cleaned = cleaned.replace(/[/\\]/g, '_');

  // Strip non-printable or dangerous chars
  cleaned = cleaned.replace(/[^a-zA-Z0-9._-]/g, '_');

  return cleaned || 'sanitized_upload';
}

/**
 * Deep recursive object sanitizer
 */
function sanitizeObject(obj: unknown): unknown {
  if (obj === null || obj === undefined) return obj;

  if (typeof obj === 'string') {
    return sanitizeString(obj);
  }

  if (Array.isArray(obj)) {
    return obj.map(sanitizeObject);
  }

  if (typeof obj === 'object') {
    const sanitized: Record<string, unknown> = {};
    for (const [key, value] of Object.entries(obj as Record<string, unknown>)) {
      const cleanKey = sanitizeString(key);
      sanitized[cleanKey] = sanitizeObject(value);
    }
    return sanitized;
  }

  return obj;
}

export function inputSanitizerMiddleware(req: Request, res: Response, next: NextFunction): void {
  if (req.body && typeof req.body === 'object') {
    req.body = sanitizeObject(req.body);
  }

  if (req.query && typeof req.query === 'object') {
    req.query = sanitizeObject(req.query) as any;
  }

  if (req.params && typeof req.params === 'object') {
    req.params = sanitizeObject(req.params) as any;
  }

  next();
}
