/**
 * Request-level security middleware.
 *
 * Notable departures from the previous build:
 *
 *  - **CSP is nonce-based and drops `unsafe-eval`.** The old policy allowed
 *    `unsafe-inline` and `unsafe-eval` on scripts and `frame-ancestors *`, which permits
 *    both arbitrary injected script and clickjacking. Vite's dev server genuinely needs
 *    `unsafe-inline` for HMR, so the relaxation is scoped to development only and
 *    production gets a strict policy.
 *
 *  - **Rate limiting no longer trusts `X-Forwarded-For` by default.** Trusting it lets a
 *    caller rotate their apparent address per request and bypass every limit.
 *
 *  - **No mutating sanitiser.** The old `inputSanitizerMiddleware` rewrote request bodies
 *    in place, stripping substrings from values. That silently corrupts legitimate data
 *    (a finding explanation containing `onerror=` loses characters) while providing no
 *    real XSS protection -- React escapes by default, and the defence that matters is
 *    output encoding plus CSP. Input is *validated* against a schema and rejected, not
 *    quietly rewritten.
 */

import crypto from 'node:crypto';
import type { NextFunction, Request, Response } from 'express';
import { CONFIG } from '../config.js';
import { log } from '../logger.js';
import { clientAddress, csrfTokenMatches, CSRF_HEADER } from './sessions.js';

declare global {
  // eslint-disable-next-line @typescript-eslint/no-namespace
  namespace Express {
    interface Request {
      cspNonce?: string;
      clientIp?: string;
    }
  }
}

export function securityHeaders(req: Request, res: Response, next: NextFunction): void {
  const nonce = crypto.randomBytes(16).toString('base64');
  req.cspNonce = nonce;

  const scriptSrc = CONFIG.isProduction
    ? `'self' 'nonce-${nonce}'`
    // Vite's dev client injects inline scripts and uses eval for HMR. This branch is
    // unreachable in production because NODE_ENV gates it.
    : `'self' 'unsafe-inline' 'unsafe-eval'`;

  const connectSrc = CONFIG.isProduction ? `'self'` : `'self' ws: wss:`;

  const directives = [
    `default-src 'self'`,
    `script-src ${scriptSrc}`,
    // The stylesheet itself is a static Tailwind build served from 'self'. The
    // allowance is for the <style> elements Radix injects at runtime for scroll
    // locking and layer ordering; style injection is not a script-execution vector,
    // and the alternative is a nonce that Radix has no way to receive.
    `style-src 'self' 'unsafe-inline'`,
    `img-src 'self' data: blob:`,
    `font-src 'self'`,
    `connect-src ${connectSrc}`,
    `object-src 'none'`,
    `base-uri 'none'`,
    `form-action 'self'`,
    // Clickjacking defence. The previous policy used `*`, which permits framing by any
    // origin -- the console's quarantine and accept controls are exactly the sort of
    // thing an attacker would want to trick an analyst into clicking.
    `frame-ancestors 'none'`,
    `frame-src 'none'`,
    `worker-src 'self' blob:`,
    `manifest-src 'self'`,
    `upgrade-insecure-requests`,
  ];

  res.setHeader('Content-Security-Policy', directives.join('; '));
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'no-referrer');
  res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=(), payment=(), usb=(), serial=()');
  res.setHeader('Cross-Origin-Opener-Policy', 'same-origin');
  res.setHeader('Cross-Origin-Resource-Policy', 'same-origin');
  res.setHeader('Cross-Origin-Embedder-Policy', 'require-corp');
  res.setHeader('X-Permitted-Cross-Domain-Policies', 'none');
  res.setHeader('Origin-Agent-Cluster', '?1');

  if (CONFIG.isProduction) {
    res.setHeader('Strict-Transport-Security', 'max-age=63072000; includeSubDomains; preload');
  }

  // Analysis results are evidence tied to a session; they must never be cached by a
  // shared proxy or written to browser disk cache.
  if (req.path.startsWith('/api') || req.path.startsWith('/analyze') || req.path.startsWith('/verify')) {
    res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, private');
    res.setHeader('Pragma', 'no-cache');
  }

  res.removeHeader('X-Powered-By');
  next();
}

function allowedOrigins(): string[] {
  const origins = new Set<string>();
  if (CONFIG.appUrl) origins.add(CONFIG.appUrl.replace(/\/$/, ''));
  for (const host of ['localhost', '127.0.0.1', '[::1]']) {
    origins.add(`http://${host}:${CONFIG.port}`);
    origins.add(`https://${host}:${CONFIG.port}`);
  }
  return [...origins];
}

/**
 * Same-origin-only CORS.
 *
 * A request with no Origin header is same-origin or a non-browser client and passes. A
 * request with an unrecognised Origin is refused outright rather than being served
 * without CORS headers, so a misconfiguration is loud instead of silent.
 */
export function cors(req: Request, res: Response, next: NextFunction): void {
  const origin = req.headers.origin;

  if (!origin) {
    if (req.method === 'OPTIONS') {
      res.status(204).end();
      return;
    }
    next();
    return;
  }

  if (!allowedOrigins().includes(origin.replace(/\/$/, ''))) {
    log.warn('cors origin refused', { origin, path: req.path });
    res.status(403).json({
      error: 'Cross-origin request refused by air-gapped deployment policy.',
      code: 'CORS_DENIED',
    });
    return;
  }

  res.setHeader('Access-Control-Allow-Origin', origin);
  res.setHeader('Vary', 'Origin');
  res.setHeader('Access-Control-Allow-Credentials', 'true');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PATCH, DELETE, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', `Content-Type, Authorization, ${CSRF_HEADER}, X-Requested-With`);
  res.setHeader('Access-Control-Max-Age', '600');

  if (req.method === 'OPTIONS') {
    res.status(204).end();
    return;
  }
  next();
}

interface Bucket {
  tokens: number;
  updatedAt: number;
}

/**
 * Token-bucket limiter.
 *
 * A bucket refills continuously rather than resetting on a window boundary, which
 * removes the burst-at-the-boundary behaviour of a fixed window without keeping a list of
 * timestamps per client.
 */
export function rateLimit(options: {
  capacity: number;
  refillPerSecond: number;
  name: string;
  keyBy?: (req: Request) => string;
}) {
  const buckets = new Map<string, Bucket>();

  const sweep = setInterval(() => {
    const cutoff = Date.now() - 10 * 60 * 1000;
    for (const [key, bucket] of buckets) {
      if (bucket.updatedAt < cutoff) buckets.delete(key);
    }
  }, 5 * 60 * 1000);
  sweep.unref();

  return (req: Request, res: Response, next: NextFunction): void => {
    const key = options.keyBy ? options.keyBy(req) : (req.clientIp ?? clientAddress(req));
    const now = Date.now();

    let bucket = buckets.get(key);
    if (!bucket) {
      bucket = { tokens: options.capacity, updatedAt: now };
      buckets.set(key, bucket);
    } else {
      const elapsed = (now - bucket.updatedAt) / 1000;
      bucket.tokens = Math.min(options.capacity, bucket.tokens + elapsed * options.refillPerSecond);
      bucket.updatedAt = now;
    }

    if (bucket.tokens < 1) {
      const retryAfter = Math.ceil((1 - bucket.tokens) / options.refillPerSecond);
      res.setHeader('Retry-After', String(retryAfter));
      res.setHeader('X-RateLimit-Limit', String(options.capacity));
      res.setHeader('X-RateLimit-Remaining', '0');
      log.warn('rate limit exceeded', { limiter: options.name, key, path: req.path });
      res.status(429).json({
        error: 'Rate limit exceeded for this operation.',
        code: 'RATE_LIMITED',
        retryAfterSeconds: retryAfter,
      });
      return;
    }

    bucket.tokens -= 1;
    res.setHeader('X-RateLimit-Limit', String(options.capacity));
    res.setHeader('X-RateLimit-Remaining', String(Math.floor(bucket.tokens)));
    next();
  };
}

/**
 * CSRF check for cookie-authenticated, state-changing requests.
 *
 * Bearer-token clients are exempt because the browser never attaches a bearer header
 * automatically -- CSRF is specifically an ambient-credential problem.
 */
export function csrfProtection(req: Request, res: Response, next: NextFunction): void {
  if (['GET', 'HEAD', 'OPTIONS'].includes(req.method)) {
    next();
    return;
  }

  const usedBearer = req.headers.authorization?.startsWith('Bearer ');
  if (usedBearer) {
    next();
    return;
  }

  const session = req.session;
  if (!session) {
    next();
    return;
  }

  const presented = req.headers[CSRF_HEADER] as string | undefined;
  if (!csrfTokenMatches(session.csrfToken, presented)) {
    log.warn('csrf token rejected', { path: req.path, actor: session.user.username });
    res.status(403).json({
      error: 'CSRF token missing or invalid. Reload the console and retry.',
      code: 'CSRF_INVALID',
    });
    return;
  }

  next();
}

/**
 * Reject a request body whose declared or actual size exceeds the ceiling.
 *
 * Express's own `limit` option handles the parsed body, but a Content-Length check before
 * any buffering means an oversized upload is rejected at the header rather than after the
 * server has already absorbed it.
 */
export function enforceContentLength(maxBytes: number) {
  return (req: Request, res: Response, next: NextFunction): void => {
    const declared = req.headers['content-length'];
    if (declared) {
      const size = Number.parseInt(declared, 10);
      if (Number.isFinite(size) && size > maxBytes) {
        res.status(413).json({
          error: `Request body exceeds the ${Math.floor(maxBytes / 1024 / 1024)} MB ceiling for this endpoint.`,
          code: 'PAYLOAD_TOO_LARGE',
        });
        return;
      }
    }
    next();
  };
}
