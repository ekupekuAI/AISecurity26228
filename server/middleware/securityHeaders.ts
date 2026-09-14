/**
 * Security Headers Middleware
 * Protects against XSS, clickjacking, MIME sniffing, and leaks.
 */

import type { Request, Response, NextFunction } from 'express';

export function securityHeadersMiddleware(req: Request, res: Response, next: NextFunction): void {
  // Prevent MIME type sniffing
  res.setHeader('X-Content-Type-Options', 'nosniff');

  // Legacy browser XSS filter
  res.setHeader('X-XSS-Protection', '1; mode=block');

  // Control referrer information
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');

  // Restrict sensitive browser APIs
  res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=(), payment=()');

  // Allow popups while maintaining origin isolation
  res.setHeader('Cross-Origin-Opener-Policy', 'same-origin-allow-popups');

  // Strict Content-Security-Policy compatible with iframe preview and Vite
  const cspDirectives = [
    "default-src 'self'",
    "script-src 'self' 'unsafe-inline' 'unsafe-eval'",
    "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com",
    "font-src 'self' https://fonts.gstatic.com data:",
    "img-src 'self' data: blob: https:",
    "connect-src 'self' https: http://localhost:8000 ws: wss:",
    "frame-ancestors *",
    "object-src 'none'",
    "base-uri 'self'",
  ].join('; ');

  res.setHeader('Content-Security-Policy', cspDirectives);

  // Remove server fingerprint
  res.removeHeader('X-Powered-By');

  next();
}
