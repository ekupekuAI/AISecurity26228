/**
 * In-Memory Sliding Window Rate Limiting Middleware
 * Protects against brute-force, denial-of-service, and resource exhaustion.
 */

import type { Request, Response, NextFunction } from 'express';

interface RateLimitRecord {
  timestamps: number[];
}

export function createRateLimiter(options: {
  windowMs: number;
  maxRequests: number;
  message?: string;
}) {
  const store = new Map<string, RateLimitRecord>();
  const { windowMs, maxRequests, message = 'Too many requests. Please try again later.' } = options;

  // Cleanup old entries every 5 minutes to prevent memory leak
  setInterval(() => {
    const now = Date.now();
    for (const [ip, record] of store.entries()) {
      record.timestamps = record.timestamps.filter((t) => now - t < windowMs);
      if (record.timestamps.length === 0) {
        store.delete(ip);
      }
    }
  }, 5 * 60 * 1000).unref();

  return (req: Request, res: Response, next: NextFunction): void => {
    // Extract client IP (handle standard proxy headers)
    const forwarded = req.headers['x-forwarded-for'];
    const ip = typeof forwarded === 'string'
      ? forwarded.split(',')[0].trim()
      : req.socket.remoteAddress || 'unknown-client';

    const now = Date.now();
    let record = store.get(ip);

    if (!record) {
      record = { timestamps: [] };
      store.set(ip, record);
    }

    // Keep only timestamps within window
    record.timestamps = record.timestamps.filter((t) => now - t < windowMs);

    const remaining = Math.max(0, maxRequests - record.timestamps.length);
    const resetTimeSeconds = Math.ceil((windowMs - (record.timestamps[0] ? now - record.timestamps[0] : 0)) / 1000);

    res.setHeader('X-RateLimit-Limit', maxRequests.toString());
    res.setHeader('X-RateLimit-Remaining', remaining.toString());
    res.setHeader('X-RateLimit-Reset', (Math.floor(now / 1000) + resetTimeSeconds).toString());

    if (record.timestamps.length >= maxRequests) {
      res.setHeader('Retry-After', resetTimeSeconds.toString());
      res.status(429).json({
        error: message,
        retryAfterSeconds: resetTimeSeconds,
      });
      return;
    }

    record.timestamps.push(now);
    next();
  };
}

// Global API rate limiter: 250 requests per minute
export const globalRateLimiter = createRateLimiter({
  windowMs: 60 * 1000,
  maxRequests: 250,
  message: 'API rate limit exceeded. Please throttle requests.',
});

// Strict rate limiter for Authentication and heavy file uploads: 40 requests per minute
export const strictRateLimiter = createRateLimiter({
  windowMs: 60 * 1000,
  maxRequests: 40,
  message: 'Security rate limit exceeded for sensitive operation. Please wait 1 minute.',
});
