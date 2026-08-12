import { verifySignature } from '../utils/hmac.js';

/**
 * In-memory sliding-window TTL cache for tracked nonces.
 * Prevents replay attacks within the timestamp drift window.
 */
export class NonceStore {
  constructor(ttlMs = 600000) {
    this.ttlMs = ttlMs;
    this.nonces = new Map(); // nonce -> addedAt timestamp
  }

  /**
   * Checks if a nonce has already been seen and is still within TTL.
   * @param {string} nonce
   * @returns {boolean}
   */
  has(nonce) {
    this.cleanup();
    return this.nonces.has(nonce);
  }

  /**
   * Records a nonce in the store.
   * @param {string} nonce
   */
  add(nonce) {
    this.cleanup();
    this.nonces.set(nonce, Date.now());
  }

  /**
   * Clears all stored nonces.
   */
  clear() {
    this.nonces.clear();
  }

  /**
   * Purges expired nonces from the map.
   */
  cleanup() {
    const now = Date.now();
    for (const [nonce, addedAt] of this.nonces.entries()) {
      if (now - addedAt > this.ttlMs) {
        this.nonces.delete(nonce);
      }
    }
  }
}

// Global default nonce store instance
export const globalNonceStore = new NonceStore();

/**
 * Creates Express security middleware for HMAC authentication and anti-replay protection.
 *
 * @param {Object} [options]
 * @param {string} [options.secret] - Shared HMAC secret
 * @param {number} [options.maxTimestampDiffMs] - Maximum clock skew window in milliseconds
 * @param {NonceStore} [options.nonceStore] - Nonce store instance
 * @returns {Function} Express middleware handler
 */
export function createSecurityMiddleware(options = {}) {
  const secret = options.secret || process.env.HMAC_SECRET || 'super_secret_key_12345';
  const maxTimestampDiffMs = options.maxTimestampDiffMs ?? 
    parseInt(process.env.MAX_TIMESTAMP_DIFF_MS || '300000', 10);
  const nonceStore = options.nonceStore || globalNonceStore;

  return function hmacSecurityMiddleware(req, res, next) {
    const signature = req.headers['x-signature'];
    const timestampHeader = req.headers['x-timestamp'];
    const nonce = req.headers['x-nonce'];

    // 1. Missing header validation
    if (!signature || !timestampHeader || !nonce) {
      return res.status(400).json({
        error: 'Missing required security headers',
        requiredHeaders: ['x-signature', 'x-timestamp', 'x-nonce'],
        receivedHeaders: {
          'x-signature': !!signature,
          'x-timestamp': !!timestampHeader,
          'x-nonce': !!nonce
        }
      });
    }

    const timestamp = parseInt(timestampHeader, 10);
    if (isNaN(timestamp)) {
      return res.status(400).json({
        error: 'Invalid x-timestamp header format. Must be numeric millisecond timestamp'
      });
    }

    // 2. Timestamp drift / clock skew validation
    const now = Date.now();
    const timeDiff = Math.abs(now - timestamp);

    if (timeDiff > maxTimestampDiffMs) {
      return res.status(401).json({
        error: 'Timestamp outside acceptable window',
        serverTime: now,
        requestTime: timestamp,
        timeDiffMs: timeDiff,
        maxAllowedDiffMs: maxTimestampDiffMs
      });
    }

    // 3. Replay attack detection (Nonce uniqueness check)
    if (nonceStore.has(nonce)) {
      return res.status(409).json({
        error: 'Replay attack detected: Nonce has already been processed',
        nonce
      });
    }

    // 4. HMAC Signature verification
    const isValid = verifySignature({
      method: req.method,
      path: req.path,
      timestamp: timestampHeader,
      nonce,
      body: req.body,
      signature,
      secret
    });

    if (!isValid) {
      return res.status(401).json({
        error: 'Invalid HMAC signature'
      });
    }

    // 5. Record nonce to prevent future replay
    nonceStore.add(nonce);

    next();
  };
}
