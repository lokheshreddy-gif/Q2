import crypto from 'crypto';

/**
 * Builds the canonical string representation of an incoming or outgoing HTTP request.
 * Canonical format: METHOD:PATH:TIMESTAMP:NONCE:BODY_JSON
 *
 * @param {Object} params
 * @param {string} params.method - HTTP method (e.g. POST, GET)
 * @param {string} params.path - Endpoint path (e.g. /api/action)
 * @param {string|number} params.timestamp - Millisecond timestamp
 * @param {string} params.nonce - Unique request nonce
 * @param {Object|string|null} [params.body] - Request body object or string
 * @returns {string} Canonical string
 */
export function buildCanonicalString({ method, path, timestamp, nonce, body }) {
  const normMethod = (method || '').toUpperCase();
  const normPath = path || '';
  const normTimestamp = String(timestamp || '');
  const normNonce = nonce || '';
  
  let bodyString = '';
  if (body !== undefined && body !== null) {
    if (typeof body === 'string') {
      bodyString = body;
    } else {
      bodyString = JSON.stringify(body);
    }
  }

  return `${normMethod}:${normPath}:${normTimestamp}:${normNonce}:${bodyString}`;
}

/**
 * Generates an HMAC-SHA256 hex signature for a request payload.
 *
 * @param {Object} params
 * @param {string} params.method
 * @param {string} params.path
 * @param {string|number} params.timestamp
 * @param {string} params.nonce
 * @param {Object|string|null} [params.body]
 * @param {string} params.secret - Shared HMAC secret key
 * @returns {string} Hex signature
 */
export function generateSignature({ method, path, timestamp, nonce, body, secret }) {
  if (!secret) {
    throw new Error('HMAC secret is required to generate signature');
  }
  const canonicalString = buildCanonicalString({ method, path, timestamp, nonce, body });
  return crypto
    .createHmac('sha256', secret)
    .update(canonicalString)
    .digest('hex');
}

/**
 * Verifies an incoming HMAC signature using constant-time string comparison.
 *
 * @param {Object} params
 * @param {string} params.method
 * @param {string} params.path
 * @param {string|number} params.timestamp
 * @param {string} params.nonce
 * @param {Object|string|null} [params.body]
 * @param {string} params.signature - Signature provided in request header
 * @param {string} params.secret - Shared HMAC secret key
 * @returns {boolean} True if signature is valid and authentic
 */
export function verifySignature({ method, path, timestamp, nonce, body, signature, secret }) {
  if (!signature || typeof signature !== 'string' || !secret) {
    return false;
  }

  try {
    const expectedSignature = generateSignature({ method, path, timestamp, nonce, body, secret });
    const sigBuf = Buffer.from(signature, 'hex');
    const expectedBuf = Buffer.from(expectedSignature, 'hex');

    if (sigBuf.length !== expectedBuf.length) {
      return false;
    }

    return crypto.timingSafeEqual(sigBuf, expectedBuf);
  } catch (err) {
    return false;
  }
}

/**
 * Generates a cryptographically secure random hex nonce.
 * @returns {string} 32-character hex string (16 bytes)
 */
export function generateNonce() {
  return crypto.randomBytes(16).toString('hex');
}
