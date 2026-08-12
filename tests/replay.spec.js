import { test, expect } from '@playwright/test';
import { generateSignature, generateNonce } from '../utils/hmac.js';

const SECRET = process.env.HMAC_SECRET || 'super_secret_key_12345';

test.describe('HMAC Anti-Replay Protection Test Suite', () => {

  test.beforeEach(async ({ request }) => {
    // Reset nonce store before each test for clean isolation
    await request.post('/test/reset-nonces');
  });

  test('1. Legitimate Request - Should succeed with HTTP 200 for valid HMAC and fresh nonce', async ({ request }) => {
    const path = '/api/action';
    const method = 'POST';
    const timestamp = Date.now().toString();
    const nonce = generateNonce();
    const body = { action: 'create_item', itemId: 42 };

    const signature = generateSignature({
      method,
      path,
      timestamp,
      nonce,
      body,
      secret: SECRET
    });

    const response = await request.post(path, {
      headers: {
        'x-signature': signature,
        'x-timestamp': timestamp,
        'x-nonce': nonce
      },
      data: body
    });

    expect(response.status()).toBe(200);
    const json = await response.json();
    expect(json.success).toBe(true);
    expect(json.message).toBe('Action executed successfully');
    expect(json.payload).toEqual(body);
  });

  test('2. Replay Attack - Replaying identical request with same nonce should be rejected (409 Conflict)', async ({ request }) => {
    const path = '/api/action';
    const method = 'POST';
    const timestamp = Date.now().toString();
    const nonce = generateNonce();
    const body = { action: 'withdraw', amount: 500 };

    const signature = generateSignature({
      method,
      path,
      timestamp,
      nonce,
      body,
      secret: SECRET
    });

    // First Request (Original Execution)
    const firstRes = await request.post(path, {
      headers: {
        'x-signature': signature,
        'x-timestamp': timestamp,
        'x-nonce': nonce
      },
      data: body
    });
    expect(firstRes.status()).toBe(200);

    // Second Request (Replay Attack Attempt)
    const replayRes = await request.post(path, {
      headers: {
        'x-signature': signature,
        'x-timestamp': timestamp,
        'x-nonce': nonce
      },
      data: body
    });

    expect(replayRes.status()).toBe(409);
    const json = await replayRes.json();
    expect(json.error).toContain('Replay attack detected');
    expect(json.nonce).toBe(nonce);
  });

  test('3. Expired Timestamp - Request with timestamp outside skew window should fail (401 Unauthorized)', async ({ request }) => {
    const path = '/api/action';
    const method = 'POST';
    // Timestamp from 10 minutes ago (beyond 5 minute allowed skew)
    const expiredTimestamp = (Date.now() - 600000).toString();
    const nonce = generateNonce();
    const body = { action: 'ping' };

    const signature = generateSignature({
      method,
      path,
      timestamp: expiredTimestamp,
      nonce,
      body,
      secret: SECRET
    });

    const response = await request.post(path, {
      headers: {
        'x-signature': signature,
        'x-timestamp': expiredTimestamp,
        'x-nonce': nonce
      },
      data: body
    });

    expect(response.status()).toBe(401);
    const json = await response.json();
    expect(json.error).toBe('Timestamp outside acceptable window');
  });

  test('4. Tampered Payload - Altering request body invalidates signature (401 Unauthorized)', async ({ request }) => {
    const path = '/api/action';
    const method = 'POST';
    const timestamp = Date.now().toString();
    const nonce = generateNonce();
    const originalBody = { recipient: 'Alice', amount: 10 };
    const tamperedBody = { recipient: 'Bob', amount: 1000000 };

    // Generate signature for original body
    const signature = generateSignature({
      method,
      path,
      timestamp,
      nonce,
      body: originalBody,
      secret: SECRET
    });

    // Send request with modified body
    const response = await request.post(path, {
      headers: {
        'x-signature': signature,
        'x-timestamp': timestamp,
        'x-nonce': nonce
      },
      data: tamperedBody
    });

    expect(response.status()).toBe(401);
    const json = await response.json();
    expect(json.error).toBe('Invalid HMAC signature');
  });

  test('5. Tampered Header - Modifying nonce header breaks HMAC verification (401 Unauthorized)', async ({ request }) => {
    const path = '/api/action';
    const method = 'POST';
    const timestamp = Date.now().toString();
    const originalNonce = generateNonce();
    const tamperedNonce = generateNonce();
    const body = { action: 'test' };

    const signature = generateSignature({
      method,
      path,
      timestamp,
      nonce: originalNonce,
      body,
      secret: SECRET
    });

    const response = await request.post(path, {
      headers: {
        'x-signature': signature,
        'x-timestamp': timestamp,
        'x-nonce': tamperedNonce // Sending different nonce than signed
      },
      data: body
    });

    expect(response.status()).toBe(401);
    const json = await response.json();
    expect(json.error).toBe('Invalid HMAC signature');
  });

  test('6. Missing Headers - Request without required security headers returns 400 Bad Request', async ({ request }) => {
    const response = await request.post('/api/action', {
      headers: {
        'x-timestamp': Date.now().toString()
        // x-signature and x-nonce omitted
      },
      data: { test: true }
    });

    expect(response.status()).toBe(400);
    const json = await response.json();
    expect(json.error).toBe('Missing required security headers');
  });

  test('7. Protected Transaction Route - Verifies high-value endpoint protection and replay defense', async ({ request }) => {
    const path = '/api/transaction';
    const method = 'POST';
    const timestamp = Date.now().toString();
    const nonce = generateNonce();
    const body = { amount: 250, recipient: 'Merchant_XYZ' };

    const signature = generateSignature({
      method,
      path,
      timestamp,
      nonce,
      body,
      secret: SECRET
    });

    const validRes = await request.post(path, {
      headers: {
        'x-signature': signature,
        'x-timestamp': timestamp,
        'x-nonce': nonce
      },
      data: body
    });

    expect(validRes.status()).toBe(200);
    const json = await validRes.json();
    expect(json.success).toBe(true);
    expect(json.transactionId).toMatch(/^tx_/);
    expect(json.details.amount).toBe(250);

    // Immediate replay attempt
    const replayRes = await request.post(path, {
      headers: {
        'x-signature': signature,
        'x-timestamp': timestamp,
        'x-nonce': nonce
      },
      data: body
    });
    expect(replayRes.status()).toBe(409);
  });

});
