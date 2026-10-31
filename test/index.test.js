import { test, describe, beforeEach, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import worker, { extractBodySafely, dispatchToCybat } from '../src/index.js';
import { maskBody, maskString } from '../src/redact.js';

describe('Cybat Intelligence Engine Edge Collector Tests', () => {
  const originalFetch = globalThis.fetch;

  afterEach(() => {
    globalThis.fetch = originalFetch;
  });

  describe('PII & Secret Redaction (src/redact.js)', () => {
    test('masks passwords and bearer tokens in text', () => {
      const text = 'Authorization: Bearer mysecrettoken123456789 and password=SuperSecretPassword!';
      const masked = maskString(text);
      assert.equal(masked.includes('SuperSecretPassword!'), false);
      assert.equal(masked.includes('mysecrettoken123456789'), false);
      assert.equal(masked.includes('[REDACTED'), true);
    });

    test('masks sensitive fields inside JSON objects', () => {
      const json = JSON.stringify({
        username: 'alice',
        password: 'PlainTextPassword99',
        apiKey: 'sk_live_1234567890abcdef',
        email: 'john.doe@example.com',
        account_id: 'acc_1001'
      });

      const masked = maskBody(json);
      const parsed = JSON.parse(masked);

      assert.equal(parsed.username, 'alice');
      assert.equal(parsed.account_id, 'acc_1001');
      assert.equal(parsed.password.startsWith('[REDACTED'), true);
      assert.equal(parsed.apiKey.startsWith('[REDACTED'), true);
      assert.equal(parsed.email, 'j***e@example.com');
    });
  });

  describe('extractBodySafely()', () => {
    test('ignores non-state-changing methods (GET)', async () => {
      const req = new Request('https://api.example.com/items', { method: 'GET' });
      const result = await extractBodySafely(req);
      assert.deepEqual(result, {});
    });

    test('ignores non-state-changing methods (HEAD)', async () => {
      const req = new Request('https://api.example.com/items', { method: 'HEAD' });
      const result = await extractBodySafely(req);
      assert.deepEqual(result, {});
    });

    test('extracts and redacts state-changing POST body', async () => {
      const payload = JSON.stringify({ action: 'transfer', amount: 100, password: 'mypassword1' });
      const req = new Request('https://api.example.com/transfer', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: payload
      });

      const result = await extractBodySafely(req);
      assert.equal(result.bodyTruncated, false);
      const parsed = JSON.parse(result.body);
      assert.equal(parsed.action, 'transfer');
      assert.equal(parsed.amount, 100);
      assert.equal(parsed.password.startsWith('[REDACTED'), true);
    });

    test('skips extraction if content-length header exceeds ceiling', async () => {
      const req = new Request('https://api.example.com/upload', {
        method: 'POST',
        headers: { 'content-length': '70000' },
        body: 'dummy'
      });

      const result = await extractBodySafely(req, 65536);
      assert.equal(result.body, '[skipped: payload exceeds 64KB]');
      assert.equal(result.bodyTruncated, true);
    });

    test('extracts payloads up to 64KB successfully', async () => {
      const payload32k = JSON.stringify({ data: 'x'.repeat(30000) });
      const req = new Request('https://api.example.com/graphql', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: payload32k
      });

      const result = await extractBodySafely(req, 65536);
      assert.equal(result.bodyTruncated, false);
      assert.equal(result.body.length > 30000, true);
    });

    test('truncates bodies exceeding 64KB', async () => {
      const largePayload = 'a'.repeat(70000);
      const req = new Request('https://api.example.com/large', {
        method: 'PUT',
        headers: { 'Content-Type': 'text/plain' },
        body: largePayload
      });

      const result = await extractBodySafely(req, 65536);
      assert.equal(result.bodyTruncated, true);
      assert.equal(result.body.includes('[truncated'), true);
    });
  });

  describe('dispatchToCybat()', () => {
    test('does nothing when CYBAT_API_KEY is missing', async () => {
      let fetchCalled = false;
      globalThis.fetch = async () => {
        fetchCalled = true;
        return new Response('OK');
      };

      const req = new Request('https://api.example.com/data', { method: 'POST', body: 'hello' });
      await dispatchToCybat(req, {}, 200, 15);

      assert.equal(fetchCalled, false);
    });

    test('formats and transmits telemetry with security headers and redacted body', async () => {
      let interceptedUrl = null;
      let interceptedOptions = null;

      globalThis.fetch = async (url, options) => {
        interceptedUrl = url;
        interceptedOptions = options;
        return new Response(JSON.stringify({ status: 'accepted' }), { status: 202 });
      };

      const bodyContent = JSON.stringify({
        role: 'admin',
        secret_token: 'secret_value_123',
        target_id: '42'
      });

      const req = new Request('https://api.example.com/users/42', {
        method: 'PATCH',
        headers: {
          'cf-connecting-ip': '198.51.100.25',
          'user-agent': 'Mozilla/5.0 TestBrowser',
          'referer': 'https://example.com/admin',
          'Content-Type': 'application/json'
        },
        body: bodyContent
      });

      req.cf = {
        ja4: 't13d1516h2_8daaf6152771_b186095e22b6',
        asn: 13335,
        country: 'US'
      };

      const env = {
        CYBAT_API_KEY: 'cybat_live_testkey_12345',
        CYBAT_INGESTION_URL: 'https://custom-ingest.cybat.co/v1/telemetry',
        CYBAT_MAX_BODY_BYTES: '65536'
      };

      await dispatchToCybat(req, env, 200, 32);

      assert.equal(interceptedUrl, 'https://custom-ingest.cybat.co/v1/telemetry');
      assert.equal(interceptedOptions.method, 'POST');
      assert.equal(interceptedOptions.headers['x-api-key'], 'cybat_live_testkey_12345');
      assert.equal(interceptedOptions.headers['X-Cybat-Key'], 'cybat_live_testkey_12345');
      assert.equal(interceptedOptions.headers['X-Client-IP'], '198.51.100.25');
      assert.equal(interceptedOptions.headers['X-Client-JA4'], 't13d1516h2_8daaf6152771_b186095e22b6');

      const payload = JSON.parse(interceptedOptions.body);
      assert.equal(Array.isArray(payload), true);
      assert.equal(payload.length, 1);
      assert.equal(payload[0].method, 'PATCH');
      assert.equal(payload[0].url, 'https://api.example.com/users/42');
      assert.equal(payload[0].status, 200);
      assert.equal(payload[0].remoteIp, '198.51.100.25');
      assert.equal(payload[0].ja4, 't13d1516h2_8daaf6152771_b186095e22b6');
      assert.equal(payload[0].asn, '13335');
      assert.equal(payload[0].country, 'US');
      assert.equal(payload[0].latencyMs, 32);

      // Verify that secret_token was redacted before sending
      const parsedBody = JSON.parse(payload[0].body);
      assert.equal(parsedBody.role, 'admin');
      assert.equal(parsedBody.target_id, '42');
      assert.equal(parsedBody.secret_token.startsWith('[REDACTED'), true);
      assert.equal(payload[0].bodyTruncated, false);
    });

    test('fails silently (fail-open) if ingest network request throws', async () => {
      globalThis.fetch = async () => {
        throw new Error('Connection refused by telemetry ingest');
      };

      const req = new Request('https://api.example.com/test', { method: 'POST', body: 'sample' });
      const env = { CYBAT_API_KEY: 'test_key' };

      await assert.doesNotReject(async () => {
        await dispatchToCybat(req, env, 500, 10);
      });
    });
  });

  describe('Worker fetch handler', () => {
    test('passes request cleanly to origin and invokes ctx.waitUntil', async () => {
      let waitUntilPromise = null;
      let originFetched = false;

      globalThis.fetch = async (req) => {
        originFetched = true;
        return new Response('{"success":true}', {
          status: 200,
          headers: { 'Content-Type': 'application/json' }
        });
      };

      const ctx = {
        waitUntil: (promise) => {
          waitUntilPromise = promise;
        }
      };

      const env = {
        CYBAT_API_KEY: 'cybat_key_abc',
        CYBAT_INGESTION_URL: 'https://gcp-ingest.cybat.co'
      };

      const incomingReq = new Request('https://origin.customer.com/api/v1/resource', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ item: 'gadget' })
      });

      const response = await worker.fetch(incomingReq, env, ctx);

      assert.equal(originFetched, true);
      assert.equal(response.status, 200);
      assert.notEqual(waitUntilPromise, null);

      await waitUntilPromise;
    });
  });
});
