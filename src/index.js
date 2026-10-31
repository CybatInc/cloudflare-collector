/**
 * Cybat Intelligence Engine Edge Collector - Cloudflare Worker
 * 
 * Out-of-band reverse proxy telemetry collector deployed at the network edge.
 * Intercepts incoming requests, passes them immediately to the origin (0 ms added latency),
 * scrubs secrets & PII at the edge, and asynchronously streams security metadata & state-changing bodies to Cybat's GCP ingestion endpoint.
 */

import { maskBody, snippetAround } from './redact.js';

const STATE_CHANGING_METHODS = new Set(['POST', 'PUT', 'PATCH', 'DELETE']);
const DEFAULT_MAX_BODY_BYTES = 64 * 1024; // 64 KB default limit for deep payload inspection

/**
 * Safely extracts and redacts request body with size guards to prevent isolate memory exhaustion.
 * @param {Request} request 
 * @param {number} maxBodyBytes
 * @returns {Promise<{ body?: string, bodyTruncated?: boolean }>}
 */
export async function extractBodySafely(request, maxBodyBytes = DEFAULT_MAX_BODY_BYTES) {
  if (!STATE_CHANGING_METHODS.has(request.method)) {
    return {};
  }

  const contentLengthHeader = request.headers.get('content-length');
  const contentLength = contentLengthHeader ? parseInt(contentLengthHeader, 10) : null;

  // Protect V8 isolate: skip body if explicitly larger than configured ceiling
  if (contentLength !== null && !isNaN(contentLength) && contentLength > maxBodyBytes) {
    return {
      body: `[skipped: payload exceeds ${Math.round(maxBodyBytes / 1024)}KB]`,
      bodyTruncated: true
    };
  }

  try {
    const rawText = await request.text();
    if (!rawText) {
      return {};
    }

    // Layer 1: Redact secrets, auth tokens, passwords, and PII before payload leaves edge
    const masked = maskBody(rawText);
    const maskedText = typeof masked === 'string' ? masked : JSON.stringify(masked);

    // Layer 2: Attack-centered excerpt truncation matching Cybat's SDK specification
    const excerpt = snippetAround(maskedText, maxBodyBytes);

    return {
      body: excerpt,
      bodyTruncated: excerpt !== maskedText
    };
  } catch {
    return {
      body: '[unreadable]',
      bodyTruncated: true
    };
  }
}

/**
 * Dispatches captured request telemetry to Cybat's Ingestion API out-of-band.
 * Suppresses all errors to guarantee fail-open behavior.
 * 
 * @param {Request} telemetryRequest Cloned request
 * @param {Record<string, any>} env Worker environment variables & secrets
 * @param {number} status Origin response HTTP status code
 * @param {number} latencyMs Origin round-trip latency in milliseconds
 */
export async function dispatchToCybat(telemetryRequest, env, status = 0, latencyMs = 0) {
  try {
    const apiKey = env.CYBAT_API_KEY || (typeof process !== 'undefined' && process.env?.CYBAT_API_KEY);
    if (!apiKey) {
      console.warn(`[Cybat] CYBAT_API_KEY secret is not configured. Telemetry dispatch skipped. (Available env keys: ${Object.keys(env).join(', ') || 'none'})`);
      return;
    }

    const clientIp = telemetryRequest.headers.get('cf-connecting-ip') ||
                     telemetryRequest.headers.get('x-forwarded-for') || '';
    const userAgent = telemetryRequest.headers.get('user-agent') || '';
    const referer = telemetryRequest.headers.get('referer') || '';
    const ja4 = telemetryRequest.cf?.ja4 || '';
    const asn = telemetryRequest.cf?.asn ? String(telemetryRequest.cf.asn) : '';
    const country = telemetryRequest.cf?.country || '';

    const configuredMaxBytes = env.CYBAT_MAX_BODY_BYTES
      ? parseInt(env.CYBAT_MAX_BODY_BYTES, 10)
      : DEFAULT_MAX_BODY_BYTES;
    const maxBodyBytes = !isNaN(configuredMaxBytes) && configuredMaxBytes > 0
      ? configuredMaxBytes
      : DEFAULT_MAX_BODY_BYTES;

    const { body, bodyTruncated } = await extractBodySafely(telemetryRequest, maxBodyBytes);

    const projectId = env.CYBAT_PROJECT_ID || 'cloudflare';

    const event = {
      method: telemetryRequest.method,
      url: telemetryRequest.url,
      status,
      remoteIp: clientIp,
      userAgent,
      referer,
      latencyMs,
      timestamp: new Date().toISOString(),
      ja4,
      asn,
      country,
      projectId,
      ...(body !== undefined ? { body, bodyTruncated } : {})
    };

    const ingestionUrl = env.CYBAT_INGESTION_URL || 'https://gcp-ingest.cybat.co';

    const ingestResponse = await fetch(ingestionUrl, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'x-api-key': apiKey,
        'X-Cybat-Key': apiKey,
        'X-Client-IP': clientIp,
        'X-Client-JA4': ja4
      },
      body: JSON.stringify([event]),
      signal: AbortSignal.timeout(10000)
    });

    if (ingestResponse.ok) {
      console.log(`[Cybat] Telemetry dispatched successfully (HTTP ${ingestResponse.status}) to ${ingestionUrl} [${event.method} ${event.url}]`);
    } else {
      const errText = await ingestResponse.text().catch(() => '');
      console.warn(`[Cybat] Ingest endpoint returned HTTP ${ingestResponse.status}: ${errText}`);
    }
  } catch (err) {
    // Fail-open: log for observability, but suppress so origin traffic is never disrupted
    console.warn(`[Cybat] Background telemetry dispatch encountered an issue: ${err.message}`);
  }
}

export default {
  /**
   * Main Worker fetch handler
   * @param {Request} request 
   * @param {Record<string, any>} env 
   * @param {{ waitUntil: (promise: Promise<any>) => void }} ctx 
   * @returns {Promise<Response>}
   */
  async fetch(request, env, ctx) {
    // 1. Immediately clone the incoming request before stream locking occurs
    const telemetryClone = request.clone();

    // 2. Measure origin round-trip timing
    const startTime = performance.now();
    let originResponse;

    try {
      // Support local emulation upstream or route directly to zone origin
      if (env.UPSTREAM_ORIGIN) {
        const targetUrl = new URL(request.url);
        const upstreamUrl = new URL(env.UPSTREAM_ORIGIN);
        targetUrl.protocol = upstreamUrl.protocol;
        targetUrl.host = upstreamUrl.host;
        targetUrl.port = upstreamUrl.port;
        originResponse = await fetch(new Request(targetUrl.toString(), request));
      } else {
        originResponse = await fetch(request);
      }
    } catch (err) {
      // If the origin itself is unreachable, return error response
      originResponse = new Response('Bad Gateway', { status: 502 });
    }

    const latencyMs = Math.round(performance.now() - startTime);

    // 3. Dispatch telemetry out-of-band using waitUntil (0 ms added user latency)
    ctx.waitUntil(
      dispatchToCybat(telemetryClone, env, originResponse.status, latencyMs)
    );

    // 4. Return origin response immediately to client
    return originResponse;
  }
};
