# Cloudflare Technology Partner Program: Application Dossier

This document provides ready-to-use, pre-filled responses for submitting Cybat to the [Cloudflare Technology Partner Program](https://www.cloudflare.com/partners/technology-partners/) and requesting listing in the **Cloudflare Dashboard (Workers & Pages → Integrations)**.

---

## 1. Company & Contact Details

| Application Field | Pre-Filled Response |
| :--- | :--- |
| **Legal Company Name** | Cybat Inc. |
| **Website URL** | `https://cybat.co` |
| **Headquarters** | United States / Remote |
| **Primary Contact Name** | Engineering / Technology Alliance Lead |
| **Primary Contact Email** | `cto@cybat.co` |
| **Support Email** | `support@cybat.co` |
| **Target Partner Track** | Technology Alliance Partner (Developer Platform / Workers) |

---

## 2. Product & Listing Profile

| Application Field | Pre-Filled Response |
| :--- | :--- |
| **Product / Solution Name** | Cybat Intelligence Engine Edge Collector |
| **Integration Title** | Cybat Intelligence Engine |
| **Categories** | `Security`, `Monitoring & Logging`, `Developer Tools` |
| **Tagline (Max 100 chars)** | Real-time AI threat intelligence & behavioral API security with 0 ms origin latency. |
| **Short Description** | Protect your APIs and applications with autonomous AI threat detection. The Cybat Edge Collector intercepts traffic at Cloudflare's edge, extracts behavioral signals and JA4 fingerprints, scrubs sensitive credentials in memory, and asynchronously dispatches telemetry out-of-band. |
| **Open Source Repository** | `https://github.com/CybatInc/cloudflare-collector` |
| **Integration Manifest** | [`integration.json`](../integration.json) |
| **Marketplace Icon** | [`docs/assets/cybat-icon.svg`](assets/cybat-icon.svg) |

---

## 3. Technical Integration Specification

### Target Runtime
- **Environment:** Cloudflare Workers (`workerd` V8 isolates).
- **Execution Model:** Reverse proxy with out-of-band telemetry via `ctx.waitUntil()`.
- **Runtime Dependencies:** Zero external npm packages; runs entirely on native Web Standards (`fetch`, `Request`, `Response`, `AbortController`).
- **Compatibility Date:** `2024-10-30` (`nodejs_compat`).

### Required Configuration & Environment Bindings
1. **`CYBAT_API_KEY`** (Type: `Secret`, Required: `true`):
   - Secure customer authentication token generated in the Cybat Dashboard (`https://app.cybat.co`).
   - Stored as an encrypted Cloudflare secret binding.
2. **`PROJECT_ID`** (Type: `Text Variable`, Required: `false`, Default: `"cloudflare"`):
   - Customer project or zone label for grouping analytics within Cybat.
3. **`CYBAT_INGESTION_URL`** (Type: `Text Variable`, Required: `false`, Default: `"https://gcp-ingest.cybat.co"`):
   - Ingestion gateway URL.
4. **`CYBAT_MAX_BODY_BYTES`** (Type: `Text Variable`, Required: `false`, Default: `"65536"`):
   - Maximum body extraction ceiling (64 KB) to protect isolate memory limits.

---

## 4. Value Proposition for Cloudflare Customers

### Why Cloudflare + Cybat?
1. **Zero Origin Latency Overhead (0 ms):**
   Unlike traditional inline security proxies that add round-trip network hops, Cybat uses Cloudflare's `ctx.waitUntil()` to deliver the client response from origin immediately, while streaming telemetry to Cybat in the background.
2. **Complementary Layer 7 Security:**
   Cloudflare WAF defends the perimeter against known CVEs and volumetric DDoS. Cybat analyzes application logic flaws, BOLA (Broken Object Level Authorization), and multi-step zero-day exploitation attempts at the behavioral layer.
3. **In-Memory Edge Sanitization:**
   Authentication headers, Bearer tokens, passwords, cookies, and sensitive PII are redacted inside the Cloudflare isolate before any data leaves the edge.
4. **Fail-Open Operational Resilience:**
   Any transient network error or timeout contacting Cybat's ingest cluster is caught silently. Customer origin traffic is never disrupted.

---

## 5. Security & Compliance Review Answers

| Review Question | Official Cybat Statement |
| :--- | :--- |
| **Does the integration store customer credentials?** | No. Only the customer's Cybat API key is stored as an encrypted secret binding in Cloudflare. |
| **Does the integration inspect or transmit plain-text credentials?** | No. In-memory redaction removes `authorization`, `cookie`, `proxy-authorization`, and regex-matched credential fields before telemetry payload creation. |
| **What happens if the partner endpoint is offline?** | Fail-open. The worker catches any network exceptions and ensures origin response delivery is 100% unaffected. |
| **Are background subrequests bounded?** | Yes. An `AbortController` enforces a strict 10-second timeout on all asynchronous calls. |
| **Payload ceiling protection?** | Requests with bodies exceeding 64 KB (or `Content-Length > 65536`) have body inspection truncated or skipped to prevent memory exhaustion. |

---

## 6. Verification & Validation Evidence

- **Unit Test Coverage:** 14 automated tests passing (`npm test`), covering redaction, ceiling limits, fallback variables, and fail-open handling.
- **Wrangler Dry-Run:** Verified clean upload profile (33.94 KiB uncompressed / 9.74 KiB gzip).
- **Deployment Models Supported:**
  - 1-Click "Deploy to Cloudflare" Worker template button.
  - Native Cloudflare Dashboard Integration modal (Workers & Pages → Integrations).
  - Manual deployment via Wrangler CLI and Terraform.
