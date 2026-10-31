# Cybat Intelligence Engine Edge Collector (Cloudflare Worker)

[![License: Apache-2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Cloudflare Workers](https://img.shields.io/badge/Cloudflare-Workers-F38020?logo=cloudflare&logoColor=white)](https://workers.cloudflare.com/)

**Cybat Intelligence Engine Edge Collector** is an out-of-band reverse proxy sensor deployed at Cloudflare's network edge. It monitors API traffic for zero-day logic flaws, BOLA (Broken Object Level Authorization), and malformed payload injection **without adding any latency (0 ms)** to customer applications.

---

## 🏛️ Architecture & Latency Model

Traditional in-line security proxies introduce round-trip network hops that degrade user response times. The Cybat Intelligence Engine Edge Collector eliminates this penalty by decoupling origin delivery from telemetry transmission:

```
[End User Client]
       │
       │ (1) Incoming HTTP Request
       ▼
┌────────────────────────────────────────────────────────┐
│ Cloudflare Edge Worker (Cybat Intelligence Collector) │
│                                                        │
│  (2) request.clone()                                   │
│  (3) await fetch(request) ───[Origin Request]────┐     │
│  (4) Return Response <───────[Origin Response]───┤     │
│                                                  │     │
│  (5) ctx.waitUntil(dispatchToCybat(...))         │     │
│       └── Asynchronous Telemetry to GCP ───┐     │     │
└────────────────────────────────────────────┼─────┼─────┘
                                             │     │
                 ┌───────────────────────────┘     │
                 ▼                                 ▼
   [Cybat GCP Ingestion API]             [Customer Origin Server]
   (Pub/Sub -> AI Threat Engine)          (Fast & Unaffected)
```

### Why 0 ms Added Latency?
1. The incoming request is immediately cloned into memory before the request stream is locked.
2. The Worker forwards the primary request directly to the origin via `await fetch(request)`.
3. The origin response is streamed directly back to the client.
4. Using Cloudflare's `ctx.waitUntil()`, telemetry dispatch executes out-of-band in the background. The user connection completes immediately without waiting for the Cybat ingestion handshake.
5. Telemetry network calls are wrapped in fail-open error handling: an ingest timeout or outage will **never** interrupt or degrade client traffic.

---

## 🛡️ Telemetry & Security Extraction

* **Client IP:** Extracted from Cloudflare's verified `cf-connecting-ip` header.
* **JA4 Fingerprint:** Reads `request.cf?.ja4` (TLS client fingerprint) to detect credential stuffing, botnets, and impersonated user agents regardless of spoofed headers.
* **Edge PII & Secret Redaction (Zero-Knowledge Telemetry):**
  * Before any state-changing payload leaves the client's network edge, [`src/redact.js`](src/redact.js) scrubs sensitive data.
  * Masks passwords, API keys, JWT tokens, Bearer authorization credentials, credit cards (Luhn-validated), emails, and private keys.
  * Preserves attack shapes (`[REDACTED len=N sus=sqlkw,quote]`) so Cybat AI can accurately analyze threat intent without storing plain-text secrets.
* **Payload Isolation & Memory Guard:**
  * Only state-changing methods (`POST`, `PUT`, `PATCH`, `DELETE`) have their bodies inspected.
  * Requests with `content-length` exceeding `CYBAT_MAX_BODY_BYTES` (default: 64 KB) are automatically skipped to protect V8 isolate memory limits.
  * Extracted bodies up to 64 KB (65,536 bytes) are preserved for deep payload analysis (e.g., GraphQL mutations, nested objects, and bulk operations). Bodies exceeding this cap are cleanly truncated with `bodyTruncated: true`.

---

## 🚀 Deployment

### Option A: Cloudflare Workers Builds (Recommended / Automated CI/CD)

1. Fork or push this repository to your GitHub/GitLab account.
2. In the **Cloudflare Dashboard**, navigate to **Compute (Workers) → Workers & Pages → Create application**.
3. Select **Workers** → **Connect to Git**.
4. Choose the repository and specify:
   * **Project Name:** `cybat-edge-collector`
   * **Production Branch:** `main`
   * **Build Command:** `npm run deploy` (or leave empty)
5. Under **Settings → Variables and Secrets**, add the encrypted secret:
   * `CYBAT_API_KEY`: Paste your live API key from the **Cybat Dashboard** (`cybat_live_...`).
6. Set your route or custom domain (e.g. `api.yourdomain.com/*`).

---

### Option B: Deploy via Wrangler CLI

#### 1. Clone & Install
```bash
git clone https://github.com/CybatInc/cloudflare-collector.git
cd cloudflare-collector
npm install
```

#### 2. Set Your Cybat API Key Secret
Set your organization API key as an encrypted secret in Cloudflare:
```bash
npx wrangler secret put CYBAT_API_KEY
# Enter your Cybat API key when prompted
```

#### 3. Deploy
```bash
npm run deploy
```

---

## ⚙️ Environment Variables & Configuration

Configured in `wrangler.jsonc` or the Cloudflare Dashboard:

| Variable | Type | Default | Description |
| :--- | :--- | :--- | :--- |
| `CYBAT_API_KEY` | **Secret** | *Required* | API key generated from the Cybat Dashboard. Maps traffic to your organization. |
| `CYBAT_INGESTION_URL` | Var | `https://gcp-ingest.cybat.co` | Destination Cybat ingestion endpoint. |
| `CYBAT_PROJECT_ID` | Var | `cloudflare` | Project identifier reported to Cybat for dashboard & analytics grouping. |
| `CYBAT_MAX_BODY_BYTES` | Var | `65536` (64 KB) | Maximum request body extraction size in bytes. |
| `UPSTREAM_ORIGIN` | Var | *Optional* | Upstream target URL used for local emulation and testing (e.g., `https://httpbin.org`). |

---

## 🧪 Local Emulation & Testing

### 1. Run the Test Suite
The collector includes unit tests covering payload truncation, fail-open resilience, JA4 header mapping, and origin pass-through:
```bash
npm test
```

### 2. Local Worker Emulation (`wrangler dev`)
To test the collector locally with a simulated origin:

```bash
# Start local emulation with an upstream proxy target
npx wrangler dev --var UPSTREAM_ORIGIN:https://httpbin.org
```

### 3. Verify with `curl`

#### Clean Pass-Through (GET):
```bash
curl -i http://localhost:8787/get
```
*Expected: 200 OK from origin. No request body dispatched.*

#### State-Changing Telemetry (POST):
```bash
curl -i -X POST http://localhost:8787/post \
  -H "Content-Type: application/json" \
  -d '{"action": "update_balance", "account_id": "acc_8921", "amount": 500}'
```
*Expected: Origin response returns immediately. Telemetry event with body dispatched asynchronously.*

#### Large Payload Safeguard Test (>64KB):
```bash
python3 -c "print('A' * 70000)" > /tmp/large.txt
curl -i -X POST http://localhost:8787/post \
  -H "Content-Type: text/plain" \
  --data-binary "@/tmp/large.txt"
```
*Expected: Origin processes request; collector skips body extraction to protect isolate memory.*

---

## 📄 License
Apache-2.0. Copyright (c) Cybat Inc.
