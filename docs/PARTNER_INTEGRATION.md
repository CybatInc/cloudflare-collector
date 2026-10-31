# Cloudflare Technology Partner Integration: Cybat Intelligence Engine

This document contains the complete technical specification, marketplace listing metadata, security assurances, and application workflow for submitting the **Cybat Intelligence Engine Edge Collector** to the **Cloudflare Developer Platform Partner Program** and listing it in the official **Cloudflare Dashboard (Workers & Pages → Integrations)**.

---

## 1. Executive Summary & Partnership Value Proposition

| Item | Details |
| :--- | :--- |
| **Partner Name** | Cybat Inc. |
| **Product Name** | Cybat Intelligence Engine Edge Collector |
| **Category** | Security, Observability, AI / Machine Learning |
| **Target Runtime** | Cloudflare Workers (`workerd` edge isolate) |
| **Repository** | [https://github.com/CybatInc/cloudflare-collector](https://github.com/CybatInc/cloudflare-collector) |
| **Target Audience** | Enterprise & mid-market Cloudflare customers seeking zero-day API threat protection, AI bot mitigation, and out-of-band behavioral telemetry without latency penalties. |

### Why Cloudflare + Cybat?
Cloudflare's WAF and DDoS protection stop known volumetric and signature-based attacks at the network perimeter. **Cybat** operates at the application and AI layer, analyzing behavioral patterns, JA4 client fingerprints, and state-changing payloads out-of-band to identify advanced persistent threats, API abuse, and zero-day exploitation attempts.

By integrating directly into the Cloudflare Workers ecosystem:
- **0 ms Added Latency:** Telemetry extraction and transmission run out-of-band via `ctx.waitUntil()`. The customer's origin response is never blocked or delayed.
- **Edge-Native PII/Secret Scrubbing:** Sensitive data (passwords, Bearer tokens, API keys, credit cards) is redacted directly in the edge isolate before leaving Cloudflare.
- **Fail-Open Resilience:** Unresponsive ingest endpoints or transient network failures do not impact end-user traffic.

---

## 2. Cloudflare Integrations Marketplace Listing Metadata

When registered in Cloudflare's partner portal, the integration will appear in the Cloudflare Dashboard under **Workers & Pages → Integrations**:

### A. Listing Profile
* **Integration Title:** Cybat Intelligence Engine
* **Tagline:** Real-time AI threat intelligence, JA4 fingerprinting, and behavioral API security with 0 ms origin latency.
* **Short Description:**
  > Protect your APIs and applications with autonomous AI threat detection. The Cybat Edge Collector intercepts HTTP/HTTPS traffic at Cloudflare's edge, extracts behavioral signals and JA4 fingerprints, scrubs sensitive credentials in memory, and asynchronously dispatches telemetry to your Cybat tenant.
* **Categories:** `Security`, `Monitoring & Logging`, `Developer Tools`
* **Website:** [https://cybat.co](https://cybat.co)
* **Documentation URL:** [https://github.com/CybatInc/cloudflare-collector](https://github.com/CybatInc/cloudflare-collector)
* **Support Email:** `support@cybat.co` / `cto@cybat.co`

### B. Configuration & Bindings Specification
The integration provisions a lightweight worker that requires the following environment bindings:

| Binding Name | Type | Required | Default | Purpose |
| :--- | :--- | :--- | :--- | :--- |
| `CYBAT_API_KEY` | **Secret** (Encrypted) | **Yes** | — | Unique organization API key obtained from Cybat Dashboard (`https://app.cybat.co`). |
| `PROJECT_ID` | Variable (Text) | No | `cloudflare` | Identifier for multi-project or multi-zone grouping inside Cybat analytics. |
| `CYBAT_INGESTION_URL` | Variable (Text) | No | `https://gcp-ingest.cybat.co` | Regional telemetry ingestion endpoint. |
| `CYBAT_MAX_BODY_BYTES` | Variable (Text) | No | `65536` | Maximum payload extraction ceiling in bytes (default 64 KB). |

---

## 3. Customer Onboarding & Setup Flows

Cloudflare Partner Integrations support two standard installation models:

### Model A: Direct API Key Handshake (Recommended for Fast Launch)
1. **Discovery:** Customer navigates to **Cloudflare Dashboard → Workers & Pages → Integrations → Cybat**.
2. **Configuration Modal:** Cloudflare displays a streamlined modal asking for:
   - **`CYBAT_API_KEY`** (Secret field with link: *"Get your API Key in Cybat Dashboard"*).
   - **`PROJECT_ID`** (Optional custom project label, defaults to `"cloudflare"`).
   - **Route / Domain Selection:** Customer selects the zone and route pattern (e.g., `api.example.com/*`).
3. **Provisioning:** Cloudflare's integration orchestrator automatically:
   - Deploys the collector worker isolate.
   - Encrypts and binds `CYBAT_API_KEY`.
   - Attaches the selected route pattern to the customer's domain.

### Model B: OAuth 2.0 Auto-Provisioning Flow (Enterprise Option)
1. In the Cloudflare modal, the customer clicks **"Connect with Cybat"**.
2. Customer is redirected to `https://app.cybat.co/oauth/authorize?client_id=cloudflare&redirect_uri=https://dash.cloudflare.com/integrations/callback`.
3. Customer signs in, selects their Cybat Workspace / Project, and clicks **Authorize**.
4. Cybat's OAuth server securely exchanges an organization ingestion token back to Cloudflare's integration service.
5. Cloudflare automatically sets the encrypted secret and attaches the worker route.

---

## 4. Technical Architecture & Security Assurances

```
┌────────────────────────────────────────────────────────────────────────┐
│                        Cloudflare Global Edge                          │
│                                                                        │
│   [ Client HTTP Request ]                                              │
│             │                                                          │
│             ▼                                                          │
│     [ Cybat Collector Worker ]                                         │
│      ├── 1. Clone request metadata & body                              │
│      ├── 2. Extract JA4 & CF Edge Ray/Geo Headers                      │
│      ├── 3. In-memory PII / Secret scrubbing                           │
│      │                                                                 │
│      ├──> Forward cleanly to [ Customer Zone Origin ] ── (Synchronous) │
│      │    (0 ms added overhead, unmodified response returned)          │
│      │                                                                 │
│      └──> ctx.waitUntil(dispatchToCybat())             ── (Async)      │
│             │                                                          │
└─────────────┼──────────────────────────────────────────────────────────┘
              ▼
    [ https://gcp-ingest.cybat.co ]
    (Cybat Intelligence Engine Ingestion Cluster)
```

### Security & Privacy Guarantees for Cloudflare Compliance Review
1. **In-Memory Sanitization Before Transit:**
   The collector strips Authorization headers, Bearer tokens, session cookies, passwords, and API keys inside the `workerd` isolate before constructing the telemetry event.
2. **Zero Ingestion Dependency on Origin Path:**
   If the Cybat ingestion endpoint is unreachable or times out, the client's request to the customer origin is completely unaffected (strict `try...catch` wrapper with `fail-open` semantics).
3. **Strict AbortController Timeout:**
   All background subrequests to Cybat are capped at a 10-second timeout to prevent lingering isolate resources.
4. **No External Runtime Dependencies:**
   Built purely with standard web APIs (`fetch`, `Request`, `Response`, `AbortController`). Zero npm runtime dependencies.

---

## 5. Step-by-Step Cloudflare Partner Program Submission Guide

### Step 1: Submit Technology Partner Application
1. Navigate to the [Cloudflare Technology Partner Program Application](https://www.cloudflare.com/partners/technology-partners/).
2. Submit the organization profile:
   - **Company:** Cybat Inc.
   - **Contact:** CTO / Engineering Leadership (`cto@cybat.co`).
   - **Product Overview:** Cybat Intelligence Engine (Cloudflare Workers Edge Collector).
   - **Target Integration:** Workers & Pages Integration Marketplace.

### Step 2: Access Partner Portal & Sandbox
Once approved, Cloudflare provides:
- Access to the **Cloudflare Partner Portal**.
- A partner development sandbox with enterprise worker features and testing accounts.
- Introduction to a Cloudflare Partner Engineering Manager.

### Step 3: Technical Validation & Code Review
Provide Cloudflare's partner engineers with:
- GitHub Repository: `https://github.com/CybatInc/cloudflare-collector`
- Verified unit test suite (`npm test` — 14/14 passing).
- Live verification proof on Cloudflare Workers edge (e.g., HTTP 202 Ingest confirmation).

### Step 4: Marketplace Publishing & Joint GTM
- Cloudflare stages the integration in internal preview.
- Cybat verifies the end-to-end installation flow in the dashboard.
- Cloudflare publishes Cybat to the public Integrations Marketplace.
- Joint co-marketing announcement (blog post, community spotlight).
