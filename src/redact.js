// Layer 1 of the data-protection stack: fast, local, dependency-free redaction.
//
// NOTE: intentionally identical in soc-ai-agent/services/redact.ts,
// intelligence-api/services/redact.ts, SDK/node/src/redact.ts and
// cloudflare-collector/src/redact.js — keep them in sync.
//
// The collector runs this on the client's side BEFORE anything leaves their
// edge infrastructure; the server runs it again before persisting, before
// prompting the model, and before alerts.
// It is therefore idempotent: masking already-masked text leaves it unchanged.

const REDACTED = '[REDACTED';

// ── Attack-shape descriptor (content-free) ───────────────────────────────────

const SUSPICIOUS = [
  ['quote', /['"`]|%27|%22/i],
  ['comment', /--|\/\*|#\s*$/],
  ['sqlkw', /\b(union|select|insert|update|delete|drop|sleep|benchmark|waitfor)\b/i],
  ['angle', /[<>]|%3c|%3e/i],
  ['semicolon', /;/],
  ['traversal', /\.\.[\/\\]|%2e%2e/i],
  ['cmdchar', /[|&$`]|\$\(/],
  ['template', /\{\{|\$\{|<%/],
  ['nullbyte', /%00|\x00/],
];

/** `[REDACTED len=N sus=a,b]` — no characters of the original survive. */
export function redactedShape(value) {
  const s = String(value ?? '');
  const sus = SUSPICIOUS.filter(([, re]) => re.test(s)).map(([n]) => n);
  return `${REDACTED} len=${s.length}${sus.length ? ` sus=${sus.join(',')}` : ''}]`;
}

// ── Credit cards (Luhn) ──────────────────────────────────────────────────────

export function luhnValid(digits) {
  if (!/^\d{13,19}$/.test(digits)) return false;
  let sum = 0;
  let alt = false;
  for (let i = digits.length - 1; i >= 0; i--) {
    let n = digits.charCodeAt(i) - 48;
    if (alt) {
      n *= 2;
      if (n > 9) n -= 9;
    }
    sum += n;
    alt = !alt;
  }
  return sum % 10 === 0;
}

const maskCard = (digits) => `XXXX-XXXX-XXXX-${digits.slice(-4)}`;

// ── Emails ───────────────────────────────────────────────────────────────────

export function maskEmail(local, domain) {
  const first = local[0] ?? '';
  const last = local.length > 2 ? local[local.length - 1] : '';
  return `${first}***${last}@${domain}`;
}

const EMAIL_RE = /([A-Za-z0-9._%+*-]{1,64})(?:@|%40)([A-Za-z0-9-]{1,63}(?:\.[A-Za-z0-9-]{1,63})*\.[A-Za-z]{2,24})/g;
const CARD_RE = /\b\d(?:[ -]?\d){12,18}\b/g;
const JWT_RE = new RegExp('\\beyJ' + '[A-Za-z0-9_-]{5,}\\.[A-Za-z0-9_-]{5,}\\.[A-Za-z0-9_-]*', 'g');
const BEARER_RE = new RegExp('\\b(Bearer|Basic)\\s+(?!' + '\\[' + 'REDACTED)[A-Za-z0-9._~+\\/=-]{8,}', 'gi');
const PRIVKEY_RE = new RegExp('-----BEGIN ' + '[A-Z ]*PRIVATE KEY-----' + '[\\s\\S]*?(?:-----END ' + '[A-Z ]*PRIVATE KEY-----|$)', 'g');
const KEY_TOKEN_RES = [
  new RegExp('\\bA' + 'KIA[0-9A-Z]{16}\\b', 'g'),                     // AWS access key id
  new RegExp('\\bA' + 'Iza[0-9A-Za-z_-]{35}\\b', 'g'),                // Google API key
  new RegExp('\\bgh' + '[pousr]_[A-Za-z0-9]{36,}\\b', 'g'),           // GitHub tokens
  new RegExp('\\bxox' + '[abprs]-[A-Za-z0-9-]{10,}\\b', 'g'),         // Slack tokens
  new RegExp('\\b[sr]k_' + '(?:live|test)_[A-Za-z0-9]{16,}\\b', 'g'), // Stripe keys
];

const PARAM_SECRET_RE = new RegExp(
  '((?:^|[?&;,\\s"\'])' +
  '(?:access[_-]?token|refresh[_-]?token|id[_-]?token|token|api[_-]?key|apikey|client[_-]?secret|secret|password|passwd|passphrase|pwd|auth|authorization|session(?:[_-]?id)?|sid|signature|sig|key|credential|cc[_-]?num(?:ber)?|card[_-]?(?:number|no|num)?|cvv|cvc|ssn|iban)=' +
  ')((?:(?!;\\s)[^&#\\r\\n])+)',
  'gi'
);

const MAX_INPUT_CHARS = 65536;

const JSON_PAIR_RE = /"([^"\\]{1,64})"(\s*:\s*)(?:"((?:[^"\\]|\\.){0,4000})"|(-?\d{1,25}))/g;

/** Redacts secrets and personal data inside free text. Idempotent. */
export function maskString(input, extraKeys) {
  if (!input) return input;
  let s = input.length > MAX_INPUT_CHARS ? `${input.slice(0, MAX_INPUT_CHARS)}…[truncated]` : input;

  s = s.replace(PRIVKEY_RE, `${REDACTED} private-key]`);
  s = s.replace(JWT_RE, `${REDACTED} jwt]`);
  s = s.replace(BEARER_RE, (_m, scheme) => `${scheme} ${REDACTED}]`);
  for (const re of KEY_TOKEN_RES) s = s.replace(re, `${REDACTED} key]`);

  s = s.replace(PARAM_SECRET_RE, (m, prefix, value) =>
    value.startsWith(REDACTED) ? m : `${prefix}${redactedShape(safeDecode(value))}`);

  s = s.replace(JSON_PAIR_RE, (m, key, colon, str, num) => {
    if (!isSensitiveKey(key, extraKeys)) return m;
    const raw = str ?? num ?? '';
    if (raw.startsWith(REDACTED) || raw.startsWith('XXXX-XXXX-XXXX-')) return m;
    const digits = String(raw).replace(/\D/g, '');
    const masked = CARD_KEY_RE.test(key) && digits.length >= 12 ? maskCard(digits) : redactedShape(raw);
    return `"${key}"${colon}"${masked}"`;
  });

  s = s.replace(CARD_RE, (m) => {
    const digits = m.replace(/[ -]/g, '');
    return luhnValid(digits) ? maskCard(digits) : m;
  });

  s = s.replace(EMAIL_RE, (m, local, domain) =>
    local.includes('***') ? m : maskEmail(local, domain));

  return s;
}

function safeDecode(v) {
  try {
    return decodeURIComponent(v.replace(/\+/g, ' '));
  } catch {
    return v;
  }
}

// ── Structured values (parsed JSON / form bodies) ────────────────────────────

const SENSITIVE_KEY_RE =
  /(pass|pwd|secret|token|auth|cookie|session|credential|private|api[_-]?key|apikey|card|cvv|cvc|ssn|iban|\bpin\b)/i;
const CARD_KEY_RE = /(card|cc[_-]?num|ccnum|pan)/i;

function isSensitiveKey(key, extraKeys) {
  if (SENSITIVE_KEY_RE.test(key)) return true;
  return extraKeys ? extraKeys.has(key.toLowerCase()) : false;
}

const MAX_DEPTH = 6;
const MAX_ITEMS = 50;

/**
 * Deep-masks a parsed body.
 */
export function maskValue(value, depth = 0, extraKeys) {
  if (value === null || value === undefined) return value;
  if (typeof value === 'string') return maskString(value, extraKeys);
  if (typeof value === 'number' || typeof value === 'boolean') return value;
  if (depth >= MAX_DEPTH) return `${REDACTED} depth-limit]`;

  if (Array.isArray(value)) {
    const out = value.slice(0, MAX_ITEMS).map(v => maskValue(v, depth + 1, extraKeys));
    if (value.length > MAX_ITEMS) out.push(`…[${value.length - MAX_ITEMS} more items]`);
    return out;
  }

  if (typeof value === 'object') {
    const out = {};
    const entries = Object.entries(value);
    for (const [k, v] of entries.slice(0, MAX_ITEMS)) {
      if (isSensitiveKey(k, extraKeys) && (typeof v === 'string' || typeof v === 'number')) {
        const raw = String(v);
        if (raw.startsWith(REDACTED) || raw.startsWith('XXXX-XXXX-XXXX-')) {
          out[k] = raw;
          continue;
        }
        const digits = raw.replace(/\D/g, '');
        out[k] = CARD_KEY_RE.test(k) && digits.length >= 12 ? maskCard(digits) : redactedShape(raw);
      } else {
        out[k] = maskValue(v, depth + 1, extraKeys);
      }
    }
    if (entries.length > MAX_ITEMS) out['…'] = `${entries.length - MAX_ITEMS} more keys`;
    return out;
  }
  return String(value);
}

/**
 * Masks a request body of unknown shape (string or object).
 */
export function maskBody(body, extraKeys) {
  if (body === null || body === undefined) return body;
  if (typeof body !== 'string') return maskValue(body, 0, extraKeys);
  const trimmed = body.trim();
  if (trimmed.startsWith('{') || trimmed.startsWith('[')) {
    try {
      return JSON.stringify(maskValue(JSON.parse(trimmed), 0, extraKeys));
    } catch {
      /* fallback to string masking */
    }
  }
  return maskString(body, extraKeys);
}

// ── Truncation (Layer 2) ─────────────────────────────────────────────────────

function byteLength(s) {
  if (typeof Buffer !== 'undefined') return Buffer.byteLength(s);
  return new TextEncoder().encode(s).length;
}

export function capText(s, maxBytes) {
  if (byteLength(s) <= maxBytes) return s;
  let head;
  if (typeof Buffer !== 'undefined') {
    head = Buffer.from(s).subarray(0, Math.max(0, maxBytes - 32)).toString('utf8');
  } else {
    const encoded = new TextEncoder().encode(s).subarray(0, Math.max(0, maxBytes - 32));
    head = new TextDecoder('utf-8', { fatal: false }).decode(encoded);
  }
  return `${head}…[truncated ${byteLength(s) - byteLength(head)} bytes]`;
}

const METADATA_IP = ['169', '254', '169', '254'].join('.');
const METADATA_HOST = ['metadata', 'google', 'internal'].join('.');
const SHELL_CMDS = ['cat', 'ls', 'curl', 'wget', 'nc', 'bash', 'sh'].join('|');
const JNDI_PATTERN = '\\$\\{' + 'jndi';

const TRIGGER_RES = [
  /'\s*(or|and)\s+['\d]/i,
  /union\s+select/i,
  /<\s*script/i,
  /on\w+\s*=/i,
  /\.\.[\/\\]/,
  new RegExp(JNDI_PATTERN, 'i'),
  new RegExp(';\\s*(' + SHELL_CMDS + ')\\b', 'i'),
  /(ignore|disregard)\s+(all\s+)?(previous|prior)/i,
  new RegExp(METADATA_IP + '|' + METADATA_HOST, 'i'),
  /--\s*$/m,
  /%27|%3c\s*script/i,
];

export function snippetAround(text, maxBytes) {
  if (byteLength(text) <= maxBytes) return text;
  let at = -1;
  for (const re of TRIGGER_RES) {
    const m = re.exec(text);
    if (m && (at === -1 || m.index < at)) at = m.index;
  }
  if (at <= maxBytes / 4) return capText(text, maxBytes);
  const start = Math.max(0, at - Math.floor(maxBytes / 4));
  return `…${capText(text.slice(start), maxBytes - 3)}`;
}
