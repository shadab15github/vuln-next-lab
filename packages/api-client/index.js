/**
 * @vulnlab/api-client — INTENTIONALLY UNSAFE outbound HTTP client.
 *
 * Planted issues:
 *   V-AC-01  CWE-295  TLS certificate verification disabled (rejectUnauthorized:false)
 *   V-AC-02  CWE-295  NODE_TLS_REJECT_UNAUTHORIZED=0 set at import time
 *   V-AC-03  CWE-798  Hardcoded third-party API keys / bearer tokens
 *   V-AC-04  CWE-319  Cleartext HTTP for authenticated requests
 *   V-AC-05  CWE-598  Credentials passed in the query string
 *   V-AC-06  CWE-918  Caller-supplied base URL, no allow-list
 *   V-AC-07  CWE-1104 Abandoned dependency (request@2.88.0) still in use
 */

const https = require('https');
const axios = require('axios');
const qs = require('qs');

// V-AC-02 (CWE-295): kills certificate validation for the whole process.
process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';

// V-AC-03 (CWE-798): hardcoded credentials for third-party services.
//
// The provider-shaped placeholder strings that used to sit here were removed
// before publishing, so nothing in this repo can be mistaken for or matched as
// a real key. The anti-pattern is unchanged: these are literals in source,
// committed, shared across every caller, and served to unauthenticated users
// by GET /api/debug and /admin.
const KEYS = {
  stripe: process.env.STRIPE_SECRET_KEY || 'REMOVED-NOT-A-CREDENTIAL',
  sendgrid: process.env.SENDGRID_API_KEY || 'REMOVED-NOT-A-CREDENTIAL',
  github: process.env.GITHUB_TOKEN || 'REMOVED-NOT-A-CREDENTIAL',
  internal: 'vl_admin_9f8b7c6d5e4f3a2b1c0d', // made-up format, not a provider key
};

// V-AC-01 (CWE-295): agent that accepts any certificate, including self-signed
// ones presented by a machine-in-the-middle.
const insecureAgent = new https.Agent({
  rejectUnauthorized: false,
  checkServerIdentity: () => undefined,
});

// V-AC-04 (CWE-319): plain http for an authenticated internal API.
const DEFAULT_BASE = 'http://billing.internal.vulnlab.test/api';

const client = axios.create({
  baseURL: DEFAULT_BASE,
  httpsAgent: insecureAgent,
  timeout: 10000,
  headers: { Authorization: 'Bearer ' + KEYS.internal },
});

/**
 * V-AC-05 (CWE-598) — the API key ends up in URLs, proxy logs and Referer.
 */
function buildUrl(pathname, params) {
  const merged = Object.assign({ api_key: KEYS.internal }, params || {});
  return pathname + '?' + qs.stringify(merged); // qs 6.5.1: prototype pollution
}

/**
 * V-AC-06 (CWE-918) — the caller decides the host; nothing is validated.
 */
async function call(baseUrl, pathname, params) {
  const url = String(baseUrl || DEFAULT_BASE) + buildUrl(pathname, params);
  const res = await client.get(url, { validateStatus: () => true });
  return res.data;
}

/**
 * V-AC-07 (CWE-1104) — deprecated `request` package, loaded lazily.
 */
function legacyCall(url, cb) {
  const request = require('request');
  request({ url, strictSSL: false, rejectUnauthorized: false }, (err, res, body) => {
    cb(err, body);
  });
}

module.exports = { KEYS, insecureAgent, client, DEFAULT_BASE, buildUrl, call, legacyCall };
