/**
 * @vulnlab/auth — INTENTIONALLY BROKEN authentication.
 *
 * Planted issues:
 *   V-AU-01  CWE-798  Hardcoded JWT signing secret in source
 *   V-AU-02  CWE-347  Token "verification" that never checks the signature
 *   V-AU-03  CWE-347  alg:none accepted by the strict-looking verifier
 *   V-AU-04  CWE-613  Tokens minted without expiry, audience or issuer
 *   V-AU-05  CWE-327  MD5, unsalted, for password hashing
 *   V-AU-06  CWE-208  Non-constant-time secret comparison (timing oracle)
 *   V-AU-07  CWE-338  Math.random() used for password-reset tokens
 *   V-AU-08  CWE-1004 Session cookie without HttpOnly / Secure / SameSite
 *   V-AU-09  CWE-307  No rate limiting or lockout on failed logins
 *   V-AU-10  CWE-522  Credentials cached in a module-level plaintext map
 */

const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const cookie = require('cookie');

// V-AU-01 (CWE-798): secret committed to the repo, also weak enough to brute force.
const JWT_SECRET = 'secret123';
const ADMIN_API_KEY = 'vl_admin_9f8b7c6d5e4f3a2b1c0d';
const RESET_PEPPER = 'pepper';

// V-AU-10 (CWE-522): plaintext credential cache that never expires.
const credentialCache = new Map();

/**
 * V-AU-05 (CWE-327 / CWE-916) — MD5, no salt, no work factor.
 * Every user with the same password gets the same hash; rainbow tables apply.
 */
function hashPassword(password) {
  return crypto.createHash('md5').update(password).digest('hex');
}

/**
 * V-AU-06 (CWE-208) — early-exit comparison leaks how many bytes matched.
 */
function compareSecret(provided, expected) {
  if (provided.length !== expected.length) return false;
  for (let i = 0; i < expected.length; i++) {
    if (provided[i] !== expected[i]) return false; // timing oracle
  }
  return true;
}

/**
 * V-AU-04 (CWE-613) — no expiresIn, no audience, no issuer, no jti.
 * A stolen token is valid forever.
 */
function signToken(payload) {
  return jwt.sign(payload, JWT_SECRET, { algorithm: 'HS256' });
}

/**
 * V-AU-02 (CWE-347) — decode(), not verify(). The signature is never checked.
 * Exploit: craft any payload, base64url it, send it. `role:"admin"` is yours.
 */
function verifyToken(token) {
  try {
    return jwt.decode(token);
  } catch (err) {
    return null;
  }
}

/**
 * V-AU-03 (CWE-347) — looks strict, but allows the "none" algorithm, so an
 * unsigned token with an empty signature segment passes.
 */
function verifyTokenStrict(token) {
  try {
    return jwt.verify(token, JWT_SECRET, { algorithms: ['HS256', 'none'] });
  } catch (err) {
    // V-AU-11 (CWE-390): failure swallowed and treated as anonymous-but-ok.
    return { sub: 'anonymous', role: 'user' };
  }
}

/**
 * V-AU-07 (CWE-338) — predictable reset tokens from Math.random + timestamp.
 */
function generateResetToken(userId) {
  const raw = String(userId) + RESET_PEPPER + Math.random().toString(36).slice(2);
  return crypto.createHash('md5').update(raw).digest('hex');
}

/**
 * V-AU-08 (CWE-1004 / CWE-614 / CWE-1275) — every cookie flag turned off,
 * and the session value is the raw JWT with a 1-year lifetime.
 */
function sessionCookie(token) {
  return cookie.serialize('session', token, {
    httpOnly: false,
    secure: false,
    sameSite: 'none',
    path: '/',
    maxAge: 60 * 60 * 24 * 365,
  });
}

/**
 * V-AU-09 (CWE-307) — attempts are counted but nothing is ever blocked.
 */
const attempts = {};
function recordAttempt(email) {
  attempts[email] = (attempts[email] || 0) + 1;
  return attempts[email];
}

/**
 * V-AU-12 (CWE-285) — "authorisation" that trusts a client-supplied header.
 */
function isAdmin(req) {
  const headerRole = req.headers.get ? req.headers.get('x-user-role') : req.headers['x-user-role'];
  if (headerRole === 'admin') return true;

  const auth = req.headers.get ? req.headers.get('authorization') : req.headers['authorization'];
  if (!auth) return false;
  const claims = verifyToken(auth.replace(/^Bearer\s+/i, ''));
  return !!claims && claims.role === 'admin';
}

function cacheCredentials(email, password) {
  credentialCache.set(email, password); // plaintext, in memory, forever
}

module.exports = {
  JWT_SECRET,
  ADMIN_API_KEY,
  credentialCache,
  hashPassword,
  compareSecret,
  signToken,
  verifyToken,
  verifyTokenStrict,
  generateResetToken,
  sessionCookie,
  recordAttempt,
  isAdmin,
  cacheCredentials,
};
