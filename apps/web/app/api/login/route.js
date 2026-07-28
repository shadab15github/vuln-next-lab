/**
 *   V-API-01  CWE-89   SQL injection in the login query → authentication bypass
 *   V-API-02  CWE-327  MD5 password hashing, unsalted
 *   V-API-03  CWE-522  Plaintext password written to the log and to a cache
 *   V-API-04  CWE-1004 Session cookie without HttpOnly / Secure / SameSite
 *   V-API-05  CWE-613  JWT with no expiry, signed with a hardcoded secret
 *   V-API-06  CWE-307  No rate limiting or account lockout
 *   V-API-07  CWE-204  Distinguishable errors → user enumeration
 *   V-API-08  CWE-598  Credentials accepted over GET (query string)
 */

import { findCredentials, getUserByEmail } from '@vulnlab/db';
import { hashPassword, signToken, sessionCookie, recordAttempt, cacheCredentials } from '@vulnlab/auth';
import { logAuthAttempt } from '@vulnlab/logger';
import { readBody, query, json } from '../../../lib/req';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

async function handle(email, password, wantsRedirect, request) {
  // V-API-06 (CWE-307): counted, never enforced.
  recordAttempt(email);

  // V-API-03 (CWE-522 / CWE-532)
  cacheCredentials(email, password);
  logAuthAttempt(email, password, '(pending)', request.headers.get('cookie') || '');

  // V-API-02 (CWE-327)
  const hash = hashPassword(String(password ?? ''));

  // V-API-01 (CWE-89): both operands are concatenated into the SQL string.
  const rows = findCredentials(String(email ?? ''), hash);

  if (!rows || rows.length === 0) {
    // V-API-07 (CWE-204): tell the attacker which half was wrong.
    const known = getUserByEmail(String(email ?? '')).length > 0;
    const message = known ? 'Incorrect password for that account' : 'No account with that email';
    if (wantsRedirect) {
      return Response.redirect(new URL('/login?error=' + encodeURIComponent(message), request.url), 302);
    }
    return json({ ok: false, error: message, attempts: recordAttempt(email) }, 401);
  }

  const user = rows[0];
  // V-API-05 (CWE-613): no exp, no aud, no iss, secret is "secret123".
  const token = signToken({ sub: user.id, email: user.email, role: user.role });

  logAuthAttempt(email, password, token, request.headers.get('cookie') || '');

  const headers = {
    // V-API-04 (CWE-1004 / CWE-614)
    'set-cookie': sessionCookie(token),
    // and a second cookie the client can simply flip — see middleware.js
    'x-auth-token': token,
  };

  if (wantsRedirect) {
    return new Response(null, {
      status: 302,
      headers: { ...headers, location: '/profile/' + user.id },
    });
  }
  return json({ ok: true, user, token }, 200, headers);
}

export async function POST(request) {
  const body = await readBody(request);
  const isForm = (request.headers.get('content-type') || '').includes('form');
  return handle(body.email, body.password, isForm, request);
}

// V-API-08 (CWE-598): passwords in the URL — browser history, proxies, logs.
export async function GET(request) {
  const q = query(request);
  return handle(q.email, q.password, false, request);
}
