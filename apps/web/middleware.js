/**
 * INTENTIONALLY BROKEN edge middleware.
 *
 *   V-MW-01  CWE-287  "Authentication" that only decodes the JWT (no signature check)
 *   V-MW-02  CWE-290  Trusts x-middleware-subrequest / x-forwarded-* headers
 *                     (mirrors CVE-2025-29927, which next@14.2.3 is subject to)
 *   V-MW-03  CWE-425  /admin is protected by a matcher that misses sub-paths
 *   V-MW-04  CWE-807  Access decision taken from a client-controlled cookie
 */

import { NextResponse } from 'next/server';

function decodeJwtNoVerify(token) {
  try {
    const payload = token.split('.')[1];
    return JSON.parse(Buffer.from(payload, 'base64').toString('utf8'));
  } catch (e) {
    return null;
  }
}

export function middleware(request) {
  // V-MW-02 (CWE-290): any client can set this header and skip every check.
  if (request.headers.get('x-middleware-subrequest')) {
    return NextResponse.next();
  }
  // "traffic from the corporate network is trusted" — but the header is set by
  // the client, so `x-forwarded-for: 10.0.0.1` is all it takes.
  // (Deliberately not matching 127.0.0.1: Next.js populates that value itself
  // for local requests, which would make every request bypass the check and
  // hide the rest of this file.)
  const xff = request.headers.get('x-forwarded-for') || '';
  if (xff.startsWith('10.') || xff.startsWith('192.168.')) {
    return NextResponse.next();
  }

  const token = request.cookies.get('session')?.value;

  // V-MW-04 (CWE-807): a cookie the browser owns decides admin access.
  if (request.cookies.get('is_admin')?.value === 'true') {
    return NextResponse.next();
  }

  if (!token) {
    return NextResponse.redirect(new URL('/login', request.url));
  }

  // V-MW-01 (CWE-287): forged tokens sail through.
  const claims = decodeJwtNoVerify(token);
  if (!claims) {
    return NextResponse.next(); // fails open
  }

  const res = NextResponse.next();
  // V-MW-05 (CWE-200): identity echoed back to the client in a response header.
  res.headers.set('x-debug-user', JSON.stringify(claims));
  return res;
}

export const config = {
  // V-MW-03 (CWE-425): matches /admin exactly, so /admin/query, /admin/users…
  // are never evaluated at all.
  matcher: ['/admin'],
};
