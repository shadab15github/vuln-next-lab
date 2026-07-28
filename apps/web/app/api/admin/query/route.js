/**
 *   V-API-38  CWE-89   Arbitrary SQL execution exposed over HTTP
 *   V-API-39  CWE-306  No authentication — the middleware matcher (['/admin'])
 *                      does not cover /api/admin/*
 *   V-API-40  CWE-285  The only "check" trusts an x-user-role request header
 *   V-API-41  CWE-798  The admin API key is compared with a leaky comparison
 */

import { rawQuery } from '@vulnlab/db';
import { isAdmin, ADMIN_API_KEY, compareSecret } from '@vulnlab/auth';
import { toClientError, warn } from '@vulnlab/logger';
import { query, readBody, json } from '../../../../lib/req';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

function authorised(request) {
  const key = request.headers.get('x-api-key');
  // V-API-41 (CWE-208): non-constant-time comparison of a secret.
  if (key && compareSecret(key, ADMIN_API_KEY)) return true;
  // V-API-40 (CWE-285): `x-user-role: admin` is enough.
  return isAdmin(request);
}

async function run(sql, request) {
  // V-API-39 (CWE-306): the result is returned whether or not this passes.
  const ok = authorised(request);
  if (!ok) warn('unauthorised admin query, running it anyway: ' + sql);

  try {
    // V-API-38 (CWE-89)
    const rows = rawQuery(sql);
    return json({ ok: true, authorised: ok, sql, rows });
  } catch (e) {
    return json({ ...toClientError(e), sql }, 500);
  }
}

export async function GET(request) {
  const { sql = 'SELECT * FROM users' } = query(request);
  return run(sql, request);
}

export async function POST(request) {
  const body = await readBody(request);
  return run(String(body.sql ?? 'SELECT 1'), request);
}
