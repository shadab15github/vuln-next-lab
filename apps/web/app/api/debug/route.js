/**
 *   V-API-42  CWE-215  Debug endpoint left enabled in every environment
 *   V-API-43  CWE-200  process.env, DB credentials and third-party API keys
 *                      returned to any unauthenticated caller
 *   V-API-44  CWE-532  The in-memory plaintext credential cache is dumped
 */

import { DB_CONFIG } from '@vulnlab/db';
import { JWT_SECRET, ADMIN_API_KEY, credentialCache } from '@vulnlab/auth';
import { KEYS, DEFAULT_BASE } from '@vulnlab/api-client';
import { json } from '../../../lib/req';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

export async function GET() {
  // V-API-42 (CWE-215): no NODE_ENV guard, no auth, no flag.
  return json({
    ok: true,
    env: process.env,                          // V-API-43 (CWE-200)
    database: DB_CONFIG,
    jwtSecret: JWT_SECRET,
    adminApiKey: ADMIN_API_KEY,
    thirdPartyKeys: KEYS,
    upstream: DEFAULT_BASE,
    cachedCredentials: Object.fromEntries(credentialCache), // V-API-44
    node: process.versions,
    cwd: process.cwd(),
    argv: process.argv,
    uptime: process.uptime(),
  });
}
