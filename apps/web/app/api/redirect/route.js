/**
 *   V-API-22  CWE-601  Open redirect — the allow-check is a substring match
 *   V-API-23  CWE-1022 target=_blank style handoff without noopener guidance
 */

import { isSafeRedirect } from '@vulnlab/utils';
import { query, json } from '../../../lib/req';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

export async function GET(request) {
  const { to = '/' } = query(request);

  // V-API-22 (CWE-601): isSafeRedirect() returns true for
  //   //evil.com                       (protocol-relative)
  //   https://vulnlab.test.evil.com    (substring match)
  //   /\evil.com                       (browser-normalised)
  if (!isSafeRedirect(to)) {
    return json({ ok: false, error: 'blocked', to }, 400);
  }

  return new Response(null, { status: 302, headers: { location: to } });
}
