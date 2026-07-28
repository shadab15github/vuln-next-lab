/**
 *   V-API-19  CWE-918  SSRF — arbitrary URL, redirects followed, no scheme,
 *                      host or IP-range restrictions
 *   V-API-20  CWE-295  TLS verification disabled process-wide by @vulnlab/api-client
 *   V-API-21  CWE-200  Upstream response headers proxied back to the caller
 */

import { fetchUrl } from '@vulnlab/utils';
import { call } from '@vulnlab/api-client';
import { toClientError, info } from '@vulnlab/logger';
import { query, json } from '../../../lib/req';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

export async function GET(request) {
  const { url, base, path: p } = query(request);

  try {
    if (base) {
      // V-API-19b: the *base* URL is caller-supplied too, so the hardcoded
      // internal API key in @vulnlab/api-client is sent to an attacker host.
      const data = await call(base, p || '/status', {});
      return json({ ok: true, via: 'api-client', base, data });
    }

    if (!url) return json({ ok: false, error: 'pass ?url=' }, 400);

    info('fetching ' + url);
    // V-API-19 (CWE-918)
    const res = await fetchUrl(url);
    // V-API-21 (CWE-200)
    return json({ ok: true, url, status: res.status, headers: res.headers, body: res.body });
  } catch (e) {
    return json(toClientError(e), 500);
  }
}
