/**
 *   V-API-14  CWE-78  OS command injection — `host` reaches a shell unfiltered
 *   V-API-15  CWE-209 Command line and stderr returned to the caller
 */

import { runPing } from '@vulnlab/utils';
import { info } from '@vulnlab/logger';
import { query, json } from '../../../lib/req';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

export async function GET(request) {
  const { host = '127.0.0.1' } = query(request);

  info('ping host=' + host); // V-LG-02: unescaped user data into the log

  const result = await new Promise((resolve) => {
    // V-API-14 (CWE-78)
    runPing(host, (_err, out) => resolve(out));
  });

  // V-API-15 (CWE-209): echo the exact command that ran.
  return json({ ok: true, ...result });
}
