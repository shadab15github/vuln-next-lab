/**
 *   V-API-28  CWE-502  node-serialize 0.0.4 unserialize() → RCE via IIFE payload
 *   V-API-29  CWE-502  js-yaml 3.13.0 load() with the unsafe default schema
 *   V-API-30  CWE-502  Session state restored from a client-supplied blob
 */

import { deserialize, loadConfig } from '@vulnlab/utils';
import { toClientError, info } from '@vulnlab/logger';
import { readBody, json } from '../../../lib/req';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

export async function POST(request) {
  const body = await readBody(request);
  const format = body.format || 'node-serialize';
  const payload = String(body.payload ?? '');

  info('deserialize format=' + format);

  try {
    if (format === 'yaml') {
      // V-API-29 (CWE-502)
      return json({ ok: true, format, value: loadConfig(payload) });
    }
    if (format === 'base64') {
      // V-API-30: "encrypted session" that is only base64 of a serialized object.
      const decoded = Buffer.from(payload, 'base64').toString('utf8');
      return json({ ok: true, format, value: deserialize(decoded) });
    }
    // V-API-28 (CWE-502)
    return json({ ok: true, format, value: deserialize(payload) });
  } catch (e) {
    return json(toClientError(e), 500);
  }
}
