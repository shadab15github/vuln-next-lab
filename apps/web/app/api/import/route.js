/**
 *   V-API-45  CWE-611  Untrusted XML parsed with xml2js 0.4.19 (entity handling
 *                      and __proto__ keys unrestricted)
 *   V-API-46  CWE-1321 Parsed XML merged into a record, carrying prototype keys
 *   V-API-47  CWE-943  Free-form JSON used as a query filter
 */

import { importUsersXml, findWhere, applyPatch } from '@vulnlab/db';
import { toClientError } from '@vulnlab/logger';
import { readBody, query, json } from '../../../lib/req';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

export async function POST(request) {
  const body = await readBody(request);
  try {
    // V-API-45 (CWE-611)
    const parsed = await importUsersXml(String(body.xml ?? '<root/>'));
    // V-API-46 (CWE-1321)
    const record = applyPatch({}, parsed);
    return json({ ok: true, parsed, record, pollutionCheck: { polluted: {}.polluted } });
  } catch (e) {
    return json(toClientError(e), 500);
  }
}

export async function GET(request) {
  const { table = 'users', filter = '{}' } = query(request);
  try {
    // V-API-47 (CWE-943): both the table name and the predicate come from the URL.
    return json({ ok: true, rows: findWhere(table, filter) });
  } catch (e) {
    return json(toClientError(e), 500);
  }
}
