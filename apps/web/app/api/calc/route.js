/**
 *   V-API-24  CWE-95  eval() of a user-supplied expression → RCE
 *   V-API-25  CWE-94  Function constructor over a user-supplied rule → RCE
 */

import { calculate, compileRule } from '@vulnlab/utils';
import { toClientError } from '@vulnlab/logger';
import { readBody, query, json } from '../../../lib/req';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

export async function POST(request) {
  const body = await readBody(request);
  try {
    if (body.rule) {
      // V-API-25 (CWE-94)
      const fn = compileRule(String(body.rule));
      return json({ ok: true, result: fn(body.ctx || {}) });
    }
    // V-API-24 (CWE-95)
    const result = calculate(String(body.expr ?? '0'));
    return json({ ok: true, expr: body.expr, result: String(result) });
  } catch (e) {
    return json(toClientError(e), 500);
  }
}

export async function GET(request) {
  const { expr = '0' } = query(request);
  try {
    return json({ ok: true, expr, result: String(calculate(expr)) });
  } catch (e) {
    return json(toClientError(e), 500);
  }
}
