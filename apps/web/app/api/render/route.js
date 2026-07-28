/**
 *   V-API-26  CWE-1336 Server-side template injection — the template itself is
 *                      user input (Handlebars 4.0.11 and EJS 3.1.6)
 *   V-API-27  CWE-79   The rendered output is returned as text/html unescaped
 */

import { renderHandlebars, renderEjs } from '@vulnlab/utils';
import { toClientError } from '@vulnlab/logger';
import { readBody, query } from '../../../lib/req';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

function html(body, status = 200) {
  // V-API-27 (CWE-79): content-type text/html, no escaping, no CSP.
  return new Response(body, {
    status,
    headers: { 'content-type': 'text/html; charset=utf-8', 'access-control-allow-origin': '*' },
  });
}

async function render(template, engine, data) {
  if (engine === 'ejs') {
    // V-API-26 (CWE-1336): EJS 3.1.6 — see CVE-2022-29078 for the options path.
    return renderEjs(template, data, { async: false });
  }
  return renderHandlebars(template, data);
}

export async function POST(request) {
  const body = await readBody(request);
  try {
    const out = await render(String(body.template ?? ''), body.engine, body.data || { name: 'world' });
    return html(String(out));
  } catch (e) {
    return html('<pre>' + JSON.stringify(toClientError(e), null, 2) + '</pre>', 500);
  }
}

export async function GET(request) {
  const q = query(request);
  try {
    const out = await render(String(q.template ?? 'Hello {{name}}'), q.engine, { name: q.name || 'world' });
    return html(String(out));
  } catch (e) {
    return html('<pre>' + JSON.stringify(toClientError(e), null, 2) + '</pre>', 500);
  }
}
