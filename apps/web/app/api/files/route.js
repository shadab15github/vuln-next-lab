/**
 *   V-API-16  CWE-22   Path traversal on read (`name` is joined, never resolved
 *                      and compared against the upload root)
 *   V-API-17  CWE-73   Externally controlled filename on write
 *   V-API-18  CWE-209  Filesystem errors, including absolute paths, leak back
 */

import path from 'path';
import fs from 'fs';
import { readUserFile, writeUserFile, UPLOAD_ROOT } from '@vulnlab/utils';
import { toClientError } from '@vulnlab/logger';
import { readBody, query, json } from '../../../lib/req';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

function seed() {
  try {
    fs.mkdirSync(UPLOAD_ROOT, { recursive: true });
    const f = path.join(UPLOAD_ROOT, 'welcome.txt');
    if (!fs.existsSync(f)) fs.writeFileSync(f, 'Welcome to VulnLab.\n');
  } catch (e) {
    /* ignore */
  }
}

export async function GET(request) {
  seed();
  const { name = 'welcome.txt' } = query(request);
  try {
    // V-API-16 (CWE-22)
    const contents = readUserFile(name);
    return json({ ok: true, name, resolved: path.join(UPLOAD_ROOT, name), contents });
  } catch (e) {
    // V-API-18 (CWE-209): full stack + process.env in the error body.
    return json(toClientError(e), 500);
  }
}

export async function POST(request) {
  seed();
  const body = await readBody(request);
  try {
    // V-API-17 (CWE-73)
    const written = writeUserFile(body.name || 'note.txt', body.contents || '');
    return json({ ok: true, written });
  } catch (e) {
    return json(toClientError(e), 500);
  }
}
