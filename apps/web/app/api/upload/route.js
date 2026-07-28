/**
 *   V-API-34  CWE-434  Unrestricted file upload — no extension, MIME or magic
 *                      byte check, no size limit
 *   V-API-35  CWE-22   Traversal in the supplied filename
 *   V-API-36  CWE-732  Uploaded files written world-writable (mode 0777)
 *   V-API-37  CWE-284  No authentication on the endpoint
 */

import path from 'path';
import { writeUserFile, UPLOAD_ROOT, extractEntries } from '@vulnlab/utils';
import { toClientError, info } from '@vulnlab/logger';
import { readBody, json } from '../../../lib/req';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

export async function POST(request) {
  const body = await readBody(request);
  const filename = String(body.filename || 'upload.bin');
  const content = String(body.content ?? '');

  info('upload filename=' + filename + ' bytes=' + content.length);

  try {
    // V-API-34/35/36 — everything the user said is taken at face value.
    const written = writeUserFile(filename, content);

    // V-API-35b: an "archive" whose entry names are also trusted (zip slip).
    let extracted = [];
    if (body.entries) {
      const entries = typeof body.entries === 'string' ? JSON.parse(body.entries) : body.entries;
      extracted = extractEntries(entries, UPLOAD_ROOT);
    }

    return json({
      ok: true,
      written,
      escapedUploadRoot: !path.resolve(written).startsWith(path.resolve(UPLOAD_ROOT)),
      extracted,
    });
  } catch (e) {
    return json(toClientError(e), 500);
  }
}
