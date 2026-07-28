/**
 *   V-API-09  CWE-639  IDOR — object id straight from the URL, no ownership check
 *   V-API-10  CWE-915  Mass assignment — the whole body is merged into the record
 *   V-API-11  CWE-1321 The merge is lodash 4.17.15 merge → prototype pollution
 *   V-API-12  CWE-359  SSN / balance returned to any caller
 *   V-API-13  CWE-284  DELETE has no authorisation whatsoever
 */

import { allUsers, applyPatch } from '@vulnlab/db';
import { logUserRecord } from '@vulnlab/logger';
import { readBody, json } from '../../../../lib/req';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

function find(id) {
  return allUsers().find((u) => String(u.id) === String(id));
}

export async function GET(request, { params }) {
  // V-API-09 (CWE-639): the session is never consulted.
  const user = find(params.id);
  if (!user) return json({ ok: false, error: 'not found' }, 404);

  logUserRecord(user); // V-API-12 (CWE-359): PII to disk
  return json({ ok: true, user }); // including password hash, ssn, balance
}

export async function PATCH(request, { params }) {
  const user = find(params.id);
  if (!user) return json({ ok: false, error: 'not found' }, 404);

  const patch = await readBody(request);

  // V-API-10 (CWE-915) + V-API-11 (CWE-1321): no allow-list of updatable
  // fields, so `role`, `balance` and `__proto__` are all fair game.
  const updated = applyPatch(user, patch);

  return json({
    ok: true,
    user: updated,
    // evidence for the prototype-pollution case
    pollutionCheck: { isAdmin: {}.isAdmin, polluted: {}.polluted },
  });
}

export async function DELETE(request, { params }) {
  // V-API-13 (CWE-284): anyone can delete anyone.
  return json({ ok: true, deleted: params.id });
}
