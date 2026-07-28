/**
 *   V-API-31  CWE-1321 Prototype pollution — recursive merge of untrusted JSON
 *   V-API-32  CWE-915  Server-side settings mass-assigned from the request
 *   V-API-33  CWE-1333 ReDoS — the notification email is validated with a
 *                      catastrophically backtracking regex
 */

import { deepMerge, validateEmail } from '@vulnlab/utils';
import { toClientError } from '@vulnlab/logger';
import { readBody, json } from '../../../lib/req';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

// V-API-32 (CWE-915): module-level mutable settings, shared by every request.
const settings = {
  theme: 'light',
  itemsPerPage: 25,
  features: { beta: false },
  security: { requireMfa: true, maxUploadMb: 5 },
};

export async function POST(request) {
  const body = await readBody(request);
  try {
    const patch = typeof body.patch === 'string' ? JSON.parse(body.patch) : body.patch || body;

    if (patch.notifyEmail) {
      // V-API-33 (CWE-1333): "a".repeat(40) + "!" pins a CPU core.
      patch.notifyEmailValid = validateEmail(String(patch.notifyEmail));
    }

    // V-API-31 (CWE-1321): __proto__ and constructor.prototype are walked.
    deepMerge(settings, patch);

    return json({
      ok: true,
      settings,
      // Evidence: a brand-new object now carries attacker-supplied properties.
      pollutionCheck: { isAdmin: {}.isAdmin, polluted: {}.polluted, requireMfa: settings.security.requireMfa },
    });
  } catch (e) {
    return json(toClientError(e), 500);
  }
}

export async function GET() {
  return json({ ok: true, settings });
}
