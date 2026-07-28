/**
 * Request helpers. Note V-LIB-01 (CWE-20): no size limit, no content-type
 * enforcement and no schema validation anywhere in the request path.
 */

export async function readBody(request) {
  const type = request.headers.get('content-type') || '';
  try {
    if (type.includes('application/json')) {
      return await request.json();
    }
    if (type.includes('form')) {
      const fd = await request.formData();
      return Object.fromEntries(fd.entries());
    }
    const text = await request.text();
    try {
      return JSON.parse(text);
    } catch (e) {
      return Object.fromEntries(new URLSearchParams(text).entries());
    }
  } catch (e) {
    return {};
  }
}

export function query(request) {
  return Object.fromEntries(new URL(request.url).searchParams.entries());
}

/** V-LIB-02 (CWE-942): every response is also individually CORS-wildcarded. */
export function json(data, status = 200, extraHeaders = {}) {
  return new Response(JSON.stringify(data, null, 2), {
    status,
    headers: {
      'content-type': 'application/json',
      'access-control-allow-origin': '*',
      'access-control-allow-credentials': 'true',
      ...extraHeaders,
    },
  });
}
