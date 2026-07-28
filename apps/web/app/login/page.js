/**
 *   V-WEB-09  CWE-89   Login is a concatenated SQL query (bypassable)
 *   V-WEB-10  CWE-598  Credentials submitted over GET land in URLs and logs
 *   V-WEB-11  CWE-1004 The resulting session cookie has no HttpOnly/Secure
 *   V-WEB-12  CWE-204  Different messages for "unknown user" vs "bad password"
 */

export const dynamic = 'force-dynamic';

export default function LoginPage({ searchParams }) {
  const err = searchParams?.error;

  return (
    <>
      <h1>Sign in</h1>
      <p className="sub">
        <span className="tag cwe">CWE-89</span>
        <span className="tag cwe">CWE-327</span>
        <span className="tag cwe">CWE-1004</span>
        <span className="tag">@vulnlab/auth</span>
      </p>

      {/* V-WEB-12 (CWE-204): the error text distinguishes the two failure modes,
          which turns the form into a user-enumeration oracle. */}
      {err && <div className="card"><p style={{ color: '#fca5a5' }}>{err}</p></div>}

      <form className="stack" method="POST" action="/api/login">
        <input name="email" placeholder="email" defaultValue="alice@vulnlab.test" />
        <input name="password" type="password" placeholder="password" defaultValue="password" />
        <button type="submit">Sign in</button>
      </form>

      {/* V-WEB-10 (CWE-598): the same endpoint also accepts GET. */}
      <p className="sub" style={{ marginTop: 16 }}>
        Also reachable as <code>GET /api/login?email=…&amp;password=…</code>
      </p>

      <h2>Try these</h2>
      <pre>{`email:    ' OR '1'='1' --
password: anything                → logs in as the first row (alice)

email:    root@vulnlab.test' --
password: anything                → logs in as admin, no password needed

Then inspect the 'session' cookie: it is a HS256 JWT signed with "secret123",
readable and forgeable from JavaScript because HttpOnly is off.`}</pre>
    </>
  );
}
