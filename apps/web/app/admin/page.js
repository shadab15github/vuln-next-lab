/**
 *   V-WEB-13  CWE-602  Access control enforced only in middleware/UI, never in
 *                      the data layer, and bypassable several ways
 *   V-WEB-14  CWE-798  Admin API key rendered into the HTML
 *   V-WEB-15  CWE-200  Full user table (passwords + SSNs) dumped to the page
 */

import { allUsers, DB_CONFIG } from '@vulnlab/db';
import { ADMIN_API_KEY, JWT_SECRET } from '@vulnlab/auth';
import { KEYS } from '@vulnlab/api-client';
import { DebugPanel } from '@vulnlab/ui';

export const dynamic = 'force-dynamic';

export default function AdminPage() {
  const users = allUsers();

  return (
    <>
      <h1>Admin console</h1>
      <p className="sub">
        <span className="tag cwe">CWE-602</span>
        <span className="tag cwe">CWE-798</span>
        <span className="tag">middleware.js</span>
      </p>

      <div className="card">
        <h3>Bypasses that reach this page</h3>
        <pre>{`document.cookie = "is_admin=true"          → V-MW-04, client-controlled gate
curl -H "x-middleware-subrequest: 1" …     → V-MW-02, CVE-2025-29927 shape
curl -H "x-forwarded-for: 127.0.0.1" …     → V-MW-02, spoofable "internal" check
/admin/users, /api/admin/query             → V-MW-03, matcher never runs`}</pre>
      </div>

      {/* V-WEB-15 (CWE-200) */}
      <h2>Users</h2>
      <table>
        <thead>
          <tr><th>id</th><th>email</th><th>md5(password)</th><th>role</th><th>ssn</th><th>balance</th></tr>
        </thead>
        <tbody>
          {users.map((u) => (
            <tr key={u.id}>
              <td>{u.id}</td><td>{u.email}</td><td className="mono">{u.password}</td>
              <td>{u.role}</td><td>{u.ssn}</td><td>{u.balance}</td>
            </tr>
          ))}
        </tbody>
      </table>

      {/* V-WEB-14 (CWE-798): secrets shipped to the browser. */}
      <h2>Configuration</h2>
      <DebugPanel data={{ DB_CONFIG, JWT_SECRET, ADMIN_API_KEY, THIRD_PARTY_KEYS: KEYS }} />
    </>
  );
}
