/**
 *   V-WEB-16  CWE-425  Forced browsing — middleware matcher is ['/admin'] only,
 *                      so this sub-path is never evaluated. No check runs here
 *                      either, so the page is world-readable.
 */

import { allUsers } from '@vulnlab/db';

export const dynamic = 'force-dynamic';

export default function AdminUsersPage() {
  const users = allUsers();
  return (
    <>
      <h1>/admin/users</h1>
      <p className="sub">
        <span className="tag cwe">CWE-425</span>
        Reached without any session at all — the middleware matcher does not cover
        sub-paths of <code>/admin</code>.
      </p>
      <pre>{JSON.stringify(users, null, 2)}</pre>
    </>
  );
}
