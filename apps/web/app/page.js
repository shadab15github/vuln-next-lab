import Link from 'next/link';

const GROUPS = [
  {
    title: 'Injection',
    items: [
      { href: '/search?q=laptop', name: 'Product search', cwe: 'CWE-89', pkg: '@vulnlab/db', note: "SQL injection — try q=' OR '1'='1" },
      { href: "/api/admin/query?sql=SELECT%20*%20FROM%20users", name: 'GET /api/admin/query', cwe: 'CWE-89', pkg: '@vulnlab/db', note: 'Arbitrary SQL, no authorisation at all' },
      { href: '/tools#ping', name: 'GET /api/ping', cwe: 'CWE-78', pkg: '@vulnlab/utils', note: 'Command injection — host=127.0.0.1 && whoami' },
      { href: '/tools#calc', name: 'POST /api/calc', cwe: 'CWE-95', pkg: '@vulnlab/utils', note: 'eval() on the request body' },
      { href: '/tools#render', name: 'POST /api/render', cwe: 'CWE-1336', pkg: '@vulnlab/utils', note: 'Server-side template injection (Handlebars/EJS)' },
    ],
  },
  {
    title: 'Cross-site scripting',
    items: [
      { href: '/search?q=%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E', name: 'Reflected XSS', cwe: 'CWE-79', pkg: '@vulnlab/ui', note: 'Search term rendered with dangerouslySetInnerHTML' },
      { href: '/profile/1', name: 'Stored XSS in profile bio', cwe: 'CWE-79', pkg: '@vulnlab/ui', note: 'marked 0.3.6, sanitize disabled' },
    ],
  },
  {
    title: 'Broken authentication & access control',
    items: [
      { href: '/login', name: 'Login', cwe: 'CWE-89 / CWE-327', pkg: '@vulnlab/auth', note: "SQLi login bypass, MD5 hashing, forever-tokens" },
      { href: '/api/users/3', name: 'GET /api/users/3', cwe: 'CWE-639', pkg: 'apps/web', note: 'IDOR — read any user, PII included' },
      { href: '/admin', name: '/admin', cwe: 'CWE-807', pkg: 'middleware.js', note: 'Admin gate driven by a client-set cookie' },
    ],
  },
  {
    title: 'Server-side request forgery & redirects',
    items: [
      { href: '/tools#fetch', name: 'GET /api/fetch', cwe: 'CWE-918', pkg: '@vulnlab/utils', note: 'Fetches any URL, follows redirects, no allow-list' },
      { href: '/api/redirect?to=https://example.com', name: 'GET /api/redirect', cwe: 'CWE-601', pkg: '@vulnlab/utils', note: 'Open redirect via a bypassable prefix check' },
    ],
  },
  {
    title: 'Files, deserialization & configuration',
    items: [
      { href: '/tools#files', name: 'GET /api/files', cwe: 'CWE-22', pkg: '@vulnlab/utils', note: 'Path traversal on read and write' },
      { href: '/tools#deser', name: 'POST /api/deserialize', cwe: 'CWE-502', pkg: '@vulnlab/utils', note: 'node-serialize RCE, unsafe YAML load' },
      { href: '/tools#config', name: 'POST /api/config', cwe: 'CWE-1321', pkg: '@vulnlab/utils', note: 'Prototype pollution through a deep merge' },
      { href: '/api/debug', name: 'GET /api/debug', cwe: 'CWE-200', pkg: '@vulnlab/logger', note: 'Dumps process.env, config and secrets' },
    ],
  },
];

export default function Home() {
  return (
    <>
      <h1>VulnLab</h1>
      <p className="sub">
        A deliberately vulnerable Next.js 14 monorepo. Six local workspace packages
        (<code>@vulnlab/db</code>, <code>auth</code>, <code>utils</code>, <code>ui</code>,{' '}
        <code>logger</code>, <code>api-client</code>) each carry planted flaws, and the
        dependency tree is pinned to versions with published CVEs.
      </p>
      <p className="sub">
        Every finding is catalogued in <code>VULNERABILITIES.md</code> with a stable ID,
        CWE, file path and reproduction step.
      </p>

      {GROUPS.map((g) => (
        <section key={g.title}>
          <h2>{g.title}</h2>
          {g.items.map((it) => (
            <div className="card" key={it.href + it.name}>
              <h3>
                <Link href={it.href}>{it.name}</Link>
              </h3>
              <p>{it.note}</p>
              <span className="tag cwe">{it.cwe}</span>
              <span className="tag">{it.pkg}</span>
            </div>
          ))}
        </section>
      ))}

      <h2>Seeded accounts</h2>
      <table>
        <thead>
          <tr><th>email</th><th>password</th><th>role</th></tr>
        </thead>
        <tbody>
          <tr><td>alice@vulnlab.test</td><td>password</td><td>user</td></tr>
          <tr><td>bob@vulnlab.test</td><td>123456</td><td>user</td></tr>
          <tr><td>root@vulnlab.test</td><td>admin</td><td>admin</td></tr>
        </tbody>
      </table>
    </>
  );
}
