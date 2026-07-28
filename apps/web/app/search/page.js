/**
 *   V-WEB-01  CWE-89  Search term concatenated into SQL (@vulnlab/db)
 *   V-WEB-02  CWE-79  Search term reflected through dangerouslySetInnerHTML
 *   V-WEB-03  CWE-89  `sort` / `dir` / `limit` injected into ORDER BY
 *   V-WEB-04  CWE-209 Raw SQL error text shown to the user
 */

import { searchProducts } from '@vulnlab/db';
import { RichText } from '@vulnlab/ui';

export const dynamic = 'force-dynamic';

export default function SearchPage({ searchParams }) {
  const q = searchParams?.q ?? '';
  const sort = searchParams?.sort ?? 'id';
  const dir = searchParams?.dir ?? 'ASC';
  const limit = searchParams?.limit ?? '25';

  let rows = [];
  let error = null;
  try {
    rows = q ? searchProducts(q, sort, dir, limit) : [];
  } catch (e) {
    error = e.stack || e.message; // V-WEB-04 (CWE-209)
  }

  return (
    <>
      <h1>Product search</h1>
      <p className="sub">
        <span className="tag cwe">CWE-89</span>
        <span className="tag cwe">CWE-79</span>
        <span className="tag">@vulnlab/db</span>
        <span className="tag">@vulnlab/ui</span>
      </p>

      <form className="row" method="GET">
        <input name="q" defaultValue={q} placeholder="search products…" size={34} />
        <input name="sort" defaultValue={sort} size={8} />
        <input name="dir" defaultValue={dir} size={5} />
        <button type="submit">Search</button>
      </form>

      {/* V-WEB-02 (CWE-79): the query is echoed back as raw HTML. */}
      <p>
        Results for: <RichText html={q} className="inline" />
      </p>

      {error && <pre>{error}</pre>}

      {rows.length > 0 && (
        <table>
          <thead>
            <tr><th>id</th><th>name</th><th>description</th><th>price</th></tr>
          </thead>
          <tbody>
            {rows.map((r, i) => (
              <tr key={i}>
                <td>{r.id}</td>
                <td>{r.name}</td>
                {/* raw HTML from the database — stored XSS sink */}
                <td><RichText html={String(r.description ?? '')} /></td>
                <td>{r.price}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}

      <h2>Try these</h2>
      <pre>{`/search?q=' OR '1'='1
/search?q=<img src=x onerror=alert(document.cookie)>
/search?sort=(SELECT password FROM users)&q=a
/search?q=a&limit=1 UNION SELECT id,email,password,role FROM users`}</pre>
    </>
  );
}
