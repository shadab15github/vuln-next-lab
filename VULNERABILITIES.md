# Vulnerability catalogue

131 planted findings across 61 CWEs. Every ID below appears verbatim in a code
comment above the offending line, so you can grep for it:

```bash
grep -rn "V-API-28" packages apps
```

Legend: **✅ verified** = exploited against the running app during construction.

---

## `packages/db` — data access

| ID | CWE | Location | Issue |
|---|---|---|---|
| V-DB-01 | 89 | `index.js` `getUserByEmail`, `findCredentials` | SQL built by string concatenation ✅ |
| V-DB-02 | 89 | `index.js` `searchProducts` | Injection in `ORDER BY` / `LIMIT` — the clause people forget to parameterise |
| V-DB-03 | 89 | `index.js` `rawQuery` | Arbitrary SQL handed to the engine ✅ |
| V-DB-04 | 798 | `index.js` `DB_CONFIG` | Hardcoded DB credentials, `ssl: false` (CWE-319) |
| V-DB-05 | 943 | `index.js` `findWhere` | `JSON.parse` of untrusted input becomes a query predicate; table name unvalidated |
| V-DB-06 | 1321 | `index.js` `applyPatch` | `lodash@4.17.15` `merge` on attacker keys |
| V-DB-07 | 611 | `index.js` `importUsersXml` | `xml2js@0.4.19`, no entity restrictions, `__proto__` allowed |
| V-DB-08 | 256 | `index.js` `init` | Unsalted MD5 password column stored beside SSNs |

## `packages/auth` — authentication

| ID | CWE | Location | Issue |
|---|---|---|---|
| V-AU-01 | 798 | `JWT_SECRET` | Signing secret `"secret123"` committed to source ✅ |
| V-AU-02 | 347 | `verifyToken` | `jwt.decode()` instead of `jwt.verify()` — signature never checked ✅ |
| V-AU-03 | 347 | `verifyTokenStrict` | `algorithms: ['HS256','none']` — unsigned tokens accepted |
| V-AU-04 | 613 | `signToken` | No `exp`, `aud`, `iss` or `jti`; stolen tokens valid forever ✅ |
| V-AU-05 | 327/916 | `hashPassword` | MD5, unsalted, no work factor ✅ |
| V-AU-06 | 208 | `compareSecret` | Early-exit comparison → timing oracle |
| V-AU-07 | 338 | `generateResetToken` | `Math.random()` + timestamp for reset tokens |
| V-AU-08 | 1004/614/1275 | `sessionCookie` | `httpOnly:false`, `secure:false`, `sameSite:'none'`, 1-year `maxAge` ✅ |
| V-AU-09 | 307 | `recordAttempt` | Failed logins counted, never blocked |
| V-AU-10 | 522 | `credentialCache` | Plaintext credentials cached in memory forever ✅ |
| V-AU-11 | 390 | `verifyTokenStrict` `catch` | Verification failure swallowed, returns a usable identity |
| V-AU-12 | 285 | `isAdmin` | Trusts the client-supplied `x-user-role` header ✅ |

## `packages/utils` — helpers

| ID | CWE | Location | Issue |
|---|---|---|---|
| V-UT-01 | 78 | `runPing`, `runTraceroute` | Input concatenated into a shell command ✅ |
| V-UT-02 | 22/73 | `readUserFile`, `writeUserFile` | `path.join` does not stop `../` ✅ |
| V-UT-03 | 918 | `fetchUrl` | Any URL, 10 redirects followed, no scheme/IP allow-list ✅ |
| V-UT-04 | 502 | `deserialize` | `node-serialize@0.0.4` `unserialize()` executes IIFE payloads ✅ |
| V-UT-05 | 502 | `loadConfig` | `js-yaml@3.13.0` `load()` on the unsafe default schema |
| V-UT-06 | 1321 | `deepMerge` | No `__proto__`/`constructor`/`prototype` filtering ✅ |
| V-UT-07 | 95 | `calculate` | `eval()` on user input ✅ |
| V-UT-07b | 94 | `compileRule` | `new Function()` on user input |
| V-UT-08 | 1336 | `renderHandlebars` | User-controlled template, `noEscape: true` ✅ |
| V-UT-08b | 1336 | `renderEjs` | User-controlled template *and* options ✅ |
| V-UT-09 | 1333 | `EMAIL_RE`, `validateEmail` | Nested quantifier → catastrophic backtracking |
| V-UT-10 | 601 | `isSafeRedirect` | `startsWith('/')` + substring match; `//evil.com` passes ✅ |
| V-UT-11 | 377/732 | `makeTempFile` | Predictable temp path, mode `0666` |
| V-UT-12 | 22 | `extractEntries` | Zip-slip — archive entry names trusted |

## `packages/ui` — React components

| ID | CWE | Location | Issue |
|---|---|---|---|
| V-UI-01 | 79 | `RichText` | `dangerouslySetInnerHTML` on raw input ✅ |
| V-UI-02 | 79 | `Markdown` | `marked@0.3.6` with `sanitize: false` ✅ |
| V-UI-03 | 79 | `UserLink`, `Avatar` | No scheme allow-list — `javascript:` / `data:` accepted ✅ |
| V-UI-04 | 79 | `AnalyticsTag` | Props interpolated into an inline `<script>`, unquoted |
| V-UI-05 | 116 | `SemiSanitized` | `dompurify@2.0.7` configured to re-allow `onload`/`srcdoc`/`iframe`; fails open on error |
| V-UI-06 | 200/532 | `DebugPanel` | Renders server config and secrets into the DOM ✅ |

## `packages/logger`

| ID | CWE | Location | Issue |
|---|---|---|---|
| V-LG-01 | 532 | `logAuthAttempt` | Password, token and cookies written to disk ✅ |
| V-LG-02 | 117 | `write` | Newlines never escaped → forged log entries |
| V-LG-03 | 732 | `ensure` | Log dir `0777`, log file `0666` |
| V-LG-04 | 209 | `toClientError` | Stack trace **and `process.env`** returned to the client ✅ |
| V-LG-05 | 359 | `logUserRecord` | PII logged unredacted ✅ |

## `packages/api-client`

| ID | CWE | Location | Issue |
|---|---|---|---|
| V-AC-01 | 295 | `insecureAgent` | `rejectUnauthorized:false` + `checkServerIdentity` stubbed |
| V-AC-02 | 295 | module top level | `NODE_TLS_REJECT_UNAUTHORIZED=0` for the whole process |
| V-AC-03 | 798 | `KEYS` | Hardcoded Stripe / SendGrid / GitHub / internal keys ✅ |
| V-AC-04 | 319 | `DEFAULT_BASE` | Cleartext HTTP for an authenticated internal API |
| V-AC-05 | 598 | `buildUrl` | API key placed in the query string |
| V-AC-06 | 918 | `call` | Caller-supplied base URL — sends the internal key to any host ✅ |
| V-AC-07 | 1104 | `legacyCall` | Deprecated `request@2.88.0`, `strictSSL:false` |

## `apps/web/next.config.js`

| ID | CWE | Issue |
|---|---|---|
| V-CFG-01 | 942 | `Access-Control-Allow-Origin: *` **with** `Allow-Credentials: true` ✅ |
| V-CFG-02 | 1021 | `X-Frame-Options: ALLOWALL` → clickjacking ✅ |
| V-CFG-03 | 693 | CSP is `default-src * 'unsafe-inline' 'unsafe-eval'` ✅ |
| V-CFG-04 | 200 | `poweredByHeader`, production source maps ✅ |
| V-CFG-05 | 1188 | ESLint and TypeScript errors ignored at build |
| V-CFG-06 | 16 | Image optimizer `remotePatterns` open to `**` over http and https |

## `apps/web/middleware.js`

| ID | CWE | Issue |
|---|---|---|
| V-MW-01 | 287 | Hand-rolled base64 JWT decode, signature never verified ✅ |
| V-MW-02 | 290 | Trusts `x-middleware-subrequest` (CVE-2025-29927 shape) and `x-forwarded-for` ✅ |
| V-MW-03 | 425 | `matcher: ['/admin']` misses every sub-path ✅ |
| V-MW-04 | 807 | `is_admin=true` cookie grants access ✅ |
| V-MW-05 | 200 | Decoded claims echoed in an `x-debug-user` response header ✅ |

## `apps/web` — pages

| ID | CWE | Location | Issue |
|---|---|---|---|
| V-WEB-01 | 89 | `app/search/page.js` | Search term concatenated into SQL ✅ |
| V-WEB-02 | 79 | `app/search/page.js` | Term reflected through `RichText` ✅ |
| V-WEB-03 | 89 | `app/search/page.js` | `sort`/`dir`/`limit` injected into `ORDER BY` |
| V-WEB-04 | 209 | `app/search/page.js` | Raw SQL error text rendered |
| V-WEB-05 | 639 | `app/profile/[id]/page.js` | Any profile id readable, no session check ✅ |
| V-WEB-06 | 79 | `app/profile/[id]/page.js` | Bio rendered as unsanitised markdown ✅ |
| V-WEB-07 | 79 | `app/profile/[id]/page.js` | `?avatar=` / `?website=` accept `javascript:` ✅ |
| V-WEB-08 | 359 | `app/profile/[id]/page.js` | SSN, balance and private notes rendered ✅ |
| V-WEB-09 | 89 | `app/login/page.js` | Login form drives the concatenated query ✅ |
| V-WEB-10 | 598 | `app/login/page.js` | Credentials also accepted over GET ✅ |
| V-WEB-11 | 1004 | `app/login/page.js` | Resulting cookie readable from JS ✅ |
| V-WEB-12 | 204 | `app/login/page.js` | Distinct errors → user enumeration ✅ |
| V-WEB-13 | 602 | `app/admin/page.js` | Access control only in middleware/UI ✅ |
| V-WEB-14 | 798 | `app/admin/page.js` | Admin key and JWT secret rendered into HTML ✅ |
| V-WEB-15 | 200 | `app/admin/page.js` | Whole user table dumped ✅ |
| V-WEB-16 | 425 | `app/admin/users/page.js` | Forced browsing, no check at all ✅ |

## `apps/web` — API routes

| ID | CWE | Route | Issue |
|---|---|---|---|
| V-API-01 | 89 | `POST/GET /api/login` | SQLi auth bypass ✅ |
| V-API-02 | 327 | `/api/login` | MD5 hashing ✅ |
| V-API-03 | 522/532 | `/api/login` | Plaintext password logged and cached ✅ |
| V-API-04 | 1004 | `/api/login` | Insecure session cookie ✅ |
| V-API-05 | 613 | `/api/login` | Non-expiring JWT ✅ |
| V-API-06 | 307 | `/api/login` | No rate limiting ✅ |
| V-API-07 | 204 | `/api/login` | User enumeration ✅ |
| V-API-08 | 598 | `GET /api/login` | Credentials in the query string ✅ |
| V-API-09 | 639 | `GET /api/users/[id]` | IDOR ✅ |
| V-API-10 | 915 | `PATCH /api/users/[id]` | Mass assignment — self-promote to admin ✅ |
| V-API-11 | 1321 | `PATCH /api/users/[id]` | Patch merged with `lodash.merge` ✅ |
| V-API-12 | 359 | `/api/users/[id]` | PII returned and logged ✅ |
| V-API-13 | 284 | `DELETE /api/users/[id]` | No authorisation |
| V-API-14 | 78 | `GET /api/ping` | Command injection ✅ |
| V-API-15 | 209 | `GET /api/ping` | Executed command echoed back ✅ |
| V-API-16 | 22 | `GET /api/files` | Path traversal on read ✅ |
| V-API-17 | 73 | `POST /api/files` | Externally controlled write path |
| V-API-18 | 209 | `/api/files` | Absolute paths and `process.env` in the error body ✅ |
| V-API-19 | 918 | `GET /api/fetch` | SSRF, incl. a caller-supplied base URL ✅ |
| V-API-20 | 295 | `GET /api/fetch` | TLS verification disabled |
| V-API-21 | 200 | `GET /api/fetch` | Upstream headers proxied back ✅ |
| V-API-22 | 601 | `GET /api/redirect` | Open redirect ✅ |
| V-API-23 | 1022 | `GET /api/redirect` | Unsafe cross-origin handoff |
| V-API-24 | 95 | `POST/GET /api/calc` | `eval()` → RCE ✅ |
| V-API-25 | 94 | `POST /api/calc` | `new Function()` → RCE |
| V-API-26 | 1336 | `POST/GET /api/render` | SSTI (Handlebars + EJS) ✅ |
| V-API-27 | 79 | `/api/render` | Output returned as `text/html`, unescaped ✅ |
| V-API-28 | 502 | `POST /api/deserialize` | `node-serialize` RCE ✅ |
| V-API-29 | 502 | `POST /api/deserialize` | Unsafe YAML load |
| V-API-30 | 502 | `POST /api/deserialize` | "Encrypted" session is just base64 |
| V-API-31 | 1321 | `POST /api/config` | Prototype pollution ✅ (see the DoS note in the README) |
| V-API-32 | 915 | `POST /api/config` | Server settings mass-assigned, shared across requests ✅ |
| V-API-33 | 1333 | `POST /api/config` | ReDoS on `notifyEmail` |
| V-API-34 | 434 | `POST /api/upload` | No extension, MIME, magic-byte or size check |
| V-API-35 | 22 | `POST /api/upload` | Traversal in the filename, plus zip-slip on `entries` |
| V-API-36 | 732 | `POST /api/upload` | Files written `0777` |
| V-API-37 | 284 | `POST /api/upload` | Unauthenticated |
| V-API-38 | 89 | `/api/admin/query` | Arbitrary SQL over HTTP ✅ |
| V-API-39 | 306 | `/api/admin/query` | Runs the query even when unauthorised ✅ |
| V-API-40 | 285 | `/api/admin/query` | `x-user-role: admin` is sufficient ✅ |
| V-API-41 | 208 | `/api/admin/query` | API key compared non-constant-time |
| V-API-42 | 215 | `GET /api/debug` | Debug endpoint always enabled ✅ |
| V-API-43 | 200 | `GET /api/debug` | `process.env`, DB creds, third-party keys ✅ |
| V-API-44 | 532 | `GET /api/debug` | Plaintext credential cache dumped ✅ |
| V-API-45 | 611 | `POST /api/import` | Untrusted XML parsed with `xml2js@0.4.19` |
| V-API-46 | 1321 | `POST /api/import` | Parsed XML merged, carrying prototype keys |
| V-API-47 | 943 | `GET /api/import` | Table name and predicate both from the URL |

## Shared / configuration

| ID | CWE | Location | Issue |
|---|---|---|---|
| V-LIB-01 | 20 | `apps/web/lib/req.js` | No size limit, content-type enforcement or schema validation |
| V-LIB-02 | 942 | `apps/web/lib/req.js` | Every JSON response individually CORS-wildcarded ✅ |
| V-ENV-02 | 200 | `.env.example` | `NEXT_PUBLIC_`-prefixed secret variables → inlined into the browser bundle (names only; values empty) |
| ~~V-ENV-01~~ | ~~798/540~~ | — | **Removed before publishing.** Committed `.env` with secrets. |
| ~~V-ENV-03~~ | ~~798/540~~ | — | **Removed before publishing.** Runtime copy of the committed secrets. |

---

## Dependency CVEs

`npm audit` → **30 advisories: 9 critical, 17 high, 3 moderate, 1 low**.
See the table in [README.md](./README.md#vulnerable-dependencies) for the pinned
versions and why each was chosen. Do not run `npm audit fix`.

---

## Suggested uses

- **SAST benchmarking** — the ID/CWE comments give you ground truth for
  precision and recall. Strip the comments first if you want a blind run.
- **SCA benchmarking** — 30 advisories across direct and transitive deps.
- **Secret scanning** — hardcoded credentials in `packages/auth`
  (`JWT_SECRET`, `ADMIN_API_KEY`) and `packages/db` (`DB_CONFIG`). Note that no
  provider-shaped keys ship in this repo and there is no committed `.env`, so
  this is a weaker target than it was; add throwaway values to a local
  `apps/web/.env` (gitignored) to restore those cases.
- **DAST / manual testing** — `/` links to a live exploit for each class.
- **Training** — each finding has a one-line explanation and a working payload.
