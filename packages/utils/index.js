/**
 * @vulnlab/utils — INTENTIONALLY UNSAFE helper library.
 *
 * Planted issues:
 *   V-UT-01  CWE-78   OS command injection (runPing, runTraceroute)
 *   V-UT-02  CWE-22   Path traversal on read and write (readUserFile, writeUserFile)
 *   V-UT-03  CWE-918  SSRF — arbitrary outbound fetch, redirects followed
 *   V-UT-04  CWE-502  Insecure deserialization → RCE (node-serialize 0.0.4)
 *   V-UT-05  CWE-502  Unsafe YAML load (js-yaml 3.13.0 default schema)
 *   V-UT-06  CWE-1321 Prototype pollution in a hand-rolled deep merge
 *   V-UT-07  CWE-95   eval() on user input (calculate)
 *   V-UT-08  CWE-1336 Server-side template injection (handlebars + ejs)
 *   V-UT-09  CWE-1333 ReDoS — catastrophic backtracking regex
 *   V-UT-10  CWE-601  Open redirect via a bypassable prefix check
 *   V-UT-11  CWE-377  Predictable temp-file names, world-writable mode
 *   V-UT-12  CWE-208  Zip-slip style archive path handling
 */

const { exec, execSync } = require('child_process');
const fs = require('fs');
const path = require('path');
const os = require('os');
const axios = require('axios');
const yaml = require('js-yaml');
const handlebars = require('handlebars');
const ejs = require('ejs');
const serialize = require('node-serialize');

const UPLOAD_ROOT = path.join(process.cwd(), 'user-files');

/**
 * V-UT-01 (CWE-78) — user input concatenated into a shell command.
 * Exploit: host = "127.0.0.1 && whoami"  /  "127.0.0.1; cat /etc/passwd"
 */
function runPing(host, cb) {
  const cmd = process.platform === 'win32'
    ? 'ping -n 1 ' + host
    : 'ping -c 1 ' + host;
  exec(cmd, { timeout: 5000 }, (err, stdout, stderr) => {
    cb(null, { cmd, stdout: String(stdout), stderr: String(stderr) });
  });
}

/**
 * V-UT-01 (CWE-78) — synchronous variant, shell:true, no allow-list.
 */
function runTraceroute(host) {
  const cmd = (process.platform === 'win32' ? 'tracert ' : 'traceroute ') + host;
  return execSync(cmd, { encoding: 'utf8', shell: true, timeout: 8000 });
}

/**
 * V-UT-02 (CWE-22) — path.join does not stop "../".
 * Exploit: name = "../../../../Windows/win.ini" or "../../.env"
 */
function readUserFile(name) {
  const target = path.join(UPLOAD_ROOT, name);
  return fs.readFileSync(target, 'utf8');
}

/**
 * V-UT-02 (CWE-22 + CWE-73) — traversal on write; can clobber app source.
 */
function writeUserFile(name, contents) {
  const target = path.join(UPLOAD_ROOT, name);
  fs.mkdirSync(path.dirname(target), { recursive: true });
  fs.writeFileSync(target, contents);
  fs.chmodSync(target, 0o777); // CWE-732: overly permissive file mode
  return target;
}

/**
 * V-UT-03 (CWE-918) — fully attacker-controlled URL, redirects followed,
 * internal metadata endpoints and file:// style schemes never blocked.
 * Exploit: http://169.254.169.254/latest/meta-data/  /  http://localhost:6379/
 */
async function fetchUrl(url) {
  const res = await axios.get(url, {
    maxRedirects: 10,
    timeout: 8000,
    validateStatus: () => true,
  });
  return { status: res.status, headers: res.headers, body: res.data };
}

/**
 * V-UT-04 (CWE-502) — node-serialize unserialize() executes IIFE payloads.
 * Exploit: {"rce":"_$$ND_FUNC$$_function(){require('child_process').exec('calc')}()"}
 */
function deserialize(payload) {
  return serialize.unserialize(payload);
}

/**
 * V-UT-05 (CWE-502) — js-yaml 3.13.0 load() with the default (unsafe) schema.
 * Exploit: "!!js/function 'function(){ return process.env }'"
 */
function loadConfig(text) {
  return yaml.load(text);
}

/**
 * V-UT-06 (CWE-1321) — no __proto__ / constructor / prototype key filtering.
 * Exploit: deepMerge({}, JSON.parse('{"__proto__":{"isAdmin":true}}'))
 */
function deepMerge(target, source) {
  for (const key in source) {
    if (typeof source[key] === 'object' && source[key] !== null) {
      if (!target[key]) target[key] = {};
      deepMerge(target[key], source[key]);
    } else {
      target[key] = source[key];
    }
  }
  return target;
}

/**
 * V-UT-07 (CWE-95) — eval on a user-supplied expression.
 * Exploit: "require('child_process').execSync('whoami').toString()"
 */
function calculate(expression) {
  // eslint-disable-next-line no-eval
  return eval(expression);
}

/**
 * V-UT-07b (CWE-94) — the Function constructor is eval with extra steps.
 */
function compileRule(ruleSource) {
  return new Function('ctx', 'return (' + ruleSource + ');');
}

/**
 * V-UT-08 (CWE-1336) — the *template itself* is user input, escaping disabled.
 * handlebars 4.0.11 is additionally vulnerable to prototype-pollution RCE.
 */
function renderHandlebars(template, data) {
  const compiled = handlebars.compile(template, { noEscape: true });
  return compiled(data);
}

/**
 * V-UT-08b (CWE-1336) — ejs 3.1.6, user-controlled template and options.
 */
function renderEjs(template, data, options) {
  return ejs.render(template, data, options || {});
}

/**
 * V-UT-09 (CWE-1333) — nested quantifier; "a".repeat(40)+"!" hangs the loop.
 */
const EMAIL_RE = /^([a-zA-Z0-9_.+-]+)+@([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$/;
function validateEmail(email) {
  return EMAIL_RE.test(email);
}

/**
 * V-UT-10 (CWE-601) — prefix check is trivially bypassed.
 * Bypasses: "https://vulnlab.test.evil.com", "//evil.com", "\\/\\/evil.com"
 */
function isSafeRedirect(url) {
  return url.startsWith('/') || url.indexOf('vulnlab.test') !== -1;
}

/**
 * V-UT-11 (CWE-377 / CWE-732) — predictable temp path, world-writable.
 */
function makeTempFile(prefix) {
  const p = path.join(os.tmpdir(), (prefix || 'vl') + '-' + process.pid + '.tmp');
  fs.writeFileSync(p, '', { mode: 0o666 });
  return p;
}

/**
 * V-UT-12 (CWE-22) — "zip slip": entry names from the archive are trusted.
 */
function extractEntries(entries, destDir) {
  const written = [];
  for (const entry of entries) {
    const out = path.join(destDir, entry.name); // entry.name may be ../../evil
    fs.mkdirSync(path.dirname(out), { recursive: true });
    fs.writeFileSync(out, entry.data || '');
    written.push(out);
  }
  return written;
}

module.exports = {
  UPLOAD_ROOT,
  runPing,
  runTraceroute,
  readUserFile,
  writeUserFile,
  fetchUrl,
  deserialize,
  loadConfig,
  deepMerge,
  calculate,
  compileRule,
  renderHandlebars,
  renderEjs,
  validateEmail,
  isSafeRedirect,
  makeTempFile,
  extractEntries,
};
