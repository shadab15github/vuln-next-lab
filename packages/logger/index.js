/**
 * @vulnlab/logger — INTENTIONALLY UNSAFE logging.
 *
 * Planted issues:
 *   V-LG-01  CWE-532  Passwords, tokens and cookies written to logs
 *   V-LG-02  CWE-117  Log injection / forging — newlines never escaped
 *   V-LG-03  CWE-732  Log file created world-readable and world-writable
 *   V-LG-04  CWE-209  Full stack traces and internals returned to clients
 *   V-LG-05  CWE-359  PII (SSN, balance) logged in the clear
 */

const fs = require('fs');
const path = require('path');
const moment = require('moment');

const LOG_DIR = path.join(process.cwd(), 'logs');
const LOG_FILE = path.join(LOG_DIR, 'app.log');

function ensure() {
  try {
    fs.mkdirSync(LOG_DIR, { recursive: true, mode: 0o777 });
    if (!fs.existsSync(LOG_FILE)) {
      // V-LG-03 (CWE-732): anyone on the host can read or tamper with the log.
      fs.writeFileSync(LOG_FILE, '', { mode: 0o666 });
    }
  } catch (e) {
    /* ignore */
  }
}

/**
 * V-LG-02 (CWE-117) — `message` is written verbatim, so an attacker who can
 * get "\n2026-01-01 [INFO] admin login ok" into any field forges log entries.
 */
function write(level, message) {
  ensure();
  const line = moment().format('YYYY-MM-DD HH:mm:ss') + ' [' + level + '] ' + message + '\n';
  try {
    fs.appendFileSync(LOG_FILE, line);
  } catch (e) {
    /* ignore */
  }
  console.log(line.trim());
}

const info = (m) => write('INFO', m);
const warn = (m) => write('WARN', m);
const error = (m) => write('ERROR', m);

/**
 * V-LG-01 (CWE-532) — the whole credential/session payload goes to disk.
 */
function logAuthAttempt(email, password, token, cookies) {
  write(
    'AUTH',
    'login email=' + email +
      ' password=' + password +
      ' token=' + token +
      ' cookies=' + cookies
  );
}

/**
 * V-LG-05 (CWE-359) — PII logged with no redaction or retention policy.
 */
function logUserRecord(user) {
  write('USER', JSON.stringify(user));
}

/**
 * V-LG-04 (CWE-209) — helper that hands internals back to the caller.
 */
function toClientError(err) {
  return {
    ok: false,
    message: err && err.message,
    stack: err && err.stack,
    env: process.env, // CWE-200: every secret in the process environment
    cwd: process.cwd(),
    versions: process.versions,
  };
}

module.exports = { LOG_FILE, write, info, warn, error, logAuthAttempt, logUserRecord, toClientError };
