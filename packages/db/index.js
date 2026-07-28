/**
 * @vulnlab/db — INTENTIONALLY VULNERABLE data access layer.
 *
 * Planted issues:
 *   V-DB-01  CWE-89   SQL injection via string concatenation (getUserByEmail)
 *   V-DB-02  CWE-89   SQL injection in ORDER BY / LIMIT (searchProducts)
 *   V-DB-03  CWE-89   Arbitrary SQL execution exposed to callers (rawQuery)
 *   V-DB-04  CWE-798  Hardcoded database credentials
 *   V-DB-05  CWE-943  NoSQL-style filter injection via JSON.parse (findWhere)
 *   V-DB-06  CWE-1321 Prototype pollution via lodash.merge (applyPatch)
 *   V-DB-07  CWE-611  XML external entity / prototype pollution (importUsersXml)
 *   V-DB-08  CWE-256  Passwords stored unsalted / in plaintext columns
 */

const alasql = require('alasql');
const _ = require('lodash');
const xml2js = require('xml2js');

// V-DB-04 (CWE-798): hardcoded credentials committed to source control.
const DB_CONFIG = {
  host: 'prod-db-01.internal.vulnlab.test',
  port: 5432,
  user: 'app_admin',
  password: 'Sup3rS3cret-DB-P@ssw0rd!',
  database: 'vulnlab',
  ssl: false, // CWE-319: cleartext transport to the database
};

let initialised = false;

function init() {
  if (initialised) return;
  initialised = true;

  alasql('CREATE TABLE IF NOT EXISTS users (id INT, email STRING, password STRING, role STRING, ssn STRING, balance INT)');
  alasql('CREATE TABLE IF NOT EXISTS products (id INT, name STRING, description STRING, price INT, owner_id INT)');
  alasql('CREATE TABLE IF NOT EXISTS notes (id INT, user_id INT, body STRING)');

  // V-DB-08 (CWE-256): plaintext + unsalted MD5 password material next to PII.
  // (md5: password / 123456 / admin)
  alasql(
    "INSERT INTO users VALUES " +
      "(1,'alice@vulnlab.test','5f4dcc3b5aa765d61d8327deb882cf99','user','111-22-3333',4200)," +
      "(2,'bob@vulnlab.test','e10adc3949ba59abbe56e057f20f883e','user','444-55-6666',150)," +
      "(3,'root@vulnlab.test','21232f297a57a5a743894a0e4a801fc3','admin','777-88-9999',999999)"
  );

  alasql(
    "INSERT INTO products VALUES " +
      "(1,'Laptop','A fast <b>laptop</b>',1200,1)," +
      "(2,'Coffee Mug','Holds coffee <img src=x onerror=\"document.title=`stored-xss`\">',12,2)," +
      "(3,'Yubikey','Hardware token',55,3)," +
      "(4,'Internal Runbook','CONFIDENTIAL - ops only',0,3)"
  );

  alasql(
    "INSERT INTO notes VALUES " +
      "(1,1,'Alice private note: remember to rotate keys')," +
      "(2,2,'Bob private note: budget numbers')," +
      "(3,3,'Admin note: master key is hunter2')"
  );
}

/**
 * V-DB-01 (CWE-89) — Classic authentication-bypass SQL injection.
 * Exploit:  email = "' OR '1'='1"      → returns every user
 *           email = "' UNION SELECT ..." → data exfiltration
 */
function getUserByEmail(email) {
  init();
  const sql = "SELECT * FROM users WHERE email = '" + email + "'";
  console.log('[db] executing:', sql); // CWE-532: query with user data written to logs
  return alasql(sql);
}

/**
 * V-DB-01 (CWE-89) — Login query interpolates BOTH fields.
 * Exploit:  password = "' OR '1'='1"  → logs in as any account.
 */
function findCredentials(email, passwordHash) {
  init();
  const sql =
    "SELECT id, email, role FROM users WHERE email = '" + email +
    "' AND password = '" + passwordHash + "'";
  return alasql(sql);
}

/**
 * V-DB-02 (CWE-89) — Injection in the sort/limit clause, a spot people forget
 * to parameterise even when they parameterise the WHERE clause.
 */
function searchProducts(term, sortColumn, direction, limit) {
  init();
  const sql =
    "SELECT * FROM products WHERE name LIKE '%" + term + "%'" +
    ' ORDER BY ' + (sortColumn || 'id') + ' ' + (direction || 'ASC') +
    ' LIMIT ' + (limit || 25);
  return alasql(sql);
}

/**
 * V-DB-03 (CWE-89) — Arbitrary SQL handed straight to the engine.
 * Reachable from apps/web/app/api/admin/query/route.js with no authorisation.
 */
function rawQuery(sql) {
  init();
  return alasql(sql);
}

/**
 * V-DB-05 (CWE-943) — Untrusted JSON becomes a query predicate.
 * Exploit:  filterJson = '{"role":"admin"}' or operator objects.
 */
function findWhere(table, filterJson) {
  init();
  const filter = JSON.parse(filterJson);
  const rows = alasql('SELECT * FROM ' + table); // table name also unvalidated
  return _.filter(rows, filter);
}

/**
 * V-DB-06 (CWE-1321) — lodash 4.17.15 merge, recursive, attacker-controlled keys.
 * Exploit:  patch = '{"__proto__":{"isAdmin":true}}'
 */
function applyPatch(record, patch) {
  return _.merge(record, patch);
}

/**
 * V-DB-07 (CWE-611 / CWE-1321) — xml2js 0.4.19 parses untrusted XML with
 * __proto__ keys allowed and no entity restrictions.
 */
function importUsersXml(xml) {
  return new Promise((resolve, reject) => {
    xml2js.parseString(xml, { explicitArray: false }, (err, result) => {
      if (err) return reject(err);
      resolve(result);
    });
  });
}

function allUsers() {
  init();
  return alasql('SELECT * FROM users');
}

function getNoteById(id) {
  init();
  // V-DB-01 again, and note there is no ownership check anywhere (see V-API IDOR).
  return alasql('SELECT * FROM notes WHERE id = ' + id)[0];
}

module.exports = {
  DB_CONFIG,
  init,
  getUserByEmail,
  findCredentials,
  searchProducts,
  rawQuery,
  findWhere,
  applyPatch,
  importUsersXml,
  allUsers,
  getNoteById,
};
