'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { securityHeaders, buildCsp, inlineScriptHashes, externalScriptUrls } = require('../src/security-headers');

const sha = (s) => `'sha256-${crypto.createHash('sha256').update(s, 'utf8').digest('base64')}'`;

function headersFrom(mw) {
  const set = {};
  let nextCalled = false;
  mw({}, { setHeader: (k, v) => { set[k] = v; } }, () => { nextCalled = true; });
  return { set, nextCalled };
}

test('inlineScriptHashes hashes inline scripts and skips src= scripts', () => {
  const html = '<script>var a = 1;</script>\n<script src="app.js"></script>\n<script type="module">\n  b();\n</script>';
  assert.deepEqual(inlineScriptHashes(html), [sha('var a = 1;'), sha('\n  b();\n')]);
  assert.deepEqual(inlineScriptHashes('<p>no scripts</p>'), []);
});

test('externalScriptUrls lists absolute https script srcs once, and skips our own files', () => {
  const html = '<script src="app.js"></script><script defer src="https://cdn.example/a@1/a.min.js"></script>'
    + '<script src="https://cdn.example/a@1/a.min.js"></script><script src="http://plain.example/b.js"></script>';
  assert.deepEqual(externalScriptUrls(html), ['https://cdn.example/a@1/a.min.js']);
});

test('buildCsp locks down framing, plugins, base and connections', () => {
  const csp = buildCsp(["'sha256-abc'"], ['https://cdn.example/a@1/a.min.js']);
  for (const d of ["default-src 'self'", "frame-ancestors 'none'", "object-src 'none'", "base-uri 'none'", "connect-src 'self'", "form-action 'self'"]) {
    assert.ok(csp.includes(d), d);
  }
  assert.ok(csp.includes("script-src 'self' https://cdn.example/a@1/a.min.js 'sha256-abc';"), csp);
  // never re-opens script execution wholesale
  assert.ok(!/script-src[^;]*'unsafe-inline'/.test(csp));
  assert.ok(!/'unsafe-eval'/.test(csp));
});

test('securityHeaders sets every header and calls next', () => {
  const { set, nextCalled } = headersFrom(securityHeaders());
  assert.ok(nextCalled);
  assert.equal(set['X-Content-Type-Options'], 'nosniff');
  assert.equal(set['X-Frame-Options'], 'DENY');
  assert.equal(set['Referrer-Policy'], 'no-referrer');
  assert.equal(set['Cross-Origin-Opener-Policy'], 'same-origin');
  assert.match(set['Permissions-Policy'], /camera=\(\)/);
  assert.match(set['Content-Security-Policy'], /frame-ancestors 'none'/);
});

test('the shipped pages: every inline script is allowed by hash, and no inline event handler needs one', () => {
  const pub = path.join(__dirname, '..', 'src', 'public');
  const csp = headersFrom(securityHeaders()).set['Content-Security-Policy'];
  for (const page of ['index.html', 'login.html']) {
    const html = fs.readFileSync(path.join(pub, page), 'utf8');
    const hashes = inlineScriptHashes(html);
    assert.ok(hashes.length > 0, `${page} has its inline script`);
    for (const h of hashes) assert.ok(csp.includes(h), `${page}: ${h}`);
    // onclick= & co. are blocked by a hash-based CSP; the UI must not grow any
    assert.ok(!/<[^>]+\son[a-z]+\s*=/i.test(html), `${page} has an inline event handler`);
  }
  // every external script is ours or allowed by its exact URL — never by a
  // bare host (jsdelivr serves anything anyone has published)
  const index = fs.readFileSync(path.join(pub, 'index.html'), 'utf8');
  const scriptSrc = csp.split('; ').find((d) => d.startsWith('script-src ')).split(' ').slice(1);
  let external = 0;
  for (const [, src] of index.matchAll(/<script[^>]*\ssrc="([^"]+)"/g)) {
    if (!/^https?:/.test(src)) continue;
    external++;
    assert.ok(scriptSrc.includes(src), src);
  }
  assert.ok(external >= 2, 'cytoscape and chart.js come from the CDN');
  for (const s of scriptSrc) assert.ok(!/^https?:\/\/[^/]+\/?$/.test(s), `bare host in script-src: ${s}`);
});

test('the hashes follow the files: an edited inline script gets a new hash', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'lanscope-csp-'));
  fs.writeFileSync(path.join(dir, 'a.html'), '<script>one()</script>');
  const before = headersFrom(securityHeaders({ publicDir: dir, pages: ['a.html'] })).set['Content-Security-Policy'];
  fs.writeFileSync(path.join(dir, 'a.html'), '<script>two()</script>');
  const after = headersFrom(securityHeaders({ publicDir: dir, pages: ['a.html'] })).set['Content-Security-Policy'];
  assert.ok(before.includes(sha('one()')) && after.includes(sha('two()')) && !after.includes(sha('one()')));
});
