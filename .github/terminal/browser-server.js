#!/usr/bin/env node
/*
 * Local address browser backend for the persistent terminal.
 *
 * Runs on the host, bound to loopback, behind nginx at /browser/.  All app traffic is sent through
 * local-agent.js inside the dev container, which is the only way to reach services that bind to the
 * container's own 127.0.0.1.  The agent is authenticated with a boot-generated token; this server
 * listens only on 127.0.0.1 and nginx enforces the terminal password.
 *
 * The public proof is intentionally a path prefix (/browser/p/<port>/), not a full web proxy.  HTML
 * and CSS absolute URLs are rewritten, while browser-runtime.js covers network APIs and dynamic DOM
 * changes.  The iframe is same-origin with the rest of the terminal, so only open apps you trust.
 *
 * No dependencies: Node 18+ only.
 */
'use strict';

const http = require('http');
const https = require('https');
const net = require('net');
const tls = require('tls');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const zlib = require('zlib');
const { URL } = require('url');

const arg = (name, def) => {
  const i = process.argv.indexOf('--' + name);
  return i > -1 && process.argv[i + 1] ? process.argv[i + 1] : def;
};

const PORT = parseInt(arg('port', '7704'), 10);
const HOST = arg('host', '127.0.0.1');
const AGENT_HOST = arg('agent-host', '127.0.0.1');
const AGENT_PORT = parseInt(arg('agent-port', '7705'), 10);
const TOKEN_FILE = arg('token-file', '');
const INDEX = arg('html', path.join(__dirname, 'browser.html'));
const RUNTIME_FILE = arg('runtime', path.join(__dirname, 'browser-runtime.js'));
const TOKEN = TOKEN_FILE ? fs.readFileSync(TOKEN_FILE, 'utf8').trim() : (process.env.LOCAL_AGENT_TOKEN || '');
const MAX_TEXT = 12 * 1024 * 1024;
const MAX_AGENT_LINE = 2 * 1024 * 1024;
const SESSION = crypto.randomBytes(24).toString('hex');
const SESSION_COOKIE = '__browser_session';
const SESSION_MAX_AGE = 12 * 60 * 60;

if (!TOKEN || TOKEN.length < 16) {
  console.error('[browser] missing agent token');
  process.exit(1);
}

let INDEX_HTML;
let RUNTIME;
try {
  INDEX_HTML = fs.readFileSync(INDEX, 'utf8');
  RUNTIME = fs.readFileSync(RUNTIME_FILE, 'utf8');
} catch (err) {
  console.error('[browser] cannot read UI/runtime: ' + err.message);
  process.exit(1);
}

/* ------------------------------------------------------------------ small helpers */

const hopByHop = new Set([
  'connection', 'keep-alive', 'proxy-authenticate', 'proxy-authorization', 'te', 'trailer',
  'transfer-encoding', 'upgrade',
]);
const stripResponse = new Set([
  'content-security-policy', 'content-security-policy-report-only', 'x-frame-options',
  'cross-origin-opener-policy', 'cross-origin-embedder-policy', 'cross-origin-resource-policy',
  'strict-transport-security', 'alt-svc', 'public-key-pins', 'report-to', 'reporting-endpoints',
]);
const localHost = host => {
  const h = String(host || '').toLowerCase().replace(/^\[|\]$/g, '');
  return h === 'localhost' || h === '127.0.0.1' || h === '::1' || h === '0.0.0.0' ||
    /^127\./.test(h) || /\.localhost$/.test(h);
};
const validPort = n => Number.isInteger(n) && n >= 1 && n <= 65535;
const isText = type => /^text\/html\b|^application\/xhtml\+xml\b|^text\/css\b/i.test(String(type || ''));
const isHtml = type => /^text\/html\b|^application\/xhtml\+xml\b/i.test(String(type || ''));
const isCss = type => /^text\/css\b/i.test(String(type || ''));

function protocolFor(req) {
  const xf = String(req.headers['x-forwarded-proto'] || '').split(',')[0].trim().toLowerCase();
  return xf === 'https' || xf === 'wss' || req.socket.encrypted ? 'https' : 'http';
}

function parseCookies(header) {
  const out = new Map();
  if (!header) return out;
  for (const part of String(header).split(';')) {
    const i = part.indexOf('=');
    if (i < 0) continue;
    const k = part.slice(0, i).trim();
    if (!k) continue;
    out.set(k, part.slice(i + 1).trim());
  }
  return out;
}

function sessionOk(req) {
  const value = parseCookies(req.headers.cookie).get(SESSION_COOKIE);
  if (!value) return false;
  const a = Buffer.from(value);
  const b = Buffer.from(SESSION);
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}

function sessionCookie(req) {
  const secure = protocolFor(req) === 'https';
  // Path=/ is deliberate: an app can request an absolute /asset.js through the catch-all fallback,
  // and a /browser/-scoped cookie would not be sent on that path.  The value stays HttpOnly; nginx
  // never forwards it to the app origin.
  return `${SESSION_COOKIE}=${SESSION}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${SESSION_MAX_AGE}` +
    (secure ? '; Secure' : '');
}

function send(res, code, body, type = 'text/plain; charset=utf-8', extra = {}) {
  const buf = Buffer.isBuffer(body) ? body : Buffer.from(String(body));
  res.writeHead(code, Object.assign({
    'Content-Type': type,
    'Content-Length': buf.length,
    'Cache-Control': 'no-store',
    'X-Content-Type-Options': 'nosniff',
  }, extra));
  res.end(buf);
}

function json(res, code, obj, extra) {
  send(res, code, JSON.stringify(obj), 'application/json; charset=utf-8', extra);
}

function readTokenFile() {
  try { return fs.readFileSync(TOKEN_FILE, 'utf8').trim(); } catch { return TOKEN; }
}

/* ------------------------------------------------------------------ agent protocol */

function agentCommand(line, timeout = 5000) {
  return new Promise((resolve, reject) => {
    if (!validPort(AGENT_PORT)) return reject(new Error('invalid agent port'));
    const socket = net.connect({ host: AGENT_HOST, port: AGENT_PORT });
    let buf = Buffer.alloc(0);
    let settled = false;
    const timer = setTimeout(() => fail(new Error('agent timeout')), timeout);
    const cleanup = () => {
      clearTimeout(timer);
      socket.removeListener('data', onData);
      socket.removeListener('error', onError);
    };
    const fail = err => {
      if (settled) return;
      settled = true;
      cleanup();
      socket.destroy();
      reject(err);
    };
    const onError = err => fail(err);
    const onData = chunk => {
      if (settled) return;
      buf = Buffer.concat([buf, chunk]);
      if (buf.length > MAX_AGENT_LINE) return fail(new Error('agent response too large'));
      const nl = buf.indexOf(0x0a);
      if (nl < 0) return;
      const text = buf.subarray(0, nl).toString('utf8').replace(/\r$/, '');
      const rest = buf.subarray(nl + 1);
      if (text === 'OK' || text === 'PONG') {
        settled = true;
        cleanup();
        resolve({ socket, rest, line: text });
      } else if (text.startsWith('PORTS ')) {
        settled = true;
        cleanup();
        socket.end();
        let list = [];
        try { list = JSON.parse(text.slice(6)); } catch { /* empty */ }
        resolve({ list });
      } else if (text.startsWith('ERR ')) {
        fail(new Error(text.slice(4) || 'agent error'));
      } else {
        fail(new Error('bad agent response'));
      }
    };
    socket.once('connect', () => socket.write(line + '\n'));
    socket.once('error', onError);
    socket.on('data', onData);
  });
}

function agentPorts() {
  return agentCommand(`PORTS ${readTokenFile()}`).then(r => r.list || []);
}

function agentPing() {
  return agentCommand(`PING ${readTokenFile()}`, 2000).then(() => true, () => false);
}

function connectTarget(port, secure, cb) {
  if (!validPort(port)) return cb(new Error('invalid target port'));
  agentCommand(`CONNECT ${port} ${readTokenFile()}`).then(({ socket, rest }) => {
    if (rest && rest.length) socket.unshift(rest);
    socket.setTimeout(0);
    socket.setNoDelay(true);
    if (!secure) return cb(null, socket);
    const secureSocket = tls.connect({
      socket,
      servername: 'localhost',
      rejectUnauthorized: false,
    });
    let done = false;
    const finish = err => {
      if (done) return;
      done = true;
      secureSocket.removeListener('error', onError);
      if (err) { secureSocket.destroy(); return cb(err); }
      cb(null, secureSocket);
    };
    const onError = err => finish(err);
    secureSocket.once('error', onError);
    secureSocket.once('secureConnect', () => finish(null));
  }).catch(cb);
}

/* ------------------------------------------------------------------ URL mapping */

function routePrefix(port, secure) {
  return `/browser/${secure ? 's' : 'p'}/${port}/`;
}

function targetOrigin(port, secure) {
  return `${secure ? 'https' : 'http'}://localhost:${port}`;
}

function mapUrlValue(value, port, secure) {
  const s = String(value);
  if (!s || s.charAt(0) === '#' || s.charAt(0) === '?') return s;
  if (/^(?:data|blob|mailto|tel|javascript|about|chrome|file):/i.test(s)) return s;
  if (s.charAt(0) === '/') {
    if (s.charAt(1) === '/') {
      try {
        const u = new URL('http:' + s);
        if (localHost(u.hostname)) return mapParsedUrl(u, port, secure);
      } catch { /* leave */ }
      return s;
    }
    if (s === routePrefix(port, secure).slice(0, -1) || s.startsWith('/browser/')) return s;
    return routePrefix(port, secure) + s.slice(1);
  }
  if (/^https?:\/\//i.test(s)) {
    try {
      const u = new URL(s);
      if (localHost(u.hostname)) return mapParsedUrl(u, port, secure);
    } catch { /* leave */ }
  }
  return s;
}

function mapParsedUrl(u, port, secure) {
  const p = parseInt(u.port || (u.protocol === 'https:' ? '443' : '80'), 10);
  const sec = u.protocol === 'https:';
  const route = routePrefix(p, sec);
  if (p === port && sec === secure) return route + u.pathname.replace(/^\//, '') + u.search + u.hash;
  return route + u.pathname.replace(/^\//, '') + u.search + u.hash;
}

function mapSrcset(value, port, secure) {
  return String(value).split(',').map(part => {
    const m = part.match(/^(\s*)(\S+)([\s\S]*)$/);
    return m ? m[1] + mapUrlValue(m[2], port, secure) + m[3] : part;
  }).join(',');
}

function rewriteCss(css, port, secure) {
  let out = String(css);
  out = out.replace(/url\(\s*(['"]?)([\s\S]*?)\1\s*\)/gi, (m, q, value) => {
    const mapped = mapUrlValue(value, port, secure);
    return 'url(' + q + mapped + q + ')';
  });
  out = out.replace(/(@import\s+)(['"])([^'"]+)\2/gi, (m, pre, q, value) =>
    pre + q + mapUrlValue(value, port, secure) + q);
  return out;
}

function rewriteHtml(html, port, secure, secureOuter) {
  let out = String(html);

  // A page CSP would block the injected runtime or block framing.  Meta CSP/XFO never belongs in
  // this preview, and the response headers are stripped separately.
  out = out.replace(/<meta\b[^>]*http-equiv\s*=\s*(['"]?)(?:content-security-policy|x-frame-options)\1[^>]*>/gi, '');
  out = out.replace(/<meta\b[^>]*name\s*=\s*(['"]?)referrer\1[^>]*>/gi, '');

  // Subresource Integrity would stop matching after CSS/HTML URL rewriting.
  out = out.replace(/\s+integrity\s*=\s*(?:"[^"]*"|'[^']*'|[^\s>]+)/gi, '');

  out = out.replace(/(\s(?:href|src|action|formaction|poster|manifest|data-src|data-href)\s*=\s*)(["'])([\s\S]*?)\2/gi,
    (m, pre, q, value) => pre + q + mapUrlValue(value, port, secure) + q);
  out = out.replace(/(\s(?:href|src|action|formaction|poster|manifest|data-src|data-href)\s*=\s*)([^\s>"'`=]+)/gi,
    (m, pre, value) => pre + mapUrlValue(value, port, secure));

  out = out.replace(/(\ssrcset\s*=\s*)(["'])([\s\S]*?)\2/gi,
    (m, pre, q, value) => pre + q + mapSrcset(value, port, secure) + q);

  out = out.replace(/(\sstyle\s*=\s*)(["'])([\s\S]*?)\2/gi,
    (m, pre, q, value) => pre + q + rewriteCss(value, port, secure) + q);
  out = out.replace(/(<style\b[^>]*>)([\s\S]*?)(<\/style>)/gi,
    (m, open, css, close) => open + rewriteCss(css, port, secure) + close);

  out = out.replace(/(<meta\b[^>]*http-equiv\s*=\s*(['"]?)refresh\2[^>]*content\s*=\s*)(['"])([\s\S]*?)\3/gi,
    (m, pre, q, content) => pre + q + content.replace(/(url\s*=\s*)(['"]?)([^'";]+)\2/i,
      (x, p, quote, url) => p + quote + mapUrlValue(url, port, secure) + quote) + q);

  const config = JSON.stringify({ port, secure });
  const runtime = RUNTIME.replace(/__BROWSER_CONFIG__/g, config);
  const tag = '<script data-local-browser-runtime>' + runtime + '</script>' +
    '<meta name="referrer" content="same-origin">';
  if (/<head\b[^>]*>/i.test(out)) out = out.replace(/<head\b[^>]*>/i, m => m + tag);
  else if (/<html\b[^>]*>/i.test(out)) out = out.replace(/<html\b[^>]*>/i, m => m + tag);
  else out = tag + out;

  // The runtime is inline; make sure the outer response also asks for same-origin referrers even if
  // the document has an older policy.
  return out;
}

function rewriteLocation(value, port, secure) {
  const s = String(value || '');
  if (!s) return s;
  if (s.charAt(0) === '/') {
    if (s.charAt(1) === '/') {
      try {
        const u = new URL('http:' + s);
        if (localHost(u.hostname)) return mapParsedUrl(u, port, secure);
      } catch { /* leave */ }
      return s;
    }
    return mapUrlValue(s, port, secure);
  }
  if (/^https?:\/\//i.test(s)) {
    try {
      const u = new URL(s);
      if (localHost(u.hostname)) return mapParsedUrl(u, port, secure);
    } catch { /* leave */ }
  }
  return s;
}

function rewriteCookie(value, port, secure, secureOuter) {
  const parts = String(value).split(';');
  const out = [];
  let hadPath = false;
  for (const raw of parts) {
    const part = raw.trim();
    if (!part) continue;
    const eq = part.indexOf('=');
    const key = (eq < 0 ? part : part.slice(0, eq)).trim().toLowerCase();
    if (key === 'domain') continue;
    // A Secure cookie from an HTTPS target cannot be sent by a page whose outer origin is HTTP.
    // Keep the app's flag when the outer page is HTTPS, otherwise drop it for this local preview.
    if (key === 'secure' && !secureOuter) continue;
    if (key === 'path') {
      hadPath = true;
      let p = eq < 0 ? '/' : part.slice(eq + 1).trim();
      const prefix = routePrefix(port, secure);
      if (!p.startsWith(prefix)) {
        p = prefix + p.replace(/^\//, '');
        if (!p) p = prefix;
      }
      out.push('Path=' + p);
      continue;
    }
    out.push(part);
  }
  if (!hadPath) out.push('Path=' + routePrefix(port, secure));
  return out.join('; ');
}

/* ------------------------------------------------------------------ request/response plumbing */

function buildRequestHeaders(req, port, secure, upgrade) {
  const headers = {};
  const targetProto = secure ? 'https' : 'http';
  for (const [key, value] of Object.entries(req.headers)) {
    const k = key.toLowerCase();
    if (hopByHop.has(k) || k === 'host' || k === 'accept-encoding' || k === 'cookie') continue;
    headers[k] = value;
  }
  if (upgrade && req.headers.upgrade) headers.upgrade = req.headers.upgrade;
  if (req.headers.cookie) {
    const kept = String(req.headers.cookie).split(';')
      .map(x => x.trim())
      .filter(x => x && !x.startsWith(SESSION_COOKIE + '='));
    if (kept.length) headers.cookie = kept.join('; ');
  }
  headers.host = `localhost:${port}`;
  headers['x-forwarded-host'] = `localhost:${port}`;
  headers['x-forwarded-proto'] = targetProto;
  headers['x-forwarded-port'] = String(port);
  headers['x-forwarded-prefix'] = routePrefix(port, secure).slice(0, -1);
  headers['x-real-ip'] = req.socket.remoteAddress || '';
  if (req.headers.referer) {
    let refPath = '/';
    try {
      const u = new URL(req.headers.referer);
      const m = u.pathname.match(/^\/browser\/[ps]\/\d+(\/.*)?$/);
      refPath = (m && m[1]) || u.pathname || '/';
      if (refPath.charAt(0) !== '/') refPath = '/' + refPath;
    } catch { /* use / */ }
    headers.referer = targetOrigin(port, secure) + refPath;
  }
  if (req.headers.origin) headers.origin = targetOrigin(port, secure);
  headers['accept-encoding'] = 'identity';
  headers.connection = upgrade ? 'Upgrade' : 'close';
  return headers;
}

function proxyError(res, code, message, port) {
  if (res.headersSent) { try { res.destroy(); } catch {} return; }
  const safePort = validPort(port) ? port : '';
  const body = `<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">` +
    `<meta name="browser-error" content="1"><title>Local app unavailable</title><style>html,body{height:100%;margin:0;background:#000;color:#fff;` +
    `font:13px/1.5 ui-sans-serif,system-ui,sans-serif;display:grid;place-items:center}` +
    `main{width:min(460px,calc(100vw - 40px));padding:24px;border:1px solid rgba(255,255,255,.18)}` +
    `h1{margin:0 0 8px;font-size:15px}p{margin:0;color:rgba(255,255,255,.65);white-space:pre-wrap}` +
    `a{display:inline-block;margin-top:16px;padding:7px 11px;border:1px solid rgba(255,255,255,.34);` +
    `color:#fff;text-decoration:none;border-radius:2px}code{color:#fff}</style>` +
    `<main><h1>Local app is not answering</h1><p>${escapeHtml(message)}</p>` +
    (safePort ? `<p style="margin-top:8px">Target: <code>localhost:${safePort}</code></p>` : '') +
    `<a href="/browser/" target="_top">Back to browser</a></main></html>`;
  send(res, code, body, 'text/html; charset=utf-8');
}

function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}

function collectResponse(up, max, cb) {
  const chunks = [];
  let size = 0;
  let done = false;
  const finish = (err, buf) => {
    if (done) return;
    done = true;
    up.removeListener('data', onData);
    up.removeListener('end', onEnd);
    up.removeListener('error', onError);
    cb(err, buf);
  };
  const onData = chunk => {
    size += chunk.length;
    if (size > max) { up.destroy(); return finish(new Error('response too large')); }
    chunks.push(chunk);
  };
  const onEnd = () => finish(null, Buffer.concat(chunks));
  const onError = err => finish(err);
  up.on('data', onData);
  up.on('end', onEnd);
  up.on('error', onError);
}

function decodeBody(buf, encoding) {
  const enc = String(encoding || '').toLowerCase();
  if (!enc || enc === 'identity') return buf;
  if (enc === 'gzip' || enc === 'x-gzip') return zlib.gunzipSync(buf);
  if (enc === 'deflate') {
    try { return zlib.inflateSync(buf); } catch { return zlib.inflateRawSync(buf); }
  }
  if (enc === 'br') return zlib.brotliDecompressSync(buf);
  throw new Error('unsupported encoding ' + enc);
}

function handleResponse(req, res, up, info) {
  const { port, secure, secureOuter } = info;
  const headers = {};
  for (const [key, value] of Object.entries(up.headers)) {
    const k = key.toLowerCase();
    if (hopByHop.has(k) || stripResponse.has(k)) continue;
    // Keep Content-Encoding for the streaming path so bytes stay consistent.  It is removed
    // below only when the body is decoded and rewritten.
    if (k === 'content-length') continue;
    headers[k] = value;
  }
  if (up.headers.location) headers.location = rewriteLocation(up.headers.location, port, secure);
  if (up.headers.refresh) {
    headers.refresh = String(up.headers.refresh).replace(/(url\s*=\s*)(['"]?)([^'";]+)\2/i,
      (m, pre, q, url) => pre + q + mapUrlValue(url, port, secure) + q);
  }
  if (up.headers['set-cookie']) {
    const raw = Array.isArray(up.headers['set-cookie']) ? up.headers['set-cookie'] : [up.headers['set-cookie']];
    headers['set-cookie'] = raw.map(v => rewriteCookie(v, port, secure, secureOuter));
  }
  if (isHtml(up.headers['content-type'])) {
    headers['referrer-policy'] = 'same-origin';
  }

  const type = up.headers['content-type'];
  const wantsRewrite = (isHtml(type) || isCss(type)) && req.method !== 'HEAD' &&
    up.statusCode !== 204 && up.statusCode !== 304;
  const declared = parseInt(up.headers['content-length'] || '0', 10);
  if (!wantsRewrite || declared > MAX_TEXT) {
    headers['content-length'] = up.headers['content-length'];
    if (!headers['content-length']) delete headers['content-length'];
    res.writeHead(up.statusCode || 502, headers);
    up.pipe(res);
    up.on('error', () => { try { res.destroy(); } catch {} });
    res.on('close', () => { if (!up.destroyed) up.destroy(); });
    return;
  }

  collectResponse(up, MAX_TEXT, (err, raw) => {
    if (err) {
      proxyError(res, 502, 'The local app sent a response that could not be read: ' + err.message, port);
      return;
    }
    let body = raw;
    try { body = decodeBody(raw, up.headers['content-encoding']); }
    catch (e) { proxyError(res, 502, 'The local app used an unsupported compression: ' + e.message, port); return; }
    let text = body.toString('utf8');
    if (isHtml(type)) text = rewriteHtml(text, port, secure, secureOuter);
    else text = rewriteCss(text, port, secure);
    const out = Buffer.from(text, 'utf8');
    delete headers['content-encoding'];
    headers['content-length'] = out.length;
    res.writeHead(up.statusCode || 200, headers);
    res.end(out);
  });
}

function proxyRequest(req, res, port, secure, targetPath, query) {
  if (!sessionOk(req)) {
    return send(res, 401, 'Browser session expired. Open /browser/ and try again.',
      'text/plain; charset=utf-8', { 'Cache-Control': 'no-store' });
  }
  connectTarget(port, secure, (err, socket) => {
    if (err) {
      return proxyError(res, 502, 'Could not connect to the local service: ' + err.message, port);
    }
    const secureOuter = protocolFor(req) === 'https';
    const headers = buildRequestHeaders(req, port, secure, false);
    const module = secure ? https : http;
    // `agent: false` does not use options.createConnection, so hand the already-open tunnel
    // socket to a one-shot Agent.  host/port are only metadata here; the socket is the target.
    const Agent = secure ? https.Agent : http.Agent;
    const agent = new Agent({ keepAlive: false, maxSockets: 1 });
    agent.createConnection = () => socket;
    let upstream;
    try {
      upstream = module.request({
        method: req.method,
        host: 'localhost',
        port,
        path: targetPath + (query || ''),
        headers,
        agent,
      }, up => handleResponse(req, res, up, { port, secure, secureOuter }));
    } catch (e) {
      try { socket.destroy(); } catch {}
      return proxyError(res, 502, 'Could not create the local request: ' + e.message, port);
    }
    upstream.on('error', err => {
      if (!res.headersSent) proxyError(res, 502, 'The local service closed the connection: ' + err.message, port);
      else { try { res.destroy(); } catch {} }
      try { socket.destroy(); } catch {}
      try { agent.destroy(); } catch {}
    });
    upstream.on('close', () => { try { agent.destroy(); } catch {} });
    res.on('close', () => { if (!res.writableEnded) upstream.destroy(); });
    req.on('aborted', () => upstream.destroy());
    req.pipe(upstream);
  });
}

function proxyUpgrade(req, socket, head, port, secure, targetPath, query) {
  if (!sessionOk(req)) {
    socket.write('HTTP/1.1 401 Unauthorized\r\nConnection: close\r\nContent-Length: 0\r\n\r\n');
    return socket.destroy();
  }
  connectTarget(port, secure, (err, target) => {
    if (err) {
      socket.write('HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\nContent-Length: 0\r\n\r\n');
      return socket.destroy();
    }
    const headers = buildRequestHeaders(req, port, secure, true);
    const lines = [`${req.method} ${targetPath}${query || ''} HTTP/1.1`];
    for (const [key, value] of Object.entries(headers)) {
      if (Array.isArray(value)) for (const v of value) lines.push(`${key}: ${v}`);
      else lines.push(`${key}: ${value}`);
    }
    target.write(lines.join('\r\n') + '\r\n\r\n');
    if (head && head.length) target.write(head);
    const close = () => { socket.destroy(); target.destroy(); };
    socket.on('error', close);
    target.on('error', close);
    socket.on('close', close);
    target.on('close', close);
    target.pipe(socket);
    socket.pipe(target);
  });
}

/* ------------------------------------------------------------------ routing helpers */

function splitUrl(raw) {
  const i = raw.indexOf('?');
  return i < 0 ? { path: raw, query: '' } : { path: raw.slice(0, i), query: raw.slice(i) };
}

function refererPort(req) {
  const ref = req.headers.referer;
  if (!ref) return null;
  try {
    const u = new URL(ref);
    const m = u.pathname.match(/^\/browser\/([ps])\/(\d{1,5})(?:\/|$)/);
    if (!m) return null;
    const port = parseInt(m[2], 10);
    if (!validPort(port)) return null;
    return { port, secure: m[1] === 's' };
  } catch { return null; }
}

function fallbackTarget(req) {
  const found = refererPort(req);
  if (!found) return null;
  return found;
}

/* ------------------------------------------------------------------ HTTP server */

const server = http.createServer((req, res) => {
  const raw = req.url || '/';
  const { path: rawPath, query } = splitUrl(raw);

  if (rawPath === '/browser') {
    res.writeHead(301, { Location: '/browser/' + query });
    return res.end();
  }
  if (rawPath === '/browser/' || rawPath === '/browser/index.html') {
    return send(res, 200, INDEX_HTML, 'text/html; charset=utf-8', {
      'Cache-Control': 'no-store', 'Referrer-Policy': 'no-referrer',
    });
  }
  if (rawPath === '/browser/api/health') {
    agentPing().then(ok => json(res, 200, { ok: true, agent: ok }));
    return;
  }
  if (rawPath === '/browser/api/session') {
    return send(res, 200, 'ok', 'text/plain; charset=utf-8', {
      'Set-Cookie': sessionCookie(req), 'Cache-Control': 'no-store',
    });
  }
  if (rawPath === '/browser/api/ports') {
    agentPorts().then(list => {
      const filtered = list.filter(p => validPort(p.port) && p.port !== AGENT_PORT)
        .map(p => ({
          port: p.port,
          address: p.address || '',
          process: p.process ? String(p.process).replace(/\.exe$/i, '') : null,
          pid: p.pid || null,
        }));
      json(res, 200, { ports: filtered });
    }).catch(err => json(res, 502, { error: 'agent unavailable', detail: err.message }));
    return;
  }
  if (rawPath === '/browser/api/check') {
    const u = new URL(raw, 'http://browser.local');
    const port = parseInt(u.searchParams.get('port') || '', 10);
    const secure = u.searchParams.get('tls') === '1';
    if (!validPort(port)) return json(res, 400, { ok: false, error: 'invalid port' });
    connectTarget(port, secure, (err, socket) => {
      if (err) return json(res, 200, { ok: false, error: err.message });
      socket.destroy();
      json(res, 200, { ok: true });
    });
    return;
  }

  const proxy = rawPath.match(/^\/browser\/([ps])\/(\d{1,5})(\/.*)?$/);
  if (proxy) {
    const secure = proxy[1] === 's';
    const port = parseInt(proxy[2], 10);
    if (!validPort(port)) return send(res, 400, 'invalid port');
    const targetPath = proxy[3] || '/';
    if (!proxy[3]) {
      res.writeHead(302, { Location: rawPath + '/' + query });
      return res.end();
    }
    return proxyRequest(req, res, port, secure, targetPath, query);
  }

  if (rawPath.startsWith('/browser/')) {
    return send(res, 404, 'not found');
  }

  // nginx sends unknown-origin paths here.  A page served under /browser/p/<port>/ can request an
  // absolute /asset.js or navigate to /app; use its Referer to find the owning port.  Navigations
  // are redirected back under the prefix so cookies and the runtime stay in effect.  Subresources
  // are proxied in place, which is what makes absolute module/import URLs work.
  const found = fallbackTarget(req);
  if (!found) return send(res, 404, 'not found');
  const dest = req.method === 'GET' || req.method === 'HEAD';
  const fetchDest = String(req.headers['sec-fetch-dest'] || '').toLowerCase();
  const document = dest && /^(document|iframe|frame)$/.test(fetchDest);
  if (document) {
    const prefix = routePrefix(found.port, found.secure);
    res.writeHead(302, { Location: prefix + rawPath.replace(/^\//, '') + query });
    return res.end();
  }
  proxyRequest(req, res, found.port, found.secure, rawPath, query);
});

server.on('upgrade', (req, socket, head) => {
  const raw = req.url || '/';
  const { path: rawPath, query } = splitUrl(raw);
  const proxy = rawPath.match(/^\/browser\/([ps])\/(\d{1,5})(\/.*)?$/);
  if (proxy) {
    const port = parseInt(proxy[2], 10);
    if (!validPort(port)) { socket.destroy(); return; }
    return proxyUpgrade(req, socket, head, port, proxy[1] === 's', proxy[3] || '/', query);
  }
  const found = fallbackTarget(req);
  if (!found) { socket.destroy(); return; }
  proxyUpgrade(req, socket, head, found.port, found.secure, rawPath, query);
});

server.on('error', err => {
  console.error('[browser] ' + err.message);
  process.exit(1);
});

server.listen(PORT, HOST, () => {
  console.log(`[browser] listening on ${HOST}:${PORT} (agent ${AGENT_HOST}:${AGENT_PORT})`);
});

const shutdown = () => {
  server.close(() => process.exit(0));
  setTimeout(() => process.exit(0), 1000).unref();
};
process.on('SIGTERM', shutdown);
process.on('SIGINT', shutdown);
