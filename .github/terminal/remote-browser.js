'use strict';

/*
 * Standalone server-side browser.
 *
 * This file is intentionally independent of browser-server.js, browser-runtime.js and browser.html.
 * It owns the /remote/ origin, a server-side Chrome process, and an MJPEG viewport.  External pages
 * execute only inside Chrome on this machine; the user's browser receives JPEG frames and sends
 * mouse/keyboard commands.  A small loopback egress proxy prevents Chrome from reaching terminal
 * services and private addresses.
 */

const http = require('http');
const net = require('net');
const dns = require('dns');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { URL } = require('url');
const { RemoteChrome } = require('./remote-cdp');

function option(name, fallback) {
  const i = process.argv.indexOf(name);
  if (i >= 0 && i + 1 < process.argv.length) return process.argv[i + 1];
  return fallback;
}

const PORT = Number(option('--port', process.env.REMOTE_PORT || 7706));
const BIND = option('--bind', '127.0.0.1');
const EGRESS_PORT = Number(option('--egress-port', process.env.REMOTE_EGRESS_PORT || 7707));
const HTML_PATH = option('--html', path.join(__dirname, 'remote.html'));
const CHROME_BIN = option('--chrome', process.env.REMOTE_CHROME || '');
const PROFILE = option('--profile', process.env.REMOTE_PROFILE || '/tmp/terminal-remote-profile');
const WIDTH = 1280;
const HEIGHT = 800;
const FRAME_QUALITY = 58;
const CSRF = crypto.randomBytes(24).toString('hex');
const dnsLookup = dns.promises.lookup;

/* ------------------------------------------------------------------ *
 * Egress proxy
 * ------------------------------------------------------------------ */

function parseAuthority(authority, defaultPort) {
  let value = String(authority || '').trim();
  if (!value) throw new Error('Empty authority');
  let host = '';
  let port = defaultPort;
  if (value.startsWith('[')) {
    const end = value.indexOf(']');
    if (end < 0) throw new Error('Invalid IPv6 authority');
    host = value.slice(1, end);
    const rest = value.slice(end + 1);
    if (rest.startsWith(':')) port = Number(rest.slice(1));
  } else {
    const at = value.lastIndexOf(':');
    if (at > 0 && /^\d+$/.test(value.slice(at + 1))) {
      host = value.slice(0, at);
      port = Number(value.slice(at + 1));
    } else {
      host = value;
    }
  }
  if (!host) throw new Error('Empty host');
  if (!Number.isInteger(port) || port < 1 || port > 65535) throw new Error('Invalid port');
  return { host, port };
}

function isPrivateIPv4(ip) {
  const p = ip.split('.').map(Number);
  if (p.length !== 4 || p.some(n => !Number.isInteger(n) || n < 0 || n > 255)) return true;
  const n = (p[0] * 0x1000000) + (p[1] * 0x10000) + (p[2] * 0x100) + p[3];
  const inRange = (base, bits) => {
    const mask = bits === 0 ? 0 : (0xffffffff << (32 - bits)) >>> 0;
    return (n & mask) === (base & mask);
  };
  return (
    inRange(0x00000000, 8) || // unspecified / current network
    inRange(0x0a000000, 8) || // 10/8
    inRange(0x64400000, 10) || // 100.64/10 (carrier-grade NAT)
    inRange(0x7f000000, 8) || // loopback
    inRange(0xa9fe0000, 16) || // link-local / cloud metadata
    inRange(0xac100000, 12) || // 172.16/12
    inRange(0xc0000000, 24) || // 192.0.0/24
    inRange(0xc0000200, 24) || // 192.0.2/24
    inRange(0xc0a80000, 16) || // 192.168/16
    inRange(0xc6120000, 15) || // 198.18/15
    inRange(0xc6336400, 24) || // 198.51.100/24
    inRange(0xcb007100, 24) || // 203.0.113/24
    inRange(0xe0000000, 4) || // multicast
    inRange(0xf0000000, 4) // reserved / broadcast
  );
}

function isPrivateIPv6(ip) {
  // DNS and CONNECT can both use uncompressed IPv6 spelling.  URL normalisation
  // gives us one canonical form before checking the prefix.
  let h = String(ip).toLowerCase();
  try {
    h = new URL('http://[' + h + ']/').hostname.replace(/^\[|\]$/g, '').toLowerCase();
  } catch { /* keep the original string */ }
  if (h === '::' || h === '::1') return true;
  if (/^fe[89ab][0-9a-f]:/.test(h)) return true; // fe80::/10
  if (/^fe[c-f][0-9a-f]:/.test(h)) return true; // deprecated fec0::/10 site-local
  if (/^f[cd][0-9a-f]{2}:/.test(h)) return true; // fc00::/7
  if (/^ff[0-9a-f]{2}:/.test(h)) return true; // ff00::/8
  if (/^2001:db8:/.test(h)) return true; // documentation
  if (/^3fff:/.test(h)) return true; // documentation (RFC 9637)
  if (/^2001::/.test(h)) return true; // Teredo (2001:0000::/32)
  if (/^2001:(?:2|10|20):/.test(h)) return true; // benchmarking / ORCHID
  if (/^2002:/.test(h)) return true; // 6to4 can encode private IPv4
  if (/^64:ff9b:/.test(h)) return true; // NAT64 can encode private IPv4
  if (h.startsWith('::ffff:')) {
    const tail = h.slice(7);
    if (net.isIPv4(tail)) return isPrivateIPv4(tail);
    // ::ffff:7f00:1 and other hexadecimal IPv4-mapped forms are not needed by
    // ordinary browsing; reject them rather than trying to parse all notations.
    return true;
  }
  // IPv4-compatible and other addresses inside ::/96 are never ordinary public
  // destinations.  Rejecting them also closes the ::127.0.0.1 notation gap.
  if (h.startsWith('::')) return true;
  if (/^100::/.test(h)) return true; // discard-only prefix
  return false;
}

function isPrivateIP(ip) {
  const kind = net.isIP(ip);
  if (kind === 4) return isPrivateIPv4(ip);
  if (kind === 6) return isPrivateIPv6(ip);
  return true;
}

function isLocalHostname(host) {
  const h = String(host || '').toLowerCase().replace(/\.$/, '');
  return (
    h === 'localhost' ||
    h === 'localhost.localdomain' ||
    h.endsWith('.localhost') ||
    h.endsWith('.local') ||
    h.endsWith('.internal') ||
    h === 'metadata.google.internal' ||
    h === 'metadata'
  );
}

async function resolvePublic(host) {
  let value = String(host || '').replace(/^\[|\]$/g, '');
  if (!value) throw new Error('Empty host');
  if (isLocalHostname(value)) throw new Error('Local hostnames are blocked in remote mode');
  if (net.isIP(value)) {
    if (isPrivateIP(value)) throw new Error('Private addresses are blocked in remote mode');
    return value;
  }
  let records;
  try {
    records = await dnsLookup(value, { all: true, verbatim: true });
  } catch {
    throw new Error('Could not resolve target host');
  }
  const usable = (records || []).filter(r => !isPrivateIP(r.address));
  if (!usable.length) throw new Error('Target resolves only to private addresses');
  // Prefer IPv4 because it is the most widely reachable path, but both are fine.
  const chosen = usable.find(r => r.family === 4) || usable[0];
  return chosen.address;
}

function proxyError(socket, status, text) {
  try {
    if (socket.writable) {
      socket.write(
        'HTTP/1.1 ' + status + ' ' + text + '\r\n' +
        'Content-Type: text/plain\r\n' +
        'Connection: close\r\n' +
        'Content-Length: ' + Buffer.byteLength(text) + '\r\n\r\n' + text
      );
    }
  } catch { /* ignore */ }
  try { socket.destroy(); } catch { /* ignore */ }
}

function stripProxyHeaders(headers) {
  const out = {};
  for (const [key, value] of Object.entries(headers || {})) {
    const k = key.toLowerCase();
    if (k === 'proxy-connection' || k === 'proxy-authorization') continue;
    out[key] = value;
  }
  return out;
}

function installEgressProxy(port) {
  const server = http.createServer(async (req, res) => {
    let target;
    try {
      target = new URL(req.url);
    } catch {
      res.writeHead(400, { 'Content-Type': 'text/plain' });
      res.end('Bad proxy request');
      return;
    }
    if (target.protocol !== 'http:') {
      res.writeHead(400, { 'Content-Type': 'text/plain' });
      res.end('This proxy only forwards HTTP requests; HTTPS uses CONNECT');
      return;
    }
    try {
      const ip = await resolvePublic(target.hostname);
      const headers = stripProxyHeaders(req.headers);
      headers.host = target.host;
      headers.connection = 'close';
      const options = {
        host: ip,
        port: Number(target.port) || 80,
        method: req.method,
        path: (target.pathname || '/') + (target.search || ''),
        headers,
        timeout: 45000,
      };
      const upstream = http.request(options, upstreamRes => {
        const safeHeaders = { ...upstreamRes.headers };
        delete safeHeaders['alt-svc'];
        try {
          res.writeHead(upstreamRes.statusCode || 502, upstreamRes.statusMessage, safeHeaders);
        } catch {
          upstreamRes.destroy();
          return;
        }
        upstreamRes.pipe(res);
      });
      upstream.on('timeout', () => upstream.destroy(new Error('Target timed out')));
      upstream.on('error', () => {
        if (!res.headersSent) {
          res.writeHead(502, { 'Content-Type': 'text/plain', 'Cache-Control': 'no-store' });
          res.end('Remote target unavailable');
        } else {
          res.destroy();
        }
      });
      req.pipe(upstream);
    } catch (err) {
      res.writeHead(403, { 'Content-Type': 'text/plain', 'Cache-Control': 'no-store' });
      res.end(err.message || 'Blocked');
    }
  });

  server.on('connect', async (req, socket, head) => {
    let authority;
    try {
      authority = parseAuthority(req.url, 443);
    } catch {
      proxyError(socket, 400, 'Bad CONNECT');
      return;
    }
    try {
      const ip = await resolvePublic(authority.host);
      const upstream = net.connect({ host: ip, port: authority.port });
      upstream.setTimeout(45000, () => upstream.destroy(new Error('Target timed out')));
      upstream.once('connect', () => {
        upstream.setTimeout(0);
        try { socket.write('HTTP/1.1 200 Connection Established\r\n\r\n'); } catch { upstream.destroy(); return; }
        if (head && head.length) upstream.write(head);
        upstream.pipe(socket);
        socket.pipe(upstream);
      });
      upstream.once('error', () => proxyError(socket, 502, 'Remote target unavailable'));
      socket.once('error', () => upstream.destroy());
      socket.once('close', () => upstream.destroy());
    } catch (err) {
      proxyError(socket, 403, err.message || 'Blocked');
    }
  });

  // WebSocket and other HTTP Upgrade requests sent to an HTTP proxy use an
  // absolute request URL.  Forward them without letting Chrome see the proxy.
  server.on('upgrade', async (req, socket, head) => {
    let target;
    try {
      target = new URL(req.url);
      if (target.protocol !== 'http:' && target.protocol !== 'https:') throw new Error('Bad scheme');
    } catch {
      socket.destroy();
      return;
    }
    try {
      const ip = await resolvePublic(target.hostname);
      const targetPort = Number(target.port) || (target.protocol === 'https:' ? 443 : 80);
      const upstream = net.connect({ host: ip, port: targetPort }, () => {
        const pathPart = (target.pathname || '/') + (target.search || '');
        const lines = [];
        lines.push(req.method + ' ' + pathPart + ' HTTP/1.1');
        const headers = stripProxyHeaders(req.headers);
        headers.host = target.host;
        headers.connection = 'Upgrade';
        for (const [key, value] of Object.entries(headers)) {
          if (Array.isArray(value)) for (const v of value) lines.push(key + ': ' + v);
          else lines.push(key + ': ' + value);
        }
        upstream.write(lines.join('\r\n') + '\r\n\r\n');
        if (head && head.length) upstream.write(head);
        upstream.pipe(socket);
        socket.pipe(upstream);
      });
      upstream.once('error', () => socket.destroy());
      socket.once('error', () => upstream.destroy());
      socket.once('close', () => upstream.destroy());
    } catch {
      socket.destroy();
    }
  });

  server.on('error', err => {
    console.error('[remote] egress proxy:', err.message);
    // Without the filtering proxy the remote browser must not run: it would be
    // able to reach terminal loopback services directly.
    process.exit(1);
  });
  server.listen(port, '127.0.0.1', () => {
    console.log('[remote] egress proxy on 127.0.0.1:' + port);
  });
  return server;
}

/* ------------------------------------------------------------------ *
 * Chrome lifecycle
 * ------------------------------------------------------------------ */

let chrome = null;
let chromeStarting = null;
let lastChromeError = '';
let chromeRetryAt = 0;

function chromeOptions() {
  return {
    bin: CHROME_BIN,
    proxyPort: EGRESS_PORT,
    profile: PROFILE,
    width: WIDTH,
    height: HEIGHT,
    quality: FRAME_QUALITY,
  };
}

async function ensureChrome() {
  if (chrome && chrome.ready && !chrome.closed) return chrome;
  if (chromeStarting) return chromeStarting;
  if (Date.now() < chromeRetryAt) throw new Error(lastChromeError || 'Chrome is restarting');
  chromeStarting = (async () => {
    if (!CHROME_BIN) throw new Error('No Chrome binary configured');
    if (chrome) {
      try { await chrome.stop(); } catch { /* ignore */ }
      chrome = null;
    }
    const next = new RemoteChrome(chromeOptions());
    next.on('closed', () => {
      if (chrome === next) chrome = null;
    });
    next.on('error', err => {
      lastChromeError = err.message;
      console.error('[remote] page:', err.message);
    });
    try {
      await next.start();
      chrome = next;
      lastChromeError = '';
      chromeRetryAt = 0;
      return next;
    } catch (err) {
      lastChromeError = err.message;
      chromeRetryAt = Date.now() + 5000;
      try { await next.stop(); } catch { /* ignore */ }
      throw err;
    }
  })().finally(() => { chromeStarting = null; });
  return chromeStarting;
}

/* ------------------------------------------------------------------ *
 * UI and API server
 * ------------------------------------------------------------------ */

const frameClients = new Set();
let lastFrame = null;
let lastFrameAt = 0;
let captureInFlight = false;
let snapshotInFlight = null;

function frameHeaders(res) {
  res.writeHead(200, {
    'Content-Type': 'multipart/x-mixed-replace; boundary=frame',
    'Cache-Control': 'no-store, no-cache, must-revalidate, max-age=0',
    'Pragma': 'no-cache',
    'X-Accel-Buffering': 'no',
    'Connection': 'keep-alive',
    'X-Content-Type-Options': 'nosniff',
  });
  if (typeof res.flushHeaders === 'function') res.flushHeaders();
}

function writeFrame(res, jpg) {
  if (res.destroyed || res.writableEnded) return false;
  if (res._remoteDraining) return true;
  try {
    res.write('--frame\r\n');
    res.write('Content-Type: image/jpeg\r\n');
    res.write('Content-Length: ' + jpg.length + '\r\n\r\n');
    res.write(jpg);
    const ok = res.write('\r\n');
    if (!ok) {
      res._remoteDraining = true;
      res.once('drain', () => { res._remoteDraining = false; });
    }
    return true;
  } catch {
    return false;
  }
}

async function frameLoop() {
  if (!frameClients.size || captureInFlight) return;
  captureInFlight = true;
  try {
    const c = await ensureChrome();
    const jpg = await c.screenshot();
    if (jpg && jpg.length) {
      lastFrame = jpg;
      lastFrameAt = Date.now();
      for (const res of frameClients) {
        if (res.destroyed || res.writableEnded) {
          frameClients.delete(res);
          continue;
        }
        writeFrame(res, jpg);
      }
    }
  } catch {
    // Chrome may still be starting or navigating.  Keep streams open and retry.
  } finally {
    captureInFlight = false;
  }
}

function json(res, status, data) {
  const body = Buffer.from(JSON.stringify(data));
  res.writeHead(status, {
    'Content-Type': 'application/json; charset=utf-8',
    'Cache-Control': 'no-store',
    'X-Content-Type-Options': 'nosniff',
  });
  res.end(body);
}

function readJson(req, limit = 16384) {
  return new Promise((resolve, reject) => {
    let size = 0;
    const chunks = [];
    req.on('data', chunk => {
      size += chunk.length;
      if (size > limit) {
        reject(new Error('Request body too large'));
        req.destroy();
        return;
      }
      chunks.push(chunk);
    });
    req.on('end', () => {
      if (!chunks.length) return resolve({});
      try { resolve(JSON.parse(Buffer.concat(chunks).toString('utf8'))); }
      catch { reject(new Error('Invalid JSON')); }
    });
    req.on('error', reject);
  });
}

function csrfOk(req) {
  return String(req.headers['x-remote-csrf'] || '') === CSRF;
}

function normaliseTarget(input) {
  let value = String(input || '').trim();
  if (!value) throw new Error('Address is empty');
  if (value.length > 8192) throw new Error('Address is too long');
  // "example.com:8080" must be treated as a host and port, not as a custom
  // scheme.  Bracket-less IPv6 input is intentionally left to the URL parser
  // and will be rejected like any other invalid address.
  const explicitScheme = /^[a-z][a-z0-9+.-]*:\/\//i.test(value);
  const hostWithPort = /^(?:\[[0-9a-f:.]+\]|[^/?#:]+):\d+(?:[/?#]|$)/i.test(value);
  if (!explicitScheme && (!/^[a-z][a-z0-9+.-]*:/i.test(value) || hostWithPort)) {
    value = 'https://' + value;
  }
  let url;
  try { url = new URL(value); } catch { throw new Error('Invalid address'); }
  if (url.protocol !== 'http:' && url.protocol !== 'https:') throw new Error('Only http and https are supported');
  if (url.username || url.password) throw new Error('Credentials in the address are not supported');
  if (!url.hostname) throw new Error('Address has no host');
  if (isLocalHostname(url.hostname)) throw new Error('Local addresses belong in /browser/, not the remote browser');
  return url;
}

async function stateFor(c) {
  const state = await c.state();
  return state;
}

async function handleApi(req, res, pathname) {
  if (req.method === 'GET' && pathname === '/remote/api/health') {
    try {
      const c = await ensureChrome();
      return json(res, 200, {
        ok: true,
        chrome: true,
        url: c.url,
        title: c.title,
        lastError: lastChromeError || '',
        frameAge: lastFrameAt ? Date.now() - lastFrameAt : null,
      });
    } catch (err) {
      return json(res, 503, { ok: false, chrome: false, error: lastChromeError || err.message });
    }
  }

  if (req.method === 'GET' && pathname === '/remote/api/state') {
    try {
      const c = await ensureChrome();
      const state = await stateFor(c);
      state.frameAge = lastFrameAt ? Date.now() - lastFrameAt : null;
      return json(res, 200, state);
    } catch (err) {
      return json(res, 503, { ok: false, error: lastChromeError || err.message });
    }
  }

  // Snapshot fallback for networks or proxies that buffer a long-lived MJPEG
  // response.  The normal path is still the multipart stream above.
  if (req.method === 'GET' && pathname === '/remote/api/snapshot') {
    try {
      const c = await ensureChrome();
      if (!snapshotInFlight) {
        snapshotInFlight = c.screenshot().finally(() => { snapshotInFlight = null; });
      }
      const jpg = await snapshotInFlight;
      res.writeHead(200, {
        'Content-Type': 'image/jpeg',
        'Content-Length': jpg.length,
        'Cache-Control': 'no-store, no-cache, must-revalidate, max-age=0',
        'Pragma': 'no-cache',
        'X-Content-Type-Options': 'nosniff',
      });
      return res.end(jpg);
    } catch (err) {
      return json(res, 503, { ok: false, error: lastChromeError || err.message });
    }
  }

  if (req.method !== 'POST') {
    return json(res, 405, { ok: false, error: 'Method not allowed' });
  }
  if (!csrfOk(req)) {
    return json(res, 403, { ok: false, error: 'Invalid request token' });
  }

  let body;
  try { body = await readJson(req); }
  catch (err) { return json(res, 400, { ok: false, error: err.message }); }

  try {
    const c = await ensureChrome();

    if (pathname === '/remote/api/navigate') {
      const target = normaliseTarget(body.url);
      await resolvePublic(target.hostname);
      await c.navigate(target.href);
      return json(res, 200, await stateFor(c));
    }
    if (pathname === '/remote/api/back') {
      await c.back();
      return json(res, 200, await stateFor(c));
    }
    if (pathname === '/remote/api/forward') {
      await c.forward();
      return json(res, 200, await stateFor(c));
    }
    if (pathname === '/remote/api/reload') {
      await c.reload();
      return json(res, 200, await stateFor(c));
    }
    if (pathname === '/remote/api/home') {
      await c.home();
      return json(res, 200, await stateFor(c));
    }
    if (pathname === '/remote/api/mouse') {
      await c.mouse(body);
      return json(res, 200, { ok: true });
    }
    if (pathname === '/remote/api/key') {
      if (body.type === 'text') await c.text(body.text);
      else await c.key(body);
      return json(res, 200, { ok: true });
    }
    return json(res, 404, { ok: false, error: 'Unknown API' });
  } catch (err) {
    return json(res, 400, { ok: false, error: err.message || 'Request failed' });
  }
}

async function handle(req, res) {
  let pathname;
  try { pathname = new URL(req.url, 'http://remote.local').pathname; }
  catch { return json(res, 400, { ok: false, error: 'Bad request' }); }

  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('Referrer-Policy', 'no-referrer');
  res.setHeader('Cross-Origin-Resource-Policy', 'same-origin');

  if (pathname === '/remote' || pathname === '/remote/') {
    if (req.method !== 'GET') return json(res, 405, { ok: false, error: 'Method not allowed' });
    let html;
    try {
      html = fs.readFileSync(HTML_PATH, 'utf8');
      if (!html.includes('__REMOTE_CSRF__')) throw new Error('Remote page template is missing its request token');
    } catch (err) {
      return json(res, 500, { ok: false, error: err.message });
    }
    const body = Buffer.from(html.replace(/__REMOTE_CSRF__/g, CSRF));
    res.writeHead(200, {
      'Content-Type': 'text/html; charset=utf-8',
      'Cache-Control': 'no-store, no-cache, must-revalidate',
      'Content-Security-Policy': [
        "default-src 'self'",
        "img-src 'self' data:",
        "style-src 'self' 'unsafe-inline'",
        "script-src 'self' 'unsafe-inline'",
        "connect-src 'self'",
        "base-uri 'none'",
        "form-action 'self'",
        "frame-ancestors 'none'",
      ].join('; '),
      'X-Frame-Options': 'DENY',
      'Cross-Origin-Opener-Policy': 'same-origin',
      'Permissions-Policy': 'camera=(), microphone=(), geolocation=(), payment=(), usb=()',
    });
    res.end(body);
    return;
  }

  if (pathname === '/remote/frame') {
    if (req.method !== 'GET') return json(res, 405, { ok: false, error: 'Method not allowed' });
    if (frameClients.size >= 4) return json(res, 429, { ok: false, error: 'Too many viewers' });
    frameClients.add(res);
    frameHeaders(res);
    // Only use the cached frame when it is very fresh; otherwise wait for the
    // capture loop instead of presenting a picture of a page that has changed.
    if (lastFrame && lastFrameAt && Date.now() - lastFrameAt < 1500) writeFrame(res, lastFrame);
    req.on('close', () => frameClients.delete(res));
    res.on('close', () => frameClients.delete(res));
    return;
  }

  if (pathname.startsWith('/remote/api/')) {
    return handleApi(req, res, pathname);
  }

  if (pathname === '/favicon.ico' || pathname === '/remote/favicon.ico') {
    res.writeHead(204);
    res.end();
    return;
  }

  return json(res, 404, { ok: false, error: 'Not found' });
}

function main() {
  if (!Number.isInteger(PORT) || PORT < 1 || PORT > 65535 ||
      !Number.isInteger(EGRESS_PORT) || EGRESS_PORT < 1 || EGRESS_PORT > 65535) {
    console.error('[remote] invalid port');
    process.exit(1);
  }
  installEgressProxy(EGRESS_PORT);

  const server = http.createServer((req, res) => {
    handle(req, res).catch(err => {
      if (!res.headersSent) json(res, 500, { ok: false, error: err.message || 'Server error' });
      else try { res.destroy(); } catch { /* ignore */ }
    });
  });
  server.keepAliveTimeout = 65000;
  server.headersTimeout = 70000;
  server.listen(PORT, BIND, () => {
    console.log('[remote] browser on http://' + BIND + ':' + PORT + '/remote/');
  });
  server.on('error', err => {
    console.error('[remote] server:', err.message);
    process.exit(1);
  });

  setInterval(() => { frameLoop().catch(() => {}); }, 130);
  ensureChrome().then(c => {
    console.log('[remote] Chrome ready, initial url:', c.url);
  }).catch(err => {
    lastChromeError = err.message;
    console.error('[remote] Chrome unavailable:', err.message);
  });

  const shutdown = () => {
    console.log('[remote] shutting down');
    try { server.close(); } catch { /* ignore */ }
    try { chrome && chrome.stop(); } catch { /* ignore */ }
    setTimeout(() => process.exit(0), 500).unref();
  };
  process.on('SIGTERM', shutdown);
  process.on('SIGINT', shutdown);
  process.on('unhandledRejection', err => console.error('[remote] unhandled rejection:', err && err.message || err));
  process.on('uncaughtException', err => console.error('[remote] uncaught exception:', err && err.stack || err));
}

main();
