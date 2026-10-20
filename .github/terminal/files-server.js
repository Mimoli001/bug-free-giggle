#!/usr/bin/env node
/*
 * Web file explorer backend for the persistent terminal.
 *
 * Runs on the host, as UID 1000 (the container user), bound to loopback and proxied by nginx at
 * /files/.  nginx enforces the same basic-auth password as the terminal; this server never listens
 * on a public interface.  All paths are confined to the workspace root, including through symlinks.
 *
 * No dependencies: Node 18+ only.
 */
'use strict';

const http = require('http');
const fs = require('fs');
const fsp = fs.promises;
const path = require('path');
const { spawn } = require('child_process');

const arg = (name, def) => {
  const i = process.argv.indexOf('--' + name);
  return i > -1 && process.argv[i + 1] ? process.argv[i + 1] : def;
};

const ROOT = fs.realpathSync(path.resolve(arg('root', '/workspaces')));
const INDEX = arg('html', path.join(__dirname, 'index.html'));
const PORT = parseInt(arg('port', '7697'), 10);
const HOST = arg('host', '127.0.0.1');

const MAX_EDIT = 2 * 1024 * 1024;        // editor read limit
const MAX_WRITE = 5 * 1024 * 1024;       // editor save limit
const MAX_JSON = 12 * 1024 * 1024;
const MAX_UPLOAD = 10 * 1024 * 1024 * 1024; // hard disk guard, not a UX limit

const MIME = {
  '.txt': 'text/plain; charset=utf-8', '.md': 'text/markdown; charset=utf-8',
  '.json': 'application/json; charset=utf-8', '.css': 'text/css; charset=utf-8',
  '.html': 'text/html; charset=utf-8', '.htm': 'text/html; charset=utf-8',
  '.xml': 'application/xml; charset=utf-8', '.csv': 'text/csv; charset=utf-8',
  '.svg': 'image/svg+xml', '.png': 'image/png', '.jpg': 'image/jpeg', '.jpeg': 'image/jpeg',
  '.gif': 'image/gif', '.webp': 'image/webp', '.avif': 'image/avif', '.bmp': 'image/bmp',
  '.ico': 'image/x-icon', '.pdf': 'application/pdf', '.zip': 'application/zip',
  '.gz': 'application/gzip', '.tgz': 'application/gzip', '.tar': 'application/x-tar',
  '.mp3': 'audio/mpeg', '.wav': 'audio/wav', '.mp4': 'video/mp4', '.webm': 'video/webm',
  '.woff': 'font/woff', '.woff2': 'font/woff2', '.ttf': 'font/ttf',
  '.py': 'text/plain; charset=utf-8', '.js': 'text/plain; charset=utf-8',
  '.ts': 'text/plain; charset=utf-8', '.sh': 'text/plain; charset=utf-8',
  '.yml': 'text/plain; charset=utf-8', '.yaml': 'text/plain; charset=utf-8',
  '.toml': 'text/plain; charset=utf-8', '.log': 'text/plain; charset=utf-8',
};
const IMAGE_EXT = new Set(['.png', '.jpg', '.jpeg', '.gif', '.webp', '.avif', '.bmp', '.ico', '.svg']);

const httpErr = (code, message) => Object.assign(new Error(message), { httpCode: code });

/* ------------------------------------------------------------------ paths */

const isInside = p => p === ROOT || p.startsWith(ROOT + path.sep);

/*
 * Resolve a client-supplied relative path.  `follow` controls the final component only: reads and
 * listings follow symlinks (after checking the real target), deletes and renames operate on the
 * link itself (otherwise deleting a link would delete its target).
 */
async function safePath(rel, { follow = true } = {}) {
  if (typeof rel !== 'string' || rel.length > 4096 || rel.includes('\0')) throw httpErr(400, 'invalid path');
  const clean = rel.replace(/^\/+|\/+$/g, '');
  const abs = path.resolve(ROOT, clean);
  if (!isInside(abs)) throw httpErr(403, 'path is outside the workspace');

  const parent = abs === ROOT ? ROOT : path.dirname(abs);
  let probe = parent;
  const rest = [];
  for (;;) {
    try { await fsp.lstat(probe); break; } catch (e) {
      if (e.code !== 'ENOENT' || probe === ROOT) break;
      rest.unshift(path.basename(probe));
      probe = path.dirname(probe);
    }
  }
  let realParent;
  try { realParent = await fsp.realpath(probe); } catch { realParent = probe; }
  if (!isInside(realParent)) throw httpErr(403, 'path is outside the workspace');

  let real = abs === ROOT ? ROOT : path.join(realParent, ...rest, path.basename(abs));
  if (follow && abs !== ROOT) {
    try { real = await fsp.realpath(abs); } catch { /* does not exist yet */ }
    if (!isInside(real)) throw httpErr(403, 'symlink points outside the workspace');
  }
  return { abs, real, rel: path.relative(ROOT, abs).split(path.sep).join('/') };
}

const exists = async p => { try { await fsp.lstat(p); return true; } catch { return false; } };

function safeName(name) {
  if (typeof name !== 'string') throw httpErr(400, 'invalid name');
  const n = name.trim();
  if (!n || n === '.' || n === '..' || n.includes('/') || n.includes('\\') || /[\x00-\x1f\x7f]/.test(n) || n.length > 255)
    throw httpErr(400, 'invalid name');
  return n;
}

async function uniqueName(dir, name) {
  if (!(await exists(path.join(dir, name)))) return name;
  const ext = path.extname(name);
  const base = name.slice(0, name.length - ext.length);
  for (let i = 1; i < 10000; i++) {
    const cand = `${base} (${i})${ext}`;
    if (!(await exists(path.join(dir, cand)))) return cand;
  }
  throw httpErr(409, 'too many files with the same name');
}

/* ------------------------------------------------------------------ http helpers */

function send(res, code, body, type = 'text/plain; charset=utf-8', extra = {}) {
  const buf = Buffer.isBuffer(body) ? body : Buffer.from(String(body));
  res.writeHead(code, {
    'Content-Type': type, 'Content-Length': buf.length,
    'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff', ...extra,
  });
  res.end(buf);
}
const json = (res, code, obj, extra) => send(res, code, JSON.stringify(obj), 'application/json; charset=utf-8', extra);

function readBody(req, max) {
  return new Promise((resolve, reject) => {
    let size = 0; const chunks = [];
    req.on('data', c => {
      size += c.length;
      if (size > max) { reject(httpErr(413, 'request body too large')); req.destroy(); return; }
      chunks.push(c);
    });
    req.on('end', () => resolve(Buffer.concat(chunks)));
    req.on('error', reject);
  });
}
async function readJson(req) {
  const buf = await readBody(req, MAX_JSON);
  try { return JSON.parse(buf.toString('utf8') || '{}'); } catch { throw httpErr(400, 'invalid JSON body'); }
}

function disposition(name, inline) {
  const safe = name.replace(/[^\x20-\x7E]/g, '_').replace(/["\\]/g, '_');
  return `${inline ? 'inline' : 'attachment'}; filename="${safe}"; filename*=UTF-8''${encodeURIComponent(name)}`;
}

/* ------------------------------------------------------------------ api */

async function listDir(rel) {
  const { real, rel: clean } = await safePath(rel, { follow: true });
  const st = await fsp.stat(real);
  if (!st.isDirectory()) throw httpErr(400, 'not a directory');
  const dirents = await fsp.readdir(real, { withFileTypes: true });
  const entries = await Promise.all(dirents.map(async d => {
    const full = path.join(real, d.name);
    let ls; try { ls = await fsp.lstat(full); } catch { return null; }
    let type = 'other';
    let external = false;
    if (ls.isSymbolicLink()) {
      type = 'link';
      try {
        const target = await fsp.realpath(full);
        if (!isInside(target)) external = true;
        else type = (await fsp.stat(target)).isDirectory() ? 'dir' : 'file';
      } catch { external = true; }
    } else if (ls.isDirectory()) type = 'dir';
    else if (ls.isFile()) type = 'file';
    return {
      name: d.name, type, external,
      size: ls.isDirectory() ? 0 : ls.size,
      mtime: Math.round(ls.mtimeMs),
      link: ls.isSymbolicLink(),
    };
  }));
  return { path: clean, entries: entries.filter(Boolean) };
}

async function readFile(rel) {
  const { real, rel: clean } = await safePath(rel, { follow: true });
  const st = await fsp.stat(real);
  if (!st.isFile()) throw httpErr(400, 'not a file');
  if (st.size > MAX_EDIT) throw httpErr(413, 'file is too large to edit (limit 2 MB)');
  const buf = await fsp.readFile(real);
  if (buf.includes(0)) throw httpErr(415, 'binary file');
  let content;
  try { content = new TextDecoder('utf-8', { fatal: true }).decode(buf); }
  catch { throw httpErr(415, 'file is not valid UTF-8 text'); }
  return { path: clean, size: st.size, mtime: Math.round(st.mtimeMs), content };
}

async function writeFile(rel, content) {
  if (typeof content !== 'string') throw httpErr(400, 'content must be a string');
  if (Buffer.byteLength(content) > MAX_WRITE) throw httpErr(413, 'content is too large to save (limit 5 MB)');
  const { real, rel: clean } = await safePath(rel, { follow: true });
  const parent = path.dirname(real);
  const pst = await fsp.stat(parent).catch(() => null);
  if (!pst || !pst.isDirectory()) throw httpErr(400, 'parent directory does not exist');
  if (await exists(real)) {
    const st = await fsp.lstat(real);
    if (st.isDirectory()) throw httpErr(400, 'cannot write to a directory');
  }
  const mode = (await fsp.stat(real).then(s => s.mode & 0o777).catch(() => 0o644)) || 0o644;
  const tmp = path.join(parent, `.files-tmp-${process.pid}-${Date.now()}-${Math.random().toString(36).slice(2)}`);
  await fsp.writeFile(tmp, content, { mode });
  try { await fsp.rename(tmp, real); }
  catch (e) { await fsp.unlink(tmp).catch(() => {}); throw e; }
  return { path: clean, size: Buffer.byteLength(content) };
}

async function mkdir(rel) {
  const { abs, rel: clean } = await safePath(rel, { follow: false });
  if (abs === ROOT) throw httpErr(400, 'already exists');
  if (await exists(abs)) throw httpErr(409, 'already exists');
  await fsp.mkdir(abs);
  return { path: clean };
}

async function rename(rel, to) {
  const src = await safePath(rel, { follow: false });
  if (src.abs === ROOT) throw httpErr(400, 'cannot rename the workspace root');
  const dst = await safePath(to, { follow: false });
  if (dst.abs === ROOT) throw httpErr(400, 'invalid destination');
  if (dst.abs === src.abs) return { from: src.rel, to: dst.rel };
  if (dst.abs.startsWith(src.abs + path.sep)) throw httpErr(400, 'cannot move a directory into itself');
  const parent = path.dirname(dst.abs);
  const pst = await fsp.stat(parent).catch(() => null);
  if (!pst || !pst.isDirectory()) throw httpErr(400, 'destination directory does not exist');
  if (await exists(dst.abs)) throw httpErr(409, 'destination already exists');
  await fsp.rename(src.abs, dst.abs);
  return { from: src.rel, to: dst.rel };
}

async function remove(paths) {
  if (!Array.isArray(paths) || !paths.length) throw httpErr(400, 'no paths given');
  if (paths.length > 500) throw httpErr(400, 'too many paths');
  const deleted = [], errors = [];
  for (const rel of paths) {
    try {
      const { abs, rel: clean } = await safePath(rel, { follow: false });
      if (abs === ROOT) throw httpErr(400, 'cannot delete the workspace root');
      const st = await fsp.lstat(abs).catch(() => null);
      if (!st) throw httpErr(404, 'not found');
      await fsp.rm(abs, { recursive: st.isDirectory() && !st.isSymbolicLink(), force: false });
      deleted.push(clean);
    } catch (e) {
      errors.push({ path: rel, error: e.message });
    }
  }
  return { deleted, errors };
}

async function saveUpload(req, dirRel, rawName) {
  const name = safeName(rawName);
  const { real } = await safePath(dirRel, { follow: true });
  const st = await fsp.stat(real);
  if (!st.isDirectory()) throw httpErr(400, 'upload target is not a directory');
  const finalName = await uniqueName(real, name);
  const tmp = path.join(real, `.files-upload-${process.pid}-${Date.now()}-${Math.random().toString(36).slice(2)}`);
  const out = fs.createWriteStream(tmp, { flags: 'wx', mode: 0o644 });
  let size = 0;
  try {
    await new Promise((resolve, reject) => {
      req.on('data', c => {
        size += c.length;
        if (size > MAX_UPLOAD) { req.destroy(); reject(httpErr(413, 'upload too large')); }
      });
      req.on('aborted', () => reject(httpErr(400, 'upload aborted')));
      req.on('error', reject);
      out.on('error', reject);
      out.on('finish', resolve);
      req.pipe(out);
    });
    await fsp.rename(tmp, path.join(real, finalName));
  } catch (e) {
    out.destroy();
    await fsp.unlink(tmp).catch(() => {});
    throw e;
  }
  return { name: finalName, size };
}

function streamFile(res, abs, name, inline) {
  let st;
  try { st = fs.statSync(abs); } catch (e) { throw httpErr(e.code === 'ENOENT' ? 404 : 500, 'cannot read file'); }
  if (!st.isFile()) throw httpErr(400, 'not a file');
  const type = MIME[path.extname(name).toLowerCase()] || 'application/octet-stream';
  const headers = {
    'Content-Type': type, 'Content-Length': st.size, 'Cache-Control': 'no-store',
    'X-Content-Type-Options': 'nosniff', 'Content-Disposition': disposition(name, inline),
  };
  // An uploaded SVG opened directly must not run script on this origin.
  if (inline) headers['Content-Security-Policy'] = 'sandbox';
  res.writeHead(200, headers);
  const rs = fs.createReadStream(abs);
  rs.on('error', () => { try { res.destroy(); } catch {} });
  rs.pipe(res);
}

function archive(res, abs, name) {
  const parent = path.dirname(abs), base = path.basename(abs);
  const tar = spawn('tar', ['-czf', '-', '-C', parent, '--', base], { stdio: ['ignore', 'pipe', 'ignore'] });
  res.writeHead(200, {
    'Content-Type': 'application/gzip', 'Cache-Control': 'no-store',
    'Content-Disposition': disposition(name + '.tar.gz', false),
  });
  tar.stdout.pipe(res);
  tar.on('error', () => { try { res.destroy(); } catch {} });
  res.on('close', () => tar.kill());
}

/* ------------------------------------------------------------------ server */

function csrfOk(req, res) {
  if (req.method === 'GET' || req.method === 'HEAD') return true;
  if (req.headers['x-files'] !== '1') { json(res, 403, { error: 'missing X-Files header' }); return false; }
  const origin = req.headers.origin;
  if (origin) {
    let host;
    try { host = new URL(origin).host; } catch { host = null; }
    if (!host || host !== req.headers.host) { json(res, 403, { error: 'cross-origin request blocked' }); return false; }
  }
  return true;
}

async function handle(req, res) {
  const url = new URL(req.url, 'http://files');
  let p = url.pathname.replace(/^\/files(?=\/|$)/, '') || '/';
  if (!p.startsWith('/')) p = '/' + p;

  if (req.method === 'GET' && (p === '/' || p === '/index.html')) {
    let html;
    try { html = await fsp.readFile(INDEX); } catch { throw httpErr(500, 'UI file is missing'); }
    return send(res, 200, html, 'text/html; charset=utf-8', {
      'X-Frame-Options': 'SAMEORIGIN',
      'Content-Security-Policy': "frame-ancestors 'self'",
      'Referrer-Policy': 'no-referrer',
    });
  }
  if (!p.startsWith('/api/')) throw httpErr(404, 'not found');

  if (!csrfOk(req, res)) return;
  const q = url.searchParams;

  if (p === '/api/health' && req.method === 'GET') return json(res, 200, { ok: true, root: routeLabel() });
  if (p === '/api/list' && req.method === 'GET') return json(res, 200, await listDir(q.get('path') || ''));
  if (p === '/api/read' && req.method === 'GET') return json(res, 200, await readFile(q.get('path') || ''));

  if (p === '/api/write' && req.method === 'PUT') {
    const body = await readJson(req);
    return json(res, 200, { ok: true, ...(await writeFile(q.get('path') || '', body.content)) });
  }
  if (p === '/api/mkdir' && req.method === 'POST') {
    const body = await readJson(req);
    return json(res, 200, { ok: true, ...(await mkdir(body.path)) });
  }
  if (p === '/api/rename' && req.method === 'POST') {
    const body = await readJson(req);
    if (!body || typeof body.to !== 'string') throw httpErr(400, 'missing destination');
    return json(res, 200, { ok: true, ...(await rename(body.path || '', body.to)) });
  }
  if (p === '/api/delete' && req.method === 'POST') {
    const body = await readJson(req);
    return json(res, 200, { ok: true, ...(await remove(body.paths)) });
  }
  if (p === '/api/upload' && req.method === 'POST') {
    return json(res, 200, { ok: true, ...(await saveUpload(req, q.get('path') || '', q.get('name') || '')) });
  }
  if (p === '/api/download' && req.method === 'GET') {
    const { real, rel } = await safePath(q.get('path') || '', { follow: true });
    const st = await fsp.stat(real);
    if (st.isDirectory()) return archive(res, real, rel.split('/').pop() || 'workspace');
    return streamFile(res, real, path.basename(rel), false);
  }
  if (p === '/api/raw' && req.method === 'GET') {
    const { real, rel } = await safePath(q.get('path') || '', { follow: true });
    const inline = IMAGE_EXT.has(path.extname(real).toLowerCase());
    return streamFile(res, real, path.basename(rel), inline);
  }
  if (p === '/api/archive' && req.method === 'GET') {
    const { real, rel } = await safePath(q.get('path') || '', { follow: true });
    const st = await fsp.stat(real);
    if (!st.isDirectory()) return streamFile(res, real, path.basename(rel), false);
    return archive(res, real, path.basename(rel) || 'workspace');
  }
  throw httpErr(404, 'not found');
}

function routeLabel() {
  const parts = ROOT.split(path.sep).filter(Boolean);
  return parts.slice(-2).join('/');
}

const FS_CODES = { ENOENT: 404, EACCES: 403, EPERM: 403, ENOTDIR: 400, EISDIR: 400, EEXIST: 409, ENOSPC: 507, ENAMETOOLONG: 400 };
const server = http.createServer((req, res) => {
  handle(req, res).catch(e => {
    if (res.headersSent) { try { res.destroy(); } catch {} return; }
    const code = e.httpCode || FS_CODES[e.code] || 500;
    if (code >= 500) console.error('[files]', req.method, req.url, e.stack || e.message);
    json(res, code, { error: e.message || 'internal error' });
  });
});

server.listen(PORT, HOST, () => {
  console.log(`[files] listening on http://${HOST}:${PORT} root=${ROOT}`);
});
