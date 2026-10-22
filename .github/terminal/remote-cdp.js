'use strict';

/*
 * Small, dependency-free Chrome DevTools Protocol client for the remote browser.
 *
 * The remote browser deliberately does not use a Node browser-automation package.  Chrome is
 * launched with --remote-debugging-pipe, so commands and events travel over file descriptors 3/4
 * instead of a TCP debug port.  This keeps the DevTools endpoint private to this process and keeps
 * the terminal boot free of npm installs.
 */

const { spawn } = require('child_process');
const fs = require('fs');
const path = require('path');
const { EventEmitter } = require('events');

const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));

class RemoteChrome extends EventEmitter {
  constructor(options) {
    super();
    this.bin = options.bin;
    this.proxyPort = options.proxyPort;
    this.profile = options.profile;
    this.width = options.width || 1280;
    this.height = options.height || 800;
    this.quality = options.quality || 58;

    this.child = null;
    this.write = null;
    this.read = null;
    this.buf = Buffer.alloc(0);
    this.nextId = 1;
    this.pending = new Map();
    this.starting = null;
    this.ready = false;
    this.closed = true;
    this.sessionId = '';
    this.targetId = '';
    this.mainFrameId = '';
    this.url = '';
    this.title = '';
    this.loading = false;
    this.lastError = '';
    this.stopping = false;
  }

  async start() {
    if (this.ready) return this;
    if (this.starting) return this.starting;
    this.starting = this._start().finally(() => { this.starting = null; });
    return this.starting;
  }

  async _start() {
    if (!this.bin || !fs.existsSync(this.bin)) throw new Error('Chrome binary not found: ' + (this.bin || '(empty)'));
    fs.mkdirSync(this.profile, { recursive: true });

    // The server runs as a numeric uid (1000) but the runner's environment still points
    // HOME/XDG_CONFIG_HOME/XDG_RUNTIME_DIR at the runner user's home and runtime socket.
    // Chrome's crash handler tries to use XDG_CONFIG_HOME before it reads --user-data-dir
    // and exits immediately when that path is not writable.  Keep every per-user path
    // inside the disposable profile instead of inheriting the runner's environment.
    const xdg = {
      config: path.join(this.profile, '.config'),
      cache: path.join(this.profile, '.cache'),
      data: path.join(this.profile, '.local', 'share'),
      state: path.join(this.profile, '.local', 'state'),
      runtime: path.join(this.profile, 'run'),
    };
    for (const dir of Object.values(xdg)) {
      fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
      try { fs.chmodSync(dir, 0o700); } catch { /* best effort */ }
    }
    const chromeEnv = {
      ...process.env,
      HOME: this.profile,
      XDG_CONFIG_HOME: xdg.config,
      XDG_CACHE_HOME: xdg.cache,
      XDG_DATA_HOME: xdg.data,
      XDG_STATE_HOME: xdg.state,
      XDG_RUNTIME_DIR: xdg.runtime,
    };

    const name = path.basename(this.bin);
    const args = [];
    if (!name.includes('headless-shell')) args.push('--headless=new');
    args.push(
      '--no-sandbox',
      '--disable-setuid-sandbox',
      '--disable-gpu',
      '--disable-dev-shm-usage',
      '--disable-extensions',
      '--disable-default-apps',
      '--disable-sync',
      '--disable-background-networking',
      '--disable-component-update',
      '--disable-background-timer-throttling',
      '--disable-renderer-backgrounding',
      '--disable-backgrounding-occluded-windows',
      '--disable-features=Translate,MediaRouter,OptimizationHints,InterestFeedContentSuggestions',
      '--disable-quic',
      '--force-webrtc-ip-handling-policy=disable_non_proxied_udp',
      '--proxy-server=http://127.0.0.1:' + this.proxyPort,
      '--proxy-bypass-list=<-loopback>',
      '--deny-permission-prompts',
      '--no-first-run',
      '--no-default-browser-check',
      '--noerrdialogs',
      '--disable-notifications',
      '--disable-prompt-on-repost',
      '--disable-translate',
      '--mute-audio',
      '--hide-scrollbars',
      '--password-store=basic',
      '--use-mock-keychain',
      '--autoplay-policy=no-user-gesture-required',
      '--window-size=' + this.width + ',' + this.height,
      '--remote-debugging-pipe',
      '--user-data-dir=' + this.profile,
      'about:blank'
    );

    this.closed = false;
    this.stopping = false;
    this.lastError = '';
    this.buf = Buffer.alloc(0);
    this.pending.clear();
    this.nextId = 1;

    this.child = spawn(this.bin, args, {
      stdio: ['ignore', 'ignore', 'ignore', 'pipe', 'pipe'],
      // Chrome is intentionally run as a separate numeric uid.  Keep every
      // per-user path inside the disposable profile so it never needs the
      // runner user's home, config, cache or runtime directory.
      env: chromeEnv,
    });
    this.write = this.child.stdio[3];
    this.read = this.child.stdio[4];

    this.read.on('data', chunk => this._onData(chunk));
    this.read.on('error', err => this._fail(err));
    this.write.on('error', err => this._fail(err));

    this.child.on('error', err => this._fail(err));
    this.child.once('exit', (code, signal) => {
      const wasStopping = this.stopping;
      this.ready = false;
      this.closed = true;
      this._rejectAll(new Error('Chrome exited' + (code == null ? '' : ' (' + code + ')')));
      if (!wasStopping) this.emit('closed', { code, signal });
    });

    try {
      const targets = await this.send('Target.getTargets');
      let page = (targets.targetInfos || []).find(t => t.type === 'page');
      if (!page) {
        const created = await this.send('Target.createTarget', { url: 'about:blank' });
        page = { targetId: created.targetId };
      }
      this.targetId = page.targetId;
      const attached = await this.send('Target.attachToTarget', { targetId: this.targetId, flatten: true });
      this.sessionId = attached.sessionId;

      await this.send('Page.enable');
      await this.send('Runtime.enable');
      await this.send('Emulation.setDeviceMetricsOverride', {
        width: this.width,
        height: this.height,
        deviceScaleFactor: 1,
        mobile: false,
        screenWidth: this.width,
        screenHeight: this.height,
      });
      await this._setNormalUserAgent();
      await this._installPageScripts();
      await this._safe('Page.setDownloadBehavior', { behavior: 'deny' });
      await this._safe('Page.setInterceptFileChooserDialog', { enabled: true });
      await this._safe('Target.setDiscoverTargets', { discover: true });

      this.url = 'about:blank';
      this.title = '';
      this.loading = false;
      this.ready = true;
      return this;
    } catch (err) {
      this.lastError = err.message;
      this.ready = false;
      this._fail(err);
      this.stop();
      throw err;
    }
  }

  async _setNormalUserAgent() {
    try {
      const r = await this.send('Runtime.evaluate', {
        expression: 'navigator.userAgent',
        returnByValue: true,
      });
      const ua = String(r.result && r.result.value || '');
      if (ua) {
        await this.send('Emulation.setUserAgentOverride', {
          userAgent: ua.replace(/HeadlessChrome/g, 'Chrome'),
          acceptLanguage: 'en-US,en;q=0.9',
          platform: 'Linux x86_64',
        });
      }
    } catch { /* not fatal */ }
  }

  async _installPageScripts() {
    // A remote browser is a single-view surface.  Opening a second tab would take it off-screen,
    // so target=_blank/window.open() are redirected into this tab.  This is not a security
    // boundary; it merely keeps the screenshot view usable.
    const source = `(() => {
      try {
        const nativeOpen = window.open;
        window.open = function (url) {
          try {
            if (url != null) {
              const u = String(url);
              if (/^(?:https?|about):/i.test(u) || /^(?:\\/|\\.\\.?\\/)/.test(u)) {
                location.assign(u);
                return null;
              }
            }
          } catch (e) {}
          return nativeOpen.apply(this, arguments);
        };
      } catch (e) {}
      try {
        document.addEventListener('click', function (ev) {
          const a = ev.target && ev.target.closest ? ev.target.closest('a[target], area[target]') : null;
          if (a) a.target = '_self';
        }, true);
        document.addEventListener('submit', function (ev) {
          const f = ev.target && ev.target.closest ? ev.target.closest('form[target]') : null;
          if (f) f.target = '_self';
        }, true);
      } catch (e) {}
    })();`;
    await this.send('Page.addScriptToEvaluateOnNewDocument', { source });
  }

  _onData(chunk) {
    this.buf = Buffer.concat([this.buf, chunk]);
    let at;
    while ((at = this.buf.indexOf(0)) >= 0) {
      const text = this.buf.subarray(0, at).toString('utf8');
      this.buf = this.buf.subarray(at + 1);
      if (!text) continue;
      let msg;
      try { msg = JSON.parse(text); } catch { continue; }
      this._onMessage(msg);
    }
    // A malformed peer should not make this process grow forever.
    if (this.buf.length > 32 * 1024 * 1024) this._fail(new Error('CDP buffer overflow'));
  }

  _onMessage(msg) {
    if (msg.id && this.pending.has(msg.id)) {
      const entry = this.pending.get(msg.id);
      this.pending.delete(msg.id);
      clearTimeout(entry.timer);
      if (msg.error) entry.reject(new Error(msg.error.message || 'CDP error'));
      else entry.resolve(msg.result || {});
      return;
    }
    if (!msg.method) return;

    if (msg.method === 'Page.frameNavigated') {
      const frame = msg.params && msg.params.frame;
      if (frame && !frame.parentId) {
        this.mainFrameId = frame.id || this.mainFrameId;
        this.url = frame.url || this.url;
        // Do not mark the page as loading here.  A back/forward traversal can
        // restore a page from the back-forward cache without a load event, and
        // a frameStartedLoading event is the reliable signal for real loads.
        this._refreshTitle();
        this.emit('state');
      }
      return;
    }
    if (msg.method === 'Page.navigatedWithinDocument') {
      if (msg.params && msg.params.url && (!this.mainFrameId || msg.params.frameId === this.mainFrameId)) {
        this.url = msg.params.url;
        this.loading = false;
        this._refreshTitle();
        this.emit('state');
      }
      return;
    }
    if (msg.method === 'Page.frameStartedLoading') {
      if (!this.mainFrameId || (msg.params && msg.params.frameId === this.mainFrameId)) {
        this.loading = true;
        this.emit('state');
      }
      return;
    }
    if (msg.method === 'Page.frameStoppedLoading') {
      if (!this.mainFrameId || (msg.params && msg.params.frameId === this.mainFrameId)) {
        this.loading = false;
        this._refreshTitle();
        this.emit('state');
      }
      return;
    }
    if (msg.method === 'Page.loadEventFired') {
      this.loading = false;
      this._refreshTitle();
      this.emit('state');
      return;
    }
    if (msg.method === 'Page.javascriptDialogOpening') {
      this._safe('Page.handleJavaScriptDialog', { accept: true }).catch(() => {});
      return;
    }
    if (msg.method === 'Inspector.targetCrashed') {
      this.lastError = 'The page crashed';
      this.ready = false;
      this._rejectAll(new Error(this.lastError));
      this.stop().finally(() => {
        this.emit('error', new Error(this.lastError));
        this.emit('closed', { reason: 'page crashed' });
      });
      return;
    }
    if (msg.method === 'Target.targetDestroyed') {
      if (msg.params && msg.params.targetId === this.targetId) {
        this.lastError = 'The page was closed';
        this.ready = false;
        this._rejectAll(new Error(this.lastError));
        this.stop().finally(() => {
          this.emit('closed', { reason: 'target destroyed' });
        });
      }
    }
  }

  async _refreshTitle() {
    try {
      const r = await this.send('Runtime.evaluate', { expression: 'document.title', returnByValue: true });
      this.title = String((r.result && r.result.value) || '');
    } catch { /* page may be navigating */ }
  }

  send(method, params = {}) {
    if (!this.write || this.closed) return Promise.reject(new Error('Chrome is not running'));
    const id = this.nextId++;
    const message = { id, method, params };
    if (this.sessionId) message.sessionId = this.sessionId;
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        this.pending.delete(id);
        reject(new Error('CDP timeout: ' + method));
      }, 20000);
      this.pending.set(id, { resolve, reject, timer });
      try {
        this.write.write(JSON.stringify(message) + '\0');
      } catch (err) {
        clearTimeout(timer);
        this.pending.delete(id);
        reject(err);
      }
    });
  }

  async _safe(method, params) {
    try { return await this.send(method, params); } catch { return null; }
  }

  _rejectAll(err) {
    for (const entry of this.pending.values()) {
      clearTimeout(entry.timer);
      entry.reject(err);
    }
    this.pending.clear();
  }

  _fail(err) {
    this.lastError = err && err.message || String(err);
    this.ready = false;
    this._rejectAll(err instanceof Error ? err : new Error(this.lastError));
  }

  async state() {
    if (!this.ready) throw new Error('Chrome is starting');
    let history = null;
    try { history = await this.send('Page.getNavigationHistory'); } catch { /* transient */ }
    const entries = history && Array.isArray(history.entries) ? history.entries : [];
    const index = history ? Number(history.currentIndex) : -1;
    return {
      ok: true,
      url: this.url || '',
      title: this.title || '',
      loading: !!this.loading,
      canGoBack: index > 0,
      canGoForward: index >= 0 && index < entries.length - 1,
      width: this.width,
      height: this.height,
    };
  }

  async navigate(url) {
    if (!this.ready) throw new Error('Chrome is starting');
    const result = await this.send('Page.navigate', { url });
    if (result.errorText) throw new Error(result.errorText);
    this.url = url;
    this.loading = true;
    this.emit('state');
    return result;
  }

  async back() {
    const history = await this.send('Page.getNavigationHistory');
    const index = Number(history.currentIndex);
    if (!(index > 0)) return false;
    await this.send('Page.navigateToHistoryEntry', { entryId: history.entries[index - 1].id });
    return true;
  }

  async forward() {
    const history = await this.send('Page.getNavigationHistory');
    const index = Number(history.currentIndex);
    if (!(index >= 0 && index < history.entries.length - 1)) return false;
    await this.send('Page.navigateToHistoryEntry', { entryId: history.entries[index + 1].id });
    return true;
  }

  async reload() {
    if (!this.ready) throw new Error('Chrome is starting');
    this.loading = true;
    await this.send('Page.reload', { ignoreCache: false });
  }

  async home() {
    await this.navigate('about:blank');
  }

  async screenshot() {
    if (!this.ready) throw new Error('Chrome is starting');
    const result = await this.send('Page.captureScreenshot', {
      format: 'jpeg',
      quality: this.quality,
      fromSurface: true,
      captureBeyondViewport: false,
    });
    if (!result.data) throw new Error('Empty screenshot');
    return Buffer.from(result.data, 'base64');
  }

  async mouse(payload) {
    const x = Math.max(0, Math.min(this.width, Number(payload.x) || 0));
    const y = Math.max(0, Math.min(this.height, Number(payload.y) || 0));
    const button = ['left', 'right', 'middle'].includes(payload.button) ? payload.button : 'left';
    const clickCount = Math.max(1, Math.min(3, Number(payload.clickCount) || 1));
    const modifiers = Number(payload.modifiers) || 0;
    const type = String(payload.type || 'click');
    if (type === 'move') {
      const buttons = Math.max(0, Math.min(7, Number(payload.buttons) || 0));
      await this.send('Input.dispatchMouseEvent', {
        type: 'mouseMoved', x, y,
        button: buttons ? button : 'none',
        buttons,
      });
      return;
    }
    if (type === 'wheel') {
      await this.send('Input.dispatchMouseEvent', {
        type: 'mouseWheel', x, y,
        deltaX: Number(payload.deltaX) || 0,
        deltaY: Number(payload.deltaY) || 0,
        button: 'none', buttons: 0, modifiers,
      });
      return;
    }
    if (type === 'down' || type === 'up') {
      const isDown = type === 'down';
      await this.send('Input.dispatchMouseEvent', {
        type: isDown ? 'mousePressed' : 'mouseReleased',
        x, y,
        button,
        buttons: isDown ? (button === 'right' ? 2 : button === 'middle' ? 4 : 1) : 0,
        clickCount,
        modifiers,
      });
      return;
    }
    // "click" is the common path for taps and mouse clicks.
    await this.send('Input.dispatchMouseEvent', { type: 'mouseMoved', x, y, button: 'none', buttons: 0 });
    await this.send('Input.dispatchMouseEvent', {
      type: 'mousePressed', x, y, button, buttons: button === 'right' ? 2 : button === 'middle' ? 4 : 1,
      clickCount, modifiers,
    });
    await this.send('Input.dispatchMouseEvent', {
      type: 'mouseReleased', x, y, button, buttons: 0, clickCount, modifiers,
    });
  }

  async text(text) {
    const value = String(text || '');
    if (!value) return;
    await this.send('Input.insertText', { text: value });
  }

  async key(payload) {
    const key = String(payload.key || '');
    if (!key) return;
    const code = String(payload.code || '');
    const keyCode = Number(payload.keyCode) || 0;
    const modifiers = Number(payload.modifiers) || 0;
    const text = payload.text == null ? '' : String(payload.text);
    const base = { key, code, windowsVirtualKeyCode: keyCode, nativeVirtualKeyCode: keyCode, modifiers };
    await this.send('Input.dispatchKeyEvent', {
      type: 'keyDown', ...base, ...(text ? { text, unmodifiedText: text } : {}),
    });
    await this.send('Input.dispatchKeyEvent', { type: 'keyUp', ...base });
  }

  async stop() {
    this.stopping = true;
    this.ready = false;
    if (this.child && !this.closed) {
      try { this.child.kill('SIGTERM'); } catch {}
      await sleep(600);
      if (this.child && !this.closed) {
        try { this.child.kill('SIGKILL'); } catch {}
      }
    }
    this.closed = true;
  }
}

module.exports = { RemoteChrome };
