/*
 * Runtime injected into every HTML page served by the local browser proxy.
 *
 * The page is same-origin with the terminal, so this file deliberately stays small and boring: it
 * keeps navigation and network calls inside /browser/<kind>/<port>/ instead of trying to emulate a
 * browser.  The server also rewrites absolute URLs in HTML and CSS; this runtime covers the paths
 * that only exist after JavaScript starts (fetch/XHR/WebSocket, dynamically created elements,
 * history.pushState, document.cookie and service-worker registrations).
 *
 * The config token below is replaced by browser-server.js with {"port":8099,"secure":false}.
 */
(function () {
  'use strict';
  var CFG = __BROWSER_CONFIG__;
  var PORT = CFG.port;
  var SECURE = !!CFG.secure;
  var KIND = SECURE ? 's' : 'p';
  var PREFIX = '/browser/' + KIND + '/' + PORT + '/';
  var TARGET_ORIGIN = (SECURE ? 'https' : 'http') + '://localhost:' + PORT;

  function isLocalHost(host) {
    host = String(host || '').toLowerCase().replace(/^\[|\]$/g, '');
    return host === 'localhost' || host === '127.0.0.1' || host === '::1' ||
      host === '0.0.0.0' || /^127\./.test(host) || /\.localhost$/.test(host);
  }

  function parse(raw) {
    try { return new URL(String(raw), location.href); } catch (e) { return null; }
  }

  function routeFor(port, secure) {
    return location.origin + '/browser/' + (secure ? 's' : 'p') + '/' + port + '/';
  }

  function mapUrl(raw) {
    var s = String(raw);
    if (!s || s.charAt(0) === '#' || s.charAt(0) === '?') return s;
    if (/^(?:data|blob|mailto|tel|javascript|about|chrome):/i.test(s)) return s;
    var u = parse(s);
    if (!u) return s;
    if (u.origin === location.origin) {
      if (u.pathname === PREFIX.slice(0, -1) || u.pathname.indexOf(PREFIX) === 0) return u.href;
      if (u.pathname.indexOf('/browser/') === 0) return u.href;
      return routeFor(PORT, SECURE) + u.pathname.replace(/^\//, '') + u.search + u.hash;
    }
    if (isLocalHost(u.hostname)) {
      var p = parseInt(u.port || (u.protocol === 'https:' ? '443' : '80'), 10);
      if (!p) p = PORT;
      return routeFor(p, u.protocol === 'https:') + u.pathname.replace(/^\//, '') + u.search + u.hash;
    }
    return s;
  }

  function mapWs(raw) {
    var s = String(raw);
    var u = parse(s);
    if (!u) return s;
    var p = PORT;
    var secure = SECURE;
    var path = u.pathname;
    if (u.protocol === 'ws:' || u.protocol === 'wss:') {
      if (u.origin === location.origin || isLocalHost(u.hostname)) {
        p = parseInt(u.port || (u.protocol === 'wss:' ? '443' : '80'), 10) || PORT;
        secure = u.protocol === 'wss:';
      } else {
        return s;
      }
    } else if (u.origin === location.origin) {
      // A relative WebSocket URL is parsed by URL() as http(s), not ws(s).  Keep its path here
      // and let the final ws:// construction below build the correct scheme.
      if (u.pathname.indexOf('/browser/p/') === 0 || u.pathname.indexOf('/browser/s/') === 0) path = u.pathname;
    } else if (isLocalHost(u.hostname)) {
      p = parseInt(u.port || (u.protocol === 'https:' ? '443' : '80'), 10) || PORT;
      secure = u.protocol === 'https:';
    } else {
      return s;
    }
    if (u.pathname.indexOf('/browser/p/') === 0 || u.pathname.indexOf('/browser/s/') === 0) path = u.pathname;
    else path = '/browser/' + (secure ? 's' : 'p') + '/' + p + '/' + u.pathname.replace(/^\//, '');
    return (location.protocol === 'https:' ? 'wss:' : 'ws:') + '//' + location.host + path + u.search;
  }

  function mapAttr(name, value) {
    if (value === null || value === undefined) return value;
    var v = String(value);
    if (name === 'srcset') {
      return v.split(',').map(function (part) {
        var m = part.match(/^(\s*)(\S+)([\s\S]*)$/);
        if (!m) return part;
        return m[1] + mapUrl(m[2]) + m[3];
      }).join(',');
    }
    return mapUrl(v);
  }

  var URL_ATTRS = {
    href: 1, src: 1, action: 1, formaction: 1, poster: 1, manifest: 1,
    'data-src': 1, 'data-href': 1, 'xlink:href': 1
  };

  /* ---------------------------------------------------------------- DOM helpers */
  function fixElement(el) {
    if (!el || el.nodeType !== 1) return;
    var tag = (el.tagName || '').toLowerCase();
    for (var name in URL_ATTRS) {
      if (!Object.prototype.hasOwnProperty.call(URL_ATTRS, name)) continue;
      var val = el.getAttribute && el.getAttribute(name);
      if (val === null) continue;
      var mapped = mapAttr(name, val);
      if (mapped !== val) {
        try { el.setAttribute(name, mapped); } catch (e) {}
      }
    }
    if (tag === 'img' || tag === 'source') {
      var ss = el.getAttribute && el.getAttribute('srcset');
      if (ss) {
        var ms = mapAttr('srcset', ss);
        if (ms !== ss) { try { el.setAttribute('srcset', ms); } catch (e) {} }
      }
    }
    if (tag === 'object') {
      var data = el.getAttribute && el.getAttribute('data');
      if (data) {
        var md = mapUrl(data);
        if (md !== data) { try { el.setAttribute('data', md); } catch (e) {} }
      }
    }
    if (tag === 'meta') {
      var httpEq = (el.getAttribute('http-equiv') || '').toLowerCase();
      if (httpEq === 'refresh') {
        var content = el.getAttribute('content') || '';
        var mc = content.replace(/(url\s*=\s*)(['"]?)([^'";]+)\2/i, function (_, pre, q, url) {
          return pre + q + mapUrl(url) + q;
        });
        if (mc !== content) { try { el.setAttribute('content', mc); } catch (e) {} }
      }
    }
  }

  function fixTree(root) {
    if (!root || root.nodeType !== 1 && root.nodeType !== 9) return;
    if (root.nodeType === 1) fixElement(root);
    var list = root.querySelectorAll ? root.querySelectorAll(
      'a[href],area[href],img[src],img[srcset],script[src],link[href],source[src],source[srcset],' +
      'video[src],video[poster],audio[src],iframe[src],frame[src],form[action],input[formaction],' +
      'button[formaction],object[data],base[href],meta[http-equiv]'
    ) : [];
    for (var i = 0; i < list.length; i++) fixElement(list[i]);
  }

  var scheduled = false;
  function scheduleFix() {
    if (scheduled) return;
    scheduled = true;
    setTimeout(function () { scheduled = false; fixTree(document); }, 0);
  }

  try {
    new MutationObserver(function (mutations) {
      for (var i = 0; i < mutations.length; i++) {
        var m = mutations[i];
        if (m.type === 'attributes') fixElement(m.target);
        else if (m.addedNodes) {
          for (var j = 0; j < m.addedNodes.length; j++) {
            var n = m.addedNodes[j];
            if (n.nodeType === 1) fixTree(n);
          }
        }
      }
    }).observe(document.documentElement, {
      childList: true, subtree: true,
      attributes: true, attributeFilter: ['href', 'src', 'srcset', 'action', 'formaction', 'poster', 'data-src', 'data-href', 'content']
    });
  } catch (e) {}

  var rawSetAttribute = Element.prototype.setAttribute;
  if (rawSetAttribute) {
    Element.prototype.setAttribute = function (name, value) {
      var key = String(name).toLowerCase();
      if (URL_ATTRS[key] || key === 'srcset' || key === 'data') {
        try { value = mapAttr(key, value); } catch (e) {}
      }
      return rawSetAttribute.call(this, name, value);
    };
  }

  function hookProp(proto, prop) {
    try {
      var d = Object.getOwnPropertyDescriptor(proto, prop);
      if (!d || !d.set || !d.get) return;
      Object.defineProperty(proto, prop, {
        configurable: true, enumerable: d.enumerable, get: d.get,
        set: function (v) { d.set.call(this, mapAttr(prop, v)); }
      });
    } catch (e) {}
  }
  hookProp(HTMLAnchorElement.prototype, 'href');
  hookProp(HTMLAreaElement.prototype, 'href');
  hookProp(HTMLImageElement.prototype, 'src');
  hookProp(HTMLScriptElement.prototype, 'src');
  hookProp(HTMLLinkElement.prototype, 'href');
  hookProp(HTMLIFrameElement.prototype, 'src');
  hookProp(HTMLFrameElement.prototype, 'src');
  hookProp(HTMLSourceElement.prototype, 'src');
  hookProp(HTMLVideoElement.prototype, 'src');
  hookProp(HTMLVideoElement.prototype, 'poster');
  hookProp(HTMLAudioElement.prototype, 'src');
  hookProp(HTMLFormElement.prototype, 'action');
  hookProp(HTMLObjectElement.prototype, 'data');

  /* ---------------------------------------------------------------- network APIs */
  var nativeFetch = window.fetch;
  if (nativeFetch) {
    window.fetch = function (input, init) {
      try {
        if (typeof input === 'string' || input instanceof URL) input = mapUrl(input);
        else if (input instanceof Request) {
          var mapped = mapUrl(input.url);
          if (mapped !== input.url) input = new Request(mapped, input);
        }
      } catch (e) {}
      return nativeFetch.call(this, input, init);
    };
  }

  var xhrOpen = XMLHttpRequest.prototype.open;
  XMLHttpRequest.prototype.open = function (method, url) {
    var args = Array.prototype.slice.call(arguments);
    args[1] = mapUrl(url);
    return xhrOpen.apply(this, args);
  };

  if (navigator.sendBeacon) {
    var nativeBeacon = navigator.sendBeacon.bind(navigator);
    navigator.sendBeacon = function (url, data) { return nativeBeacon(mapUrl(url), data); };
  }

  try {
    var NativeWS = window.WebSocket;
    window.WebSocket = class extends NativeWS {
      constructor(url, protocols) {
        if (protocols === undefined) super(mapWs(url));
        else super(mapWs(url), protocols);
      }
    };
  } catch (e) {}

  try {
    var NativeES = window.EventSource;
    if (NativeES) {
      window.EventSource = class extends NativeES {
        constructor(url, opts) { super(mapUrl(url), opts); }
      };
    }
  } catch (e) {}

  try {
    var NativeWorker = window.Worker;
    if (NativeWorker) {
      window.Worker = class extends NativeWorker {
        constructor(url, opts) { super(mapUrl(url), opts); }
      };
    }
    var NativeShared = window.SharedWorker;
    if (NativeShared) {
      window.SharedWorker = class extends NativeShared {
        constructor(url, opts) { super(mapUrl(url), opts); }
      };
    }
  } catch (e) {}

  var nativeOpen = window.open;
  window.open = function (url, name, features) {
    if (url !== undefined && url !== null && url !== '') {
      try { url = mapUrl(url); } catch (e) {}
    }
    return nativeOpen.call(window, url, name, features);
  };

  var nativePush = history.pushState;
  var nativeReplace = history.replaceState;
  history.pushState = function (state, title, url) {
    if (url !== undefined && url !== null) { try { url = mapUrl(url); } catch (e) {} }
    return nativePush.call(this, state, title, url);
  };
  history.replaceState = function (state, title, url) {
    if (url !== undefined && url !== null) { try { url = mapUrl(url); } catch (e) {} }
    return nativeReplace.call(this, state, title, url);
  };

  /* ---------------------------------------------------------------- cookies */
  function scopeCookie(value) {
    var parts = String(value).split(';');
    var out = [];
    var hadPath = false;
    for (var i = 0; i < parts.length; i++) {
      var part = parts[i].trim();
      if (!part) continue;
      var eq = part.indexOf('=');
      var key = (eq < 0 ? part : part.slice(0, eq)).trim().toLowerCase();
      if (key === 'domain') continue;
      if (key === 'path') {
        hadPath = true;
        var p = eq < 0 ? '/' : part.slice(eq + 1).trim();
        if (p.indexOf(PREFIX) !== 0) p = PREFIX + p.replace(/^\//, '');
        if (!p) p = PREFIX;
        out.push('Path=' + p);
        continue;
      }
      if (key === 'samesite' && /none/i.test(part) && location.protocol === 'https:') {
        out.push(part);
        if (!/;\s*secure\b/i.test(value)) out.push('Secure');
        continue;
      }
      out.push(part);
    }
    if (!hadPath) out.push('Path=' + PREFIX);
    return out.join('; ');
  }

  try {
    var cookieDesc = Object.getOwnPropertyDescriptor(Document.prototype, 'cookie');
    if (cookieDesc && cookieDesc.get && cookieDesc.set) {
      Object.defineProperty(document, 'cookie', {
        configurable: true,
        get: function () { return cookieDesc.get.call(document); },
        set: function (v) { cookieDesc.set.call(document, scopeCookie(v)); }
      });
    }
  } catch (e) {}

  /* ---------------------------------------------------------------- service workers */
  if (navigator.serviceWorker && navigator.serviceWorker.register) {
    var nativeRegister = navigator.serviceWorker.register.bind(navigator.serviceWorker);
    navigator.serviceWorker.register = function (script, options) {
      var opts = {};
      if (options) for (var k in options) if (Object.prototype.hasOwnProperty.call(options, k)) opts[k] = options[k];
      opts.scope = PREFIX;
      return nativeRegister(mapUrl(script), opts);
    };
  }

  /* ---------------------------------------------------------------- clicks and forms */
  document.addEventListener('click', function (ev) {
    var el = ev.target;
    while (el && el.nodeType === 1 && (el.tagName || '').toLowerCase() !== 'a') el = el.parentNode;
    if (!el || el.nodeType !== 1) return;
    if (el.hasAttribute && el.hasAttribute('download')) return;
    var href = el.getAttribute && el.getAttribute('href');
    if (!href || href.charAt(0) === '#') return;
    var u = parse(href);
    if (!u) return;
    if (/^(?:data|blob|mailto|tel|javascript|about):/i.test(href)) return;
    var external = u.origin !== location.origin && !isLocalHost(u.hostname);
    if (external) {
      ev.preventDefault();
      window.open(u.href, '_blank', 'noopener');
      return;
    }
    if (el.target === '_top' || el.target === '_parent') el.target = '_self';
    // Relative links and links already rewritten by the server resolve under the app prefix
    // natively, so target/rel/hash behavior stays intact.  Only an absolute URL aimed at a
    // loopback port needs to be remapped (for example an anchor created at runtime).
    var underPrefix = u.pathname === PREFIX.slice(0, -1) || u.pathname.indexOf(PREFIX) === 0;
    var underUi = u.origin === location.origin && u.pathname.indexOf('/browser/') === 0;
    if (underPrefix || underUi) return;
    var mapped = mapUrl(href);
    ev.preventDefault();
    if (el.target === '_blank') window.open(mapped, '_blank', 'noopener');
    else location.href = mapped;
  }, true);

  document.addEventListener('submit', function (ev) {
    var f = ev.target;
    if (!f || !f.getAttribute) return;
    var action = f.getAttribute('action');
    if (action) {
      var mapped = mapUrl(action);
      if (mapped !== action) { try { f.setAttribute('action', mapped); } catch (e) {} }
    }
    if (f.target === '_top' || f.target === '_parent') f.target = '_self';
  }, true);

  /* ---------------------------------------------------------------- initial pass */
  function start() {
    try {
      fixTree(document);
      var base = document.querySelector('base[href]');
      if (base) {
        var hv = base.getAttribute('href') || '';
        var mb = mapUrl(hv);
        if (mb !== hv) base.setAttribute('href', mb);
      }
    } catch (e) {}
  }
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', start, { once: true });
    scheduleFix();
  } else start();
})();
