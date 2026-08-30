// Code generated from the hsw shim template; edit shimjs.go (the const below),
// not this header. The shim provides the minimal browser surface hsw.js
// (v1 self-contained or v2 wasm-bindgen) needs inside a v8go isolate.
package hsw

const shimTemplate = `// hsw shim: minimal browser environment for hCaptcha hsw.js inside v8go.
//
// hsw.js ships in two families:
//   v1: window.hsw = function(jwt, fpB64) -> Promise<string>; self-contained,
//       assembles its own WASM from atob() chunks and instantiates it directly.
//   v2: wasm-bindgen output exporting hsw(jwt, fp); needs TextEncoder/
//       TextDecoder and a fetch mock that serves the embedded base64 WASM.
// The shim covers the union of both. V8 supplies Date/Math/JSON/Promise/
// WebAssembly/Proxy/Uint8Array; everything else below has to be provided.

var window = {};
var module = { exports: {} };
self = window;
globalThis.window = window;
globalThis.self = window;
globalThis.module = module;

if (typeof console === "undefined") {
  console = { log: function(){}, info: function(){}, warn: function(){}, error: function(){}, debug: function(){}, trace: function(){} };
}

// ---- base64 (lenient: tolerates -/_ and missing padding) ----
// Go injects native atob/btoa over these when available; the JS fallback
// keeps bundles working in any embedder.
if (typeof atob !== "function") {
  var __b64c = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  atob = function(input) {
    if (input == null) input = "";
    input = String(input).replace(/[\\s=]+/g, "").replace(/-/g, "+").replace(/_/g, "/");
    var out = "";
    var buffer = 0, bits = 0;
    for (var i = 0; i < input.length; i++) {
      var idx = __b64c.indexOf(input.charAt(i));
      if (idx < 0) continue;
      buffer = (buffer << 6) | idx;
      bits += 6;
      if (bits >= 8) {
        bits -= 8;
        out += String.fromCharCode((buffer >> bits) & 0xff);
      }
    }
    return out;
  };
  btoa = function(input) {
    input = String(input);
    var out = "";
    for (var i = 0; i < input.length; i += 3) {
      var b0 = input.charCodeAt(i), b1 = input.charCodeAt(i + 1), b2 = input.charCodeAt(i + 2);
      var n = ((b0 & 0xff) << 16) | ((b1 & 0xff) << 8) | (b2 & 0xff);
      out += __b64c.charAt((n >> 18) & 63) + __b64c.charAt((n >> 12) & 63);
      out += i + 1 < input.length ? __b64c.charAt((n >> 6) & 63) : "=";
      out += i + 2 < input.length ? __b64c.charAt(n & 63) : "=";
    }
    return out;
  };
}

// ---- TextEncoder / TextDecoder ----
if (typeof TextEncoder === "undefined") {
  TextEncoder = function() {};
  TextEncoder.prototype.encode = function(str) {
    str = String(str);
    var bytes = [];
    for (var i = 0; i < str.length; i++) {
      var c = str.charCodeAt(i);
      if (c < 0x80) { bytes.push(c); }
      else if (c < 0x800) { bytes.push(0xc0 | (c >> 6), 0x80 | (c & 63)); }
      else if (c >= 0xd800 && c <= 0xdbff && i + 1 < str.length) {
        var c2 = str.charCodeAt(i + 1);
        if (c2 >= 0xdc00 && c2 <= 0xdfff) {
          var cp = 0x10000 + ((c - 0xd800) << 10) + (c2 - 0xdc00);
          bytes.push(0xf0 | (cp >> 18), 0x80 | ((cp >> 12) & 63), 0x80 | ((cp >> 6) & 63), 0x80 | (cp & 63));
          i++;
        } else { bytes.push(0xef, 0xbf, 0xbd); }
      } else if (c >= 0xe000) {
        bytes.push(0xe0 | (c >> 12), 0x80 | ((c >> 6) & 63), 0x80 | (c & 63));
      } else { bytes.push(0xef, 0xbf, 0xbd); }
    }
    return new Uint8Array(bytes);
  };
  TextEncoder.prototype.encodeInto = function(str, dst) {
    var enc = this.encode(str);
    var written = Math.min(dst.length, enc.length);
    for (var i = 0; i < written; i++) dst[i] = enc[i];
    return { read: enc.length, written: written };
  };
}
if (typeof TextDecoder === "undefined") {
  TextDecoder = function(label, opts) { this.fatal = !!(opts && opts.fatal); };
  TextDecoder.prototype.decode = function(bytes) {
    if (!bytes) return "";
    var view = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
    var out = "";
    var i = 0;
    while (i < view.length) {
      var b = view[i];
      var cp = 0xfffd, n = 1;
      if (b < 0x80) { cp = b; n = 1; }
      else if ((b & 0xe0) === 0xc0) { cp = b & 31; n = 2; }
      else if ((b & 0xf0) === 0xe0) { cp = b & 15; n = 3; }
      else if ((b & 0xf8) === 0xf0) { cp = b & 7; n = 4; }
      var ok = true;
      for (var j = 1; j < n; j++) {
        var nb = view[i + j];
        if (nb === undefined || (nb & 0xc0) !== 0x80) { ok = false; break; }
        cp = (cp << 6) | (nb & 63);
      }
      if (!ok) { cp = 0xfffd; n = 1; }
      out += String.fromCharCode(cp > 0xffff ? 0xfffd : cp);
      i += n;
    }
    return out;
  };
}

// ---- performance ----
var __perfT0 = Date.now();
var performance = {
  now: function() { return Date.now() - __perfT0; },
  timeOrigin: __perfT0,
  mark: function() {}, measure: function() {},
  getEntriesByType: function() { return []; },
  getEntriesByName: function() { return []; },
  getEntries: function() { return []; },
  timing: { navigationStart: __perfT0, domContentLoadedEventEnd: __perfT0, loadEventEnd: __perfT0 }
};

// ---- timers (v8go has no event loop: fire immediately, best-effort) ----
var setTimeout = function(fn, ms) {
  if (typeof fn === "function") { try { fn(); } catch (e) {} }
  return 0;
};
var clearTimeout = function(id) {};
var setInterval = function() { return 0; };
var clearInterval = function(id) {};
var queueMicrotask = function(fn) { Promise.resolve().then(fn); };

// ---- navigator ----
var navigator = {
  userAgent: "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
  appVersion: "5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
  platform: "MacIntel",
  language: "en-US",
  languages: ["en-US", "en"],
  hardwareConcurrency: 8,
  deviceMemory: 8,
  maxTouchPoints: 0,
  webdriver: false,
  vendor: "Google Inc.",
  productSub: "20030107",
  cookieEnabled: true,
  doNotTrack: null,
  onLine: true,
  pdfViewerEnabled: false,
  plugins: { length: 0, item: function(){ return null; }, namedItem: function(){ return null; } },
  mimeTypes: { length: 0, item: function(){ return null; }, namedItem: function(){ return null; } },
  connection: { effectiveType: "4g", downlink: 10, rtt: 50, saveData: false },
  mediaDevices: { enumerateDevices: function() { return Promise.resolve([]); } },
  getBattery: function() { return Promise.resolve({ charging: false, level: 1 }); },
  permissions: { query: function() { return Promise.resolve({ state: "prompt" }); } },
  storage: { estimate: function() { return Promise.resolve({ usage: 0, quota: 1073741824 }); } }
};

// ---- localStorage (in-memory) ----
var __lsStore = {};
var localStorage = {
  getItem: function(k) { return Object.prototype.hasOwnProperty.call(__lsStore, k) ? __lsStore[k] : null; },
  setItem: function(k, v) { __lsStore[k] = String(v); },
  removeItem: function(k) { delete __lsStore[k]; },
  clear: function() { __lsStore = {}; },
  key: function(i) { return Object.keys(__lsStore)[i] || null; },
  get length() { return Object.keys(__lsStore).length; }
};

// ---- screen / viewport ----
var screen = { width: 1280, height: 900, availWidth: 1280, availHeight: 860, colorDepth: 24, pixelDepth: 24,
  orientation: { type: "landscape-primary", angle: 0 } };
var devicePixelRatio = 2;
var innerWidth = 1280, innerHeight = 800, outerWidth = 1280, outerHeight = 900;
var scrollX = 0, scrollY = 0, pageXOffset = 0, pageYOffset = 0;
var visualViewport = { width: 1280, height: 800, offsetLeft: 0, offsetTop: 0, pageLeft: 0, pageTop: 0, scale: 1,
  addEventListener: function(){}, removeEventListener: function(){} };

// ---- crypto (Math.random based) ----
var crypto = {
  getRandomValues: function(arr) {
    for (var i = 0; i < arr.length; i++) arr[i] = Math.floor(Math.random() * 256);
    return arr;
  },
  randomUUID: function() {
    return "xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx".replace(/[xy]/g, function(c) {
      var r = Math.random() * 16 | 0;
      var v = c === "x" ? r : (r & 0x3) | 0x8;
      return v.toString(16);
    });
  }
};

// ---- event constructors ----
var __evtNames = ["Event","CustomEvent","MouseEvent","KeyboardEvent","TouchEvent","PointerEvent","WheelEvent","InputEvent","FocusEvent","ClipboardEvent","DragEvent","AnimationEvent","TransitionEvent","CompositionEvent"];
for (var __ei = 0; __ei < __evtNames.length; __ei++) {
  (function(name) {
    if (typeof globalThis[name] !== "undefined") return;
    var F = function(type, init) {
      this.type = String(type);
      this.target = null; this.currentTarget = null; this.srcElement = null;
      this.timeStamp = Date.now();
      this.bubbles = !!(init && init.bubbles); this.cancelable = !!(init && init.cancelable);
      this.detail = init && init.detail !== undefined ? init.detail : 0;
      this.clientX = 0; this.clientY = 0; this.screenX = 0; this.screenY = 0; this.pageX = 0; this.pageY = 0;
      this.button = 0; this.buttons = 0; this.key = ""; this.code = ""; this.keyCode = 0; this.which = 0;
      this.data = null; this.inputType = ""; this.isTrusted = false; this.defaultPrevented = false;
      this.composed = false;
    };
    F.prototype.preventDefault = function() { this.defaultPrevented = true; };
    F.prototype.stopPropagation = function() {};
    F.prototype.stopImmediatePropagation = function() {};
    F.prototype.composedPath = function() { return []; };
    globalThis[name] = F;
  })(__evtNames[__ei]);
}

// ---- minimal element ----
function __hswEl() {
  var el = {
    style: {}, dataset: {},
    children: [], childNodes: [], attributes: {},
    classList: { add: function(){}, remove: function(){}, toggle: function(){}, contains: function(){ return false; } },
    setAttribute: function(k, v) { this.attributes[k] = String(v); },
    getAttribute: function(k) { return Object.prototype.hasOwnProperty.call(this.attributes, k) ? this.attributes[k] : null; },
    removeAttribute: function(k) { delete this.attributes[k]; },
    appendChild: function(c) { this.children.push(c); c.parentNode = this; return c; },
    removeChild: function(c) { var i = this.children.indexOf(c); if (i >= 0) this.children.splice(i, 1); return c; },
    insertBefore: function(c, ref) { this.children.push(c); c.parentNode = this; return c; },
    addEventListener: function(){}, removeEventListener: function(){},
    dispatchEvent: function() { return true; },
    focus: function(){}, blur: function(){}, click: function(){},
    getContext: function() {
      return { fillRect: function(){}, clearRect: function(){}, strokeRect: function(){},
        getImageData: function() { return { data: new Uint8ClampedArray(4), width: 0, height: 0 }; },
        putImageData: function(){}, measureText: function() { return { width: 0 }; },
        fillText: function(){}, strokeText: function(){}, beginPath: function(){}, arc: function(){},
        rect: function(){}, fill: function(){}, stroke: function(){}, moveTo: function(){}, lineTo: function(){},
        quadraticCurveTo: function(){}, bezierCurveTo: function(){}, closePath: function(){}, clip: function(){},
        save: function(){}, restore: function(){}, translate: function(){}, scale: function(){}, rotate: function(){},
        drawImage: function(){}, setTransform: function(){}, transform: function(){}, globalAlpha: 1,
        globalCompositeOperation: "source-over", fillStyle: "#000000", strokeStyle: "#000000",
        lineWidth: 1, textAlign: "start", textBaseline: "alphabetic", font: "10px sans-serif",
        shadowBlur: 0, shadowColor: "rgba(0, 0, 0, 0)", shadowOffsetX: 0, shadowOffsetY: 0,
        canvas: el };
    },
    getBoundingClientRect: function() { return { top: 0, left: 0, width: 0, height: 0, right: 0, bottom: 0, x: 0, y: 0 }; },
    cloneNode: function() { return __hswEl(); },
    querySelector: function() { return null; },
    querySelectorAll: function() { return []; },
    matches: function() { return false; },
    closest: function() { return null; },
    contains: function() { return false; },
    toString: function() { return "[object HTMLUnknownElement]"; },
    offsetWidth: 0, offsetHeight: 0, clientWidth: 0, clientHeight: 0,
    textContent: "", innerHTML: "", innerText: "", value: "", checked: false,
    parentNode: null, parentElement: null, firstChild: null, lastChild: null,
    nextSibling: null, previousSibling: null, nodeType: 1, nodeName: "DIV", tagName: "DIV",
    width: 0, height: 0, tabIndex: -1, rel: "", href: "", src: "", type: "", id: "", className: "", title: "",
    hidden: false, disabled: false, readOnly: false, required: false,
    offsetParent: null, scrollWidth: 0, scrollHeight: 0, scrollTop: 0, scrollLeft: 0,
    isConnected: false, ownerDocument: null
  };
  return el;
}

// ---- document ----
var document = {
  documentElement: __hswEl(),
  body: __hswEl(),
  head: __hswEl(),
  createElement: function(tag) { var e = __hswEl(); e.tagName = String(tag).toUpperCase(); e.nodeName = e.tagName; e.localName = String(tag).toLowerCase(); return e; },
  createElementNS: function(ns, tag) { return this.createElement(tag); },
  createTextNode: function(t) { return { nodeType: 3, textContent: t, nodeValue: t, data: t, length: String(t).length }; },
  createDocumentFragment: function() { return { nodeType: 11, children: [], childNodes: [], firstChild: null, appendChild: function(c){ this.children.push(c); return c; } }; },
  createComment: function(t) { return { nodeType: 8, textContent: t, nodeValue: t }; },
  querySelector: function() { return null; },
  querySelectorAll: function() { return { length: 0, item: function(){ return null; } }; },
  getElementById: function() { return null; },
  getElementsByClassName: function() { return { length: 0, item: function(){ return null; } }; },
  getElementsByTagName: function() { return { length: 0, item: function(){ return null; } }; },
  getElementsByName: function() { return { length: 0, item: function(){ return null; } }; },
  addEventListener: function(){}, removeEventListener: function(){},
  dispatchEvent: function() { return true; },
  adoptNode: function(n) { return n; },
  importNode: function(n) { return n; },
  elementFromPoint: function() { return null; },
  elementsFromPoint: function() { return []; },
  fonts: { check: function(){ return false; }, ready: Promise.resolve(), size: 0, status: "loaded",
    addEventListener: function(){}, removeEventListener: function(){},
    entry: function(){ return undefined; }, keys: function(){ return [][Symbol.iterator](); }, values: function(){ return [][Symbol.iterator](); }, entries: function(){ return [][Symbol.iterator](); } },
  styleSheets: { length: 0, item: function(){ return null; } },
  hidden: false, visibilityState: "visible", readyState: "complete", title: "",
  URL: "https://build.nvidia.com/", referrer: "", cookie: "", domain: "build.nvidia.com",
  characterSet: "UTF-8", contentType: "text/html",
  hasFocus: function() { return true; },
  exitFullscreen: function() { return Promise.resolve(); },
  fullscreenElement: null, activeElement: __hswEl(),
  defaultView: null,
  currentScript: null,
  location: null,
  implementation: { createHTMLDocument: function(t) { return { body: __hswEl(), createElement: function(tag){ return __hswEl(); } }; } }
};

// ---- getComputedStyle ----
var getComputedStyle = function(el, pseudo) {
  var s = {
    getPropertyValue: function(p) { return ""; },
    item: function() { return ""; },
    cssText: "", length: 0,
    position: "static", display: "block", visibility: "visible", opacity: "1", zIndex: "auto",
    width: "0px", height: "0px", top: "0px", left: "0px", right: "0px", bottom: "0px",
    transform: "none", transition: "all 0s ease 0s", animation: "none 0s ease 0s 1 normal none running",
    backgroundColor: "rgba(0, 0, 0, 0)", color: "rgb(0, 0, 0)", fontFamily: "sans-serif", fontSize: "16px",
    lineHeight: "normal", letterSpacing: "normal", wordSpacing: "0px", fontWeight: "400",
    paddingTop: "0px", paddingRight: "0px", paddingBottom: "0px", paddingLeft: "0px",
    marginTop: "0px", marginRight: "0px", marginBottom: "0px", marginLeft: "0px",
    borderTopWidth: "0px", borderRightWidth: "0px", borderBottomWidth: "0px", borderLeftWidth: "0px",
    borderTopStyle: "none", borderRightStyle: "none", borderBottomStyle: "none", borderLeftStyle: "none",
    overflow: "visible", overflowX: "visible", overflowY: "visible",
    boxShadow: "none", textShadow: "none", borderRadius: "0px",
    userSelect: "auto", pointerEvents: "auto", cursor: "auto", clip: "auto", filter: "none",
    mixBlendMode: "normal", isolation: "auto", scrollbarWidth: "auto",
    writingMode: "horizontal-tb", direction: "ltr", unicodeBidi: "normal",
    backgroundImage: "none", backgroundSize: "auto", backgroundPosition: "0% 0%", backgroundRepeat: "repeat"
  };
  return s;
};

// ---- misc constructors / globals ----
var matchMedia = function(q) {
  return { matches: false, media: String(q), onchange: null,
    addListener: function(){}, removeListener: function(){}, addEventListener: function(){}, removeEventListener: function(){} };
};
var history = { length: 1, state: null, scrollRestoration: "auto",
  pushState: function(){}, replaceState: function(){}, back: function(){}, forward: function(){}, go: function(){} };
var location = { href: "https://build.nvidia.com/", protocol: "https:", host: "build.nvidia.com",
  hostname: "build.nvidia.com", port: "", pathname: "/", search: "", hash: "", origin: "https://build.nvidia.com",
  assign: function(){}, replace: function(){}, reload: function(){} };
var Audio = function() {
  return { play: function(){ return Promise.resolve(); }, pause: function(){}, load: function(){},
    addEventListener: function(){}, removeEventListener: function(){}, canPlayType: function(){ return ""; },
    currentTime: 0, duration: NaN, volume: 1, muted: false, paused: true, src: "", ended: false,
    readyState: 0, networkState: 0, playbackRate: 1, loop: false, autoplay: false, preload: "auto" };
};
var Image = function(w, h) {
  var i = __hswEl(); i.width = w || 0; i.height = h || 0; i.src = ""; i.complete = false;
  i.naturalWidth = 0; i.naturalHeight = 0; i.decode = function() { return Promise.resolve(); };
  i.onload = null; i.onerror = null; return i;
};
var requestAnimationFrame = function(fn) { if (typeof fn === "function") { try { fn(Date.now()); } catch (e) {} } return 1; };
var cancelAnimationFrame = function(id) {};
var getSelection = function() {
  return { toString: function(){ return ""; }, rangeCount: 0, removeAllRanges: function(){},
    addRange: function(){}, collapse: function(){}, collapseToStart: function(){}, collapseToEnd: function(){} };
  };
var open = function() { return null; };
var close = function() {};
var alert = function() {}; var confirm = function() { return true; }; var prompt = function() { return null; };
var scrollTo = function() {}; var scroll = function() {}; var focus = function() {}; var blur = function() {};
var postMessage = function() {}; var structuredClone = function(v) { return JSON.parse(JSON.stringify(v)); };

// ---- fetch mock: serves the embedded v2 WASM, 404 for everything else ----
var __hsw_wasm = "__HSW_WASM_B64__";
if (typeof fetch !== "function") {
  fetch = function(input, init) {
    var url = typeof input === "string" ? input : (input && input.url) || "";
    var bin = null;
    if (__hsw_wasm && __hsw_wasm.length > 0 && url.toLowerCase().indexOf("wasm") >= 0) {
      var raw = atob(__hsw_wasm);
      var arr = new Uint8Array(raw.length);
      for (var i = 0; i < raw.length; i++) arr[i] = raw.charCodeAt(i);
      bin = arr;
    }
    var ok = !!bin;
    return Promise.resolve({
      ok: ok, status: ok ? 200 : 404, statusText: ok ? "OK" : "Not Found",
      url: url,
      headers: { get: function(){ return null; }, has: function(){ return false; } },
      arrayBuffer: function() { return Promise.resolve(bin ? bin.buffer : new ArrayBuffer(0)); },
      json: function() { return Promise.reject(new Error("Not Found")); },
      text: function() { return Promise.resolve(bin ? "" : "Not Found"); },
      blob: function() { return Promise.resolve(new Blob([])); },
      clone: function() { return this; }
    });
  };
}
if (typeof Blob === "undefined") {
  Blob = function(parts, opts) {
    this.type = (opts && opts.type) || "";
    this._chunks = [];
    var total = 0;
    try {
      for (var i = 0; i < (parts || []).length; i++) {
        var p = parts[i];
        if (typeof p === "string") { this._chunks.push(p); total += p.length; }
        else if (p instanceof Uint8Array) { this._chunks.push(p); total += p.length; }
        else if (p && p.buffer instanceof ArrayBuffer) { var v = new Uint8Array(p.buffer); this._chunks.push(v); total += v.length; }
      }
    } catch (e) {}
    this.size = total;
  };
  Blob.prototype.arrayBuffer = function() {
    var self = this;
    return Promise.resolve().then(function() {
      var enc = typeof TextEncoder !== "undefined" ? new TextEncoder() : null;
      var total = 0;
      var parts = [];
      for (var i = 0; i < self._chunks.length; i++) {
        var c = self._chunks[i];
        var u = typeof c === "string" ? (enc ? enc.encode(c) : new Uint8Array(0)) : c;
        parts.push(u); total += u.length;
      }
      var out = new Uint8Array(total);
      var off = 0;
      for (var j = 0; j < parts.length; j++) { out.set(parts[j], off); off += parts[j].length; }
      return out.buffer;
    });
  };
  Blob.prototype.text = function() { var self = this; return this.arrayBuffer().then(function(buf) {
    var td = typeof TextDecoder !== "undefined" ? new TextDecoder() : null;
    return td ? td.decode(new Uint8Array(buf)) : String(self._chunks.join("")); }); };
  Blob.prototype.slice = function() { return new Blob([]); };
  Blob.prototype.stream = function() { return null; };
}

// ---- expose the environment on window ----
window.navigator = navigator;
window.document = document;
window.localStorage = localStorage;
window.performance = performance;
window.crypto = crypto;
window.screen = screen;
window.history = history;
window.location = location;
window.matchMedia = matchMedia;
window.getComputedStyle = getComputedStyle;
window.Audio = Audio;
window.Image = Image;
window.visualViewport = visualViewport;
window.TextEncoder = TextEncoder;
window.TextDecoder = TextDecoder;
window.fetch = fetch;
window.Blob = Blob;
window.requestAnimationFrame = requestAnimationFrame;
window.devicePixelRatio = devicePixelRatio;
window.innerWidth = innerWidth;
window.innerHeight = innerHeight;
window.outerWidth = outerWidth;
window.outerHeight = outerHeight;
`

// buildShim returns the wrapper script: environment shim + patched bundle +
// export wiring. wasmB64, when present, is the embedded v2 WASM that the
// fetch mock serves for __wbg_fetch-style calls.
func buildShim(wasmB64 string) string {
	return replaceAll(shimTemplate, "__HSW_WASM_B64__", wasmB64)
}

func replaceAll(s, old, new string) string {
	for {
		i := indexOf(s, old)
		if i < 0 {
			return s
		}
		s = s[:i] + new + s[i+len(old):]
	}
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
