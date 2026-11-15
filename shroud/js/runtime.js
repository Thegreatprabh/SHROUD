/* SHROUD runtime template (v1).
 *
 * Prepended to protected output by shroud/js/node/protect.js, which
 * substitutes the __SHROUD_*__ placeholders below.
 *
 * Placeholders (substituted at build time by protect.js; the tokens
 * themselves appear only in the code below, never in this comment):
 *   - the string table: JSON array of base64-encoded XOR-encrypted
 *     string literals.
 *   - the key: JSON array of key bytes (per-build key).
 *   - the integrity hash: hex SHA-256 of the string table joined with
 *     "\n"; empty string disables the check.
 *   - the domains: JSON array of allowed hostnames (domain lock).
 *   - the anti-debug flag: true/false.
 *
 * Honest limit: this raises the cost of reversal; it does not make the
 * protected code impossible to reverse. The key and the table ship inside
 * the output, so a determined reader can always decode the strings.
 */
var _shroud_table = __SHROUD_TABLE__;
var _shroud_key = __SHROUD_KEY__;
var _shroud_integrity = "__SHROUD_INTEGRITY_HASH__";

/* Compact SHA-256 (ASCII input only; callers UTF-8 encode first). */
function _shroud_sha256(ascii) {
  function _rr(value, amount) {
    return (value >>> amount) | (value << (32 - amount));
  }
  var _pow = Math.pow;
  var _maxWord = _pow(2, 32);
  var i, j;
  var result = "";
  var words = [];
  var asciiBitLength = ascii.length * 8;
  var hash = _shroud_sha256.h = _shroud_sha256.h || [];
  var k = _shroud_sha256.k = _shroud_sha256.k || [];
  var primeCounter = k.length;
  var isComposite = {};
  for (var candidate = 2; primeCounter < 64; candidate++) {
    if (!isComposite[candidate]) {
      for (i = 0; i < 313; i += candidate) {
        isComposite[i] = candidate;
      }
      hash[primeCounter] = (_pow(candidate, 0.5) * _maxWord) | 0;
      k[primeCounter++] = (_pow(candidate, 1 / 3) * _maxWord) | 0;
    }
  }
  ascii += "\x80";
  while (ascii.length % 64 - 56) {
    ascii += "\x00";
  }
  for (i = 0; i < ascii.length; i++) {
    j = ascii.charCodeAt(i);
    if (j >> 8) {
      return "";
    }
    words[i >> 2] |= j << ((3 - i) % 4) * 8;
  }
  words[words.length] = ((asciiBitLength / _maxWord) | 0);
  words[words.length] = (asciiBitLength);
  for (j = 0; j < words.length;) {
    var w = words.slice(j, j += 16);
    var oldHash = hash;
    hash = hash.slice(0, 8);
    for (i = 0; i < 64; i++) {
      var w15 = w[i - 15];
      var w2 = w[i - 2];
      var a = hash[0];
      var e = hash[4];
      var temp1 = hash[7]
        + (_rr(e, 6) ^ _rr(e, 11) ^ _rr(e, 25))
        + ((e & hash[5]) ^ ((~e) & hash[6]))
        + k[i]
        + (w[i] = (i < 16) ? w[i] : (
          w[i - 16]
          + (_rr(w15, 7) ^ _rr(w15, 18) ^ (w15 >>> 3))
          + w[i - 7]
          + (_rr(w2, 17) ^ _rr(w2, 19) ^ (w2 >>> 10))
        ) | 0);
      var temp2 = (_rr(a, 2) ^ _rr(a, 13) ^ _rr(a, 22))
        + ((a & hash[1]) ^ (a & hash[2]) ^ (hash[1] & hash[2]));
      hash = [(temp1 + temp2) | 0].concat(hash);
      hash[4] = (hash[4] + temp1) | 0;
    }
    for (i = 0; i < 8; i++) {
      hash[i] = (hash[i] + oldHash[i]) | 0;
    }
  }
  for (i = 0; i < 8; i++) {
    for (j = 3; j + 1; j--) {
      var b = (hash[i] >> (j * 8)) & 255;
      result += ((b < 16) ? 0 : "") + b.toString(16);
    }
  }
  return result;
}

/* UTF-8 encode a JS string into a byte-string for _shroud_sha256. */
function _shroud_utf8(s) {
  return unescape(encodeURIComponent(s));
}

/* Decode string-table entry `idx`: base64 -> XOR with the per-build key
 * -> UTF-8 text. Works in Node (Buffer) and browsers (atob/TextDecoder). */
function _shroud_dec(idx) {
  var enc = _shroud_table[idx];
  var raw;
  var i;
  if (typeof Buffer !== "undefined") {
    raw = Buffer.from(enc, "base64");
  } else {
    var bin = atob(enc);
    raw = new Uint8Array(bin.length);
    for (i = 0; i < bin.length; i++) {
      raw[i] = bin.charCodeAt(i);
    }
  }
  var bytes = new Uint8Array(raw.length);
  for (i = 0; i < raw.length; i++) {
    bytes[i] = raw[i] ^ _shroud_key[i % _shroud_key.length];
  }
  if (typeof TextDecoder !== "undefined") {
    return new TextDecoder().decode(bytes);
  }
  return Buffer.from(bytes).toString("utf8");
}

/* Integrity: the string table must hash to the build-time value. Any edit
 * to a table entry changes the hash and throws here, before user code runs. */
if (_shroud_integrity !== "") {
  (function () {
    var _h = _shroud_sha256(_shroud_utf8(_shroud_table.join("\n")));
    if (_h !== _shroud_integrity) {
      throw new Error("SHROUD: integrity check failed");
    }
  })();
}

/* Anti-debug: a `debugger` statement that only pauses when a debugger is
 * attached. With no debugger attached this costs ~0 ms and never throws. */
if (__SHROUD_ANTI_DEBUG__) {
  (function () {
    var _t0 = Date.now();
    debugger;
    var _t1 = Date.now();
    if (_t1 - _t0 > 100) {
      throw new Error("SHROUD: debugger detected");
    }
  })();
}

/* Domain lock (browser only). In Node `location` is undefined and the
 * check is skipped, so protected scripts still run under Node. */
(function () {
  var _domains = __SHROUD_DOMAINS__;
  if (_domains.length && typeof location !== "undefined" && location && location.hostname) {
    // Hostnames are case-insensitive: compare lowercased on both sides.
    var _host = String(location.hostname).toLowerCase();
    var _allowed = false;
    for (var i = 0; i < _domains.length; i++) {
      if (String(_domains[i]).toLowerCase() === _host) { _allowed = true; break; }
    }
    if (!_allowed) {
      throw new Error("SHROUD: domain not allowed: " + location.hostname);
    }
  }
})();
