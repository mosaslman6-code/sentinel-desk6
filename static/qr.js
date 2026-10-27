/* Minimal QR Code generator for SentinelDesk: byte mode, error correction level M, versions 1-9 (up to 180 bytes).
   Used only to show the two-factor setup code locally - the secret never leaves the browser.  QR.svg(text, sizePx) -> SVG string. */
var QR = (function () {
  "use strict";
  // version: [total codewords, EC codewords per block, blocks in group 1, data per block g1, blocks in group 2, data per block g2]
  var SPEC = { 1: [26, 10, 1, 16, 0, 0], 2: [44, 16, 1, 28, 0, 0], 3: [70, 26, 1, 44, 0, 0], 4: [100, 18, 2, 32, 0, 0], 5: [134, 24, 2, 43, 0, 0],
    6: [172, 16, 4, 27, 0, 0], 7: [196, 18, 4, 31, 0, 0], 8: [242, 22, 2, 38, 2, 39], 9: [292, 22, 3, 36, 2, 37] };
  var ALIGN = { 1: [], 2: [6, 18], 3: [6, 22], 4: [6, 26], 5: [6, 30], 6: [6, 34], 7: [6, 22, 38], 8: [6, 24, 42], 9: [6, 26, 46] };

  var EXP = [], LOG = [], i;
  (function () { var x = 1; for (var k = 0; k < 255; k++) { EXP[k] = x; LOG[x] = k; x <<= 1; if (x & 256) x ^= 0x11d; } for (k = 255; k < 512; k++) EXP[k] = EXP[k - 255]; })();
  function gmul(a, b) { return a && b ? EXP[LOG[a] + LOG[b]] : 0; }
  function generator(n) {
    var g = [1];
    for (var k = 0; k < n; k++) {
      var ng = []; for (var j = 0; j <= g.length; j++) ng[j] = 0;
      for (j = 0; j < g.length; j++) { ng[j] ^= g[j]; ng[j + 1] ^= gmul(g[j], EXP[k]); }
      g = ng;
    }
    return g;
  }
  function remainder(data, n) {
    var g = generator(n), r = [], k;
    for (k = 0; k < n; k++) r[k] = 0;
    for (k = 0; k < data.length; k++) {
      var f = data[k] ^ r.shift(); r.push(0);
      if (f) for (var j = 0; j < n; j++) r[j] ^= gmul(g[j + 1], f);
    }
    return r;
  }

  function toBytes(text) { var s = unescape(encodeURIComponent(text)), out = []; for (var k = 0; k < s.length; k++) out.push(s.charCodeAt(k)); return out; }
  function dataCapacity(v) { var s = SPEC[v]; return s[2] * s[3] + s[4] * s[5]; }

  function encode(bytes) {
    var v = 1; while (v <= 9 && dataCapacity(v) * 8 < 4 + 8 + 8 * bytes.length) v++;
    if (v > 9) throw new Error("Text too long for the QR code");
    var bits = [];
    var put = function (val, len) { for (var k = len - 1; k >= 0; k--) bits.push((val >>> k) & 1); };
    put(4, 4); put(bytes.length, 8); bytes.forEach(function (b) { put(b, 8); });
    var cap = dataCapacity(v) * 8;
    put(0, Math.min(4, cap - bits.length));
    while (bits.length % 8) bits.push(0);
    var words = [], k;
    for (k = 0; k < bits.length; k += 8) { var w = 0; for (var j = 0; j < 8; j++) w = (w << 1) | bits[k + j]; words.push(w); }
    for (k = 0; words.length < dataCapacity(v); k++) words.push(k % 2 ? 0x11 : 0xEC);
    // split into blocks, add Reed-Solomon codewords, interleave
    var s = SPEC[v], blocks = [], pos = 0;
    for (k = 0; k < s[2] + s[4]; k++) { var len = k < s[2] ? s[3] : s[5]; blocks.push(words.slice(pos, pos + len)); pos += len; }
    var ecc = blocks.map(function (b) { return remainder(b, s[1]); }), out = [];
    var maxLen = Math.max(s[3], s[5]);
    for (k = 0; k < maxLen; k++) blocks.forEach(function (b) { if (k < b.length) out.push(b[k]); });
    for (k = 0; k < s[1]; k++) ecc.forEach(function (e) { out.push(e[k]); });
    return { version: v, codewords: out };
  }

  function build(version, codewords) {
    var size = 17 + 4 * version, mod = [], fn = [], y, x;
    for (y = 0; y < size; y++) { mod.push(new Array(size).fill(false)); fn.push(new Array(size).fill(false)); }
    var set = function (x, y, dark) { mod[y][x] = dark; fn[y][x] = true; };
    for (i = 0; i < size; i++) { set(6, i, i % 2 === 0); set(i, 6, i % 2 === 0); }
    var finder = function (cx, cy) {
      for (var dy = -4; dy <= 4; dy++) for (var dx = -4; dx <= 4; dx++) {
        var d = Math.max(Math.abs(dx), Math.abs(dy)), xx = cx + dx, yy = cy + dy;
        if (xx >= 0 && xx < size && yy >= 0 && yy < size) set(xx, yy, d !== 2 && d !== 4);
      }
    };
    finder(3, 3); finder(size - 4, 3); finder(3, size - 4);
    var al = ALIGN[version], last = al.length - 1;
    al.forEach(function (ay, a) { al.forEach(function (ax, b) {
      if ((a === 0 && b === 0) || (a === 0 && b === last) || (a === last && b === 0)) return;
      for (var dy = -2; dy <= 2; dy++) for (var dx = -2; dx <= 2; dx++) set(ax + dx, ay + dy, Math.max(Math.abs(dx), Math.abs(dy)) !== 1);
    }); });
    // reserve format areas (real values are drawn per mask later) and draw version information
    var drawFormat = function (m, mask) {
      var data = (0 << 3) | mask, rem = data, k;                       // error-correction level M = 00
      for (k = 0; k < 10; k++) rem = (rem << 1) ^ ((rem >>> 9) * 0x537);
      var bits = ((data << 10) | rem) ^ 0x5412, bit = function (n) { return ((bits >>> n) & 1) !== 0; };
      var put = function (x, y, d) { m[y][x] = d; };
      for (k = 0; k <= 5; k++) put(8, k, bit(k));
      put(8, 7, bit(6)); put(8, 8, bit(7)); put(7, 8, bit(8));
      for (k = 9; k < 15; k++) put(14 - k, 8, bit(k));
      for (k = 0; k < 8; k++) put(size - 1 - k, 8, bit(k));
      for (k = 8; k < 15; k++) put(8, size - 15 + k, bit(k));
      put(8, size - 8, true);
    };
    for (i = 0; i < 9; i++) { fn[8][i] = fn[i][8] = true; }
    for (i = 0; i < 8; i++) { fn[8][size - 1 - i] = fn[size - 1 - i][8] = true; }
    fn[size - 8][8] = true; mod[size - 8][8] = true;
    if (version >= 7) {
      var rem = version, k2;
      for (k2 = 0; k2 < 12; k2++) rem = (rem << 1) ^ ((rem >>> 11) * 0x1F25);
      var vb = (version << 12) | rem;
      for (k2 = 0; k2 < 18; k2++) { var d = ((vb >>> k2) & 1) !== 0, a = size - 11 + (k2 % 3), b = Math.floor(k2 / 3); set(a, b, d); set(b, a, d); }
    }
    // place data bits in the zig-zag order
    var n = 0, total = codewords.length * 8;
    for (var right = size - 1; right >= 1; right -= 2) {
      if (right === 6) right = 5;
      for (var vert = 0; vert < size; vert++) for (var j = 0; j < 2; j++) {
        var xx = right - j, up = ((right + 1) & 2) === 0, yy = up ? size - 1 - vert : vert;
        if (!fn[yy][xx] && n < total) { mod[yy][xx] = ((codewords[n >>> 3] >>> (7 - (n & 7))) & 1) !== 0; n++; }
      }
    }
    var masks = [
      function (x, y) { return (x + y) % 2 === 0; }, function (x, y) { return y % 2 === 0; }, function (x, y) { return x % 3 === 0; },
      function (x, y) { return (x + y) % 3 === 0; }, function (x, y) { return (Math.floor(x / 3) + Math.floor(y / 2)) % 2 === 0; },
      function (x, y) { return x * y % 2 + x * y % 3 === 0; }, function (x, y) { return (x * y % 2 + x * y % 3) % 2 === 0; },
      function (x, y) { return ((x + y) % 2 + x * y % 3) % 2 === 0; }];
    var best = null, bestScore = Infinity;
    masks.forEach(function (f, mi) {
      var m = mod.map(function (row) { return row.slice(); });
      for (var yy = 0; yy < size; yy++) for (var xx = 0; xx < size; xx++) if (!fn[yy][xx] && f(xx, yy)) m[yy][xx] = !m[yy][xx];
      drawFormat(m, mi);
      var sc = penalty(m, size);
      if (sc < bestScore) { bestScore = sc; best = m; }
    });
    return { size: size, modules: best };
  }

  function penalty(m, size) {
    var score = 0, x, y, dark = 0, line, runs;
    var rows = [], cols = [];
    for (y = 0; y < size; y++) { rows.push(m[y].map(function (v) { return v ? "1" : "0"; }).join("")); }
    for (x = 0; x < size; x++) { var s = ""; for (y = 0; y < size; y++) s += m[y][x] ? "1" : "0"; cols.push(s); }
    rows.concat(cols).forEach(function (l) {
      runs = l.match(/0+|1+/g) || []; runs.forEach(function (r) { if (r.length >= 5) score += 3 + (r.length - 5); });
      var p = 0, q; while ((q = l.indexOf("10111010000", p)) >= 0) { score += 40; p = q + 1; }
      p = 0; while ((q = l.indexOf("00001011101", p)) >= 0) { score += 40; p = q + 1; }
    });
    for (y = 0; y < size - 1; y++) for (x = 0; x < size - 1; x++) { var c = m[y][x]; if (c === m[y][x + 1] && c === m[y + 1][x] && c === m[y + 1][x + 1]) score += 3; }
    for (y = 0; y < size; y++) for (x = 0; x < size; x++) if (m[y][x]) dark++;
    var tot = size * size; score += (Math.ceil(Math.abs(dark * 20 - tot * 10) / tot) - 1) * 10;
    return score;
  }

  function svg(text, px) {
    var e = encode(toBytes(text)), q = build(e.version, e.codewords), border = 4, n = q.size + border * 2, d = "";
    for (var y = 0; y < q.size; y++) for (var x = 0; x < q.size; x++) if (q.modules[y][x]) d += "M" + (x + border) + " " + (y + border) + "h1v1h-1z";
    return '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ' + n + " " + n + '" width="' + (px || 220) + '" height="' + (px || 220) + '" shape-rendering="crispEdges" role="img">' +
      '<rect width="' + n + '" height="' + n + '" fill="#fff"/><path d="' + d + '" fill="#000"/></svg>';
  }
  return { svg: svg };
})();
