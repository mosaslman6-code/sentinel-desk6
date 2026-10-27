"use strict";
/* SentinelDesk 2.0 - core: helpers, i18n, icons, charts, shell, command palette, notifications. */
var $ = function (s, r) { return (r || document).querySelector(s); };
var $$ = function (s, r) { return Array.prototype.slice.call((r || document).querySelectorAll(s)); };
var store = {
  get: function (k) { try { return localStorage.getItem(k); } catch (e) { return null; } },
  set: function (k, v) { try { localStorage.setItem(k, v); } catch (e) {} }
};
var ME = null, META = null, seq = 0;
var LANG = store.get("sd.lang") || ((navigator.language || "").slice(0, 2) === "ar" ? "ar" : "en");
var THEME = store.get("sd.theme") || "light";

function esc(s) { return String(s == null ? "" : s).replace(/[&<>"']/g, function (c) { return { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]; }); }
function t(s, v) {
  var r = (LANG === "ar" && window.AR && window.AR[s]) || s;
  return v ? r.replace(/\{(\w+)\}/g, function (m, k) { return v[k] !== undefined ? v[k] : m; }) : r;
}
function locale() { return LANG === "ar" ? "ar-u-nu-latn" : "en-GB"; }
function applyLang() {
  document.documentElement.lang = LANG;
  document.documentElement.dir = LANG === "ar" ? "rtl" : "ltr";
  $$("[data-i18n]").forEach(function (e) { e.textContent = t(e.dataset.i18n); });
  $$("[data-i18n-ph]").forEach(function (e) { e.placeholder = t(e.dataset.i18nPh); });
  $$("[data-i18n-title]").forEach(function (e) { e.title = t(e.dataset.i18nTitle); e.setAttribute("aria-label", t(e.dataset.i18nTitle)); });
  $$("#langLbl,#langLbl2").forEach(function (lb) { lb.textContent = LANG === "ar" ? "EN" : "ع"; });
}
function applyTheme() {
  document.documentElement.dataset.theme = THEME;
  $$(".themeBtn").forEach(function (b) { b.innerHTML = icon(THEME === "dark" ? "sun" : "moon"); });
}
function setLang(l) { LANG = l; store.set("sd.lang", l); applyLang(); if (ME) { buildNav(); render(); loadAlerts(); } }
function setTheme(x) { THEME = x; store.set("sd.theme", x); applyTheme(); if (ME && /dashboard/.test(location.hash)) render(true); }

/* ---------- icons ---------- */
var IC = {
  dashboard: '<rect x="3" y="3" width="7" height="9" rx="1.5"/><rect x="14" y="3" width="7" height="5" rx="1.5"/><rect x="14" y="12" width="7" height="9" rx="1.5"/><rect x="3" y="16" width="7" height="5" rx="1.5"/>',
  incidents: '<path d="M12 3.5l9 15.5H3z"/><path d="M12 10v4M12 17h.01"/>',
  target: '<circle cx="12" cy="12" r="9"/><circle cx="12" cy="12" r="4.5"/><path d="M12 1.5v4M12 18.500v4M1.500 12h4M18.500 12h4"/>',
  report: '<path d="M6 3h9l4 4v14H6z"/><path d="M14 3v5h5M9 13h7M9 17h5"/>',
  users: '<circle cx="9" cy="8" r="3.500"/><path d="M2.500 20c.5-4 3.200-6 6.500-6s6 2 6.500 6M16 4.500a3.500 3.500 0 010 7M18 14c2 .6 3.300 2.500 3.500 6"/>',
  audit: '<path d="M6 3h9l4 4v14H6z"/><path d="M14 3v5h5M9 12l2 2 4-4M9 18h6"/>',
  db: '<ellipse cx="12" cy="5" rx="8" ry="3"/><path d="M4 5v6c0 1.700 3.600 3 8 3s8-1.300 8-3V5M4 11v6c0 1.700 3.600 3 8 3s8-1.300 8-3v-6"/>',
  settings: '<path d="M4 6h10M18 6h2M4 12h4M12 12h8M4 18h12M20 18h0"/><circle cx="16" cy="6" r="2"/><circle cx="10" cy="12" r="2"/><circle cx="18" cy="18" r="2"/>',
  search: '<circle cx="11" cy="11" r="7"/><path d="M20 20l-3.500-3.500"/>',
  bell: '<path d="M6 9a6 6 0 0112 0c0 6 2.500 7.500 2.500 7.500h-17S6 15 6 9zM10 20a2 2 0 004 0"/>',
  sun: '<circle cx="12" cy="12" r="4"/><path d="M12 2v2M12 20v2M2 12h2M20 12h2M5 5l1.500 1.500M17.500 17.500L19 19M5 19l1.500-1.500M17.500 6.500L19 5"/>',
  moon: '<path d="M20 14.500A8.500 8.500 0 019.500 4a8.500 8.500 0 1010.500 10.500z"/>',
  plus: '<path d="M12 5v14M5 12h14"/>',
  download: '<path d="M12 4v11M7 11l5 5 5-5M5 20h14"/>',
  upload: '<path d="M12 16V5M7 9l5-5 5 5M5 20h14"/>',
  trash: '<path d="M4 7h16M9 7V4h6v3M6 7l1 13h10l1-13"/>',
  check: '<path d="M5 12.500l4.500 4.500L19 7"/>',
  copy: '<rect x="9" y="9" width="11" height="11" rx="2"/><path d="M5 15V6a2 2 0 012-2h9"/>',
  file: '<path d="M6 3h8l5 5v13H6z"/><path d="M14 3v5h5"/>',
  board: '<rect x="3" y="4" width="5" height="16" rx="1.500"/><rect x="10" y="4" width="5" height="10" rx="1.500"/><rect x="17" y="4" width="4" height="13" rx="1.500"/>',
  list: '<path d="M8 6h13M8 12h13M8 18h13M3.500 6h.01M3.500 12h.01M3.500 18h.01"/>',
  menu: '<path d="M4 6h16M4 12h16M4 18h16"/>',
  back: '<path d="M19 12H5M11 6l-6 6 6 6"/>',
  globe: '<circle cx="12" cy="12" r="9"/><path d="M3 12h18M12 3c3 3 3 15 0 18M12 3c-3 3-3 15 0 18"/>',
  edit: '<path d="M4 20h4L19 9l-4-4L4 16z"/>',
  lock: '<rect x="5" y="11" width="14" height="9" rx="2"/><path d="M8 11V8a4 4 0 018 0v3"/>',
  shield: '<path d="M12 3l8 3v6c0 5-3.500 8-8 9-4.500-1-8-4-8-9V6z"/><path d="M8.500 12l2.500 2.500 4.500-5"/>',
  link: '<path d="M10 14a4 4 0 005.600 0l3-3a4 4 0 00-5.600-5.600l-1 1M14 10a4 4 0 00-5.600 0l-3 3a4 4 0 005.600 5.600l1-1"/>',
  pulse: '<path d="M3 12h4l3-8 4 16 3-8h4"/>',
  help: '<circle cx="12" cy="12" r="9"/><path d="M9.500 9.500a2.500 2.500 0 114 2c-.9.6-1.500 1.100-1.500 2.200M12 17h.01"/>',
  code: '<path d="M8 8l-4 4 4 4M16 8l4 4-4 4M13 5l-2 14"/>',
  upload: '<path d="M12 16V4M7 9l5-5 5 5M4 20h16"/>',
  asset: '<rect x="3" y="4" width="18" height="6" rx="1.500"/><rect x="3" y="14" width="18" height="6" rx="1.500"/><path d="M7 7h.01M7 17h.01M12 7h6M12 17h6"/>'
};
function icon(n, cls) { return '<svg class="ico ' + (cls || "") + '" viewBox="0 0 24 24" aria-hidden="true">' + (IC[n] || "") + "</svg>"; }
var LOGO = '<svg width="30" height="30" viewBox="0 0 32 32" aria-hidden="true"><rect width="32" height="32" rx="8" fill="#18293d"/><path d="M16 5.500l8.500 3v7.500c0 5-3.600 8.600-8.500 10.500C11.100 24.600 7.500 21 7.500 16V8.500z" fill="none" stroke="#7391ff" stroke-width="2"/><path d="M11.500 16.200l3 3 6-6.700" fill="none" stroke="#7391ff" stroke-width="2.200" stroke-linecap="round" stroke-linejoin="round"/></svg>';

/* ---------- toast / api ---------- */
function toast(m, k) {
  var box = $("#toasts"), d = document.createElement("div");
  d.className = "toast " + (k || ""); d.textContent = m; box.appendChild(d);
  setTimeout(function () { d.remove(); }, 3200);
}
async function api(method, url, body, quiet) {
  var r = await fetch(url, { method: method, headers: { "Content-Type": "application/json", "X-Requested-With": "SOC" }, body: body ? JSON.stringify(body) : undefined, credentials: "same-origin" });
  var j = {}; try { j = await r.json(); } catch (e) {}
  if (r.status === 401 && url !== "/api/login" && !j.mfa_required) { showLogin(); throw new Error("auth"); }
  if (!r.ok) { var msg = t(j.error || "Something went wrong"); if (!quiet) toast(msg, "err"); var e = new Error(msg); e.msg = msg; e.data = j; throw e; }
  return j;
}

/* ---------- formatting ---------- */
function fdate(s) { if (!s) return "-"; return new Date(s).toLocaleString(locale(), { day: "2-digit", month: "short", year: "numeric", hour: "2-digit", minute: "2-digit" }); }
function fshort(s) { return new Date(s).toLocaleString(locale(), { day: "2-digit", month: "short", hour: "2-digit", minute: "2-digit" }); }
function dur(ms) {
  ms = Math.abs(ms); var m = Math.floor(ms / 60000), h = Math.floor(m / 60), d = Math.floor(h / 24);
  if (d >= 1) return d + t("d") + " " + (h % 24) + t("h"); if (h >= 1) return h + t("h") + " " + (m % 60) + t("m"); return Math.max(m, 1) + t("m");
}
function ago(s) { return t("{x} ago", { x: dur(Date.now() - new Date(s).getTime()) }); }
function hrs(h) { return h == null ? "-" : (h < 48 ? h.toFixed(1) + " " + t("h") : (h / 24).toFixed(1) + " " + t("d")); }
function kb(n) { return n > 1048576 ? (n / 1048576).toFixed(1) + " MB" : Math.max(1, Math.round(n / 1024)) + " KB"; }
function person(u) { if (!u || u === "Unassigned") return null; var p = (META && META.people || []).filter(function (x) { return x.username === u; })[0]; return p ? p.full_name : u; }
function who(u) {
  var n = person(u);
  if (!n) return '<span class="who mut"><span class="av un">?</span>' + t("Unassigned") + "</span>";
  return '<span class="who"><span class="av">' + esc(n.split(" ").map(function (x) { return x[0]; }).slice(0, 2).join("").toUpperCase()) + "</span>" + esc(n) + "</span>";
}
function riskPill(i) { return '<span class="pill sev-' + esc(i.risk_band) + '" title="' + esc(t("Risk score")) + '">' + esc(i.risk) + "/100</span>"; }
function sevPill(s) { return '<span class="pill sev-' + esc(s) + '">' + esc(t(s)) + "</span>"; }
var LIFE = ["New", "Investigating", "Contained", "Resolved", "Closed"];
function stPill(s) {
  var i = LIFE.indexOf(s), b = ""; for (var k = 0; k < 5; k++) b += '<b class="' + (k <= i ? "f" : "") + '"></b>';
  return '<span class="st ' + esc(s) + '"><i>' + b + "</i>" + esc(t(s)) + "</span>";
}
function tlpTag(x) { return '<span class="tlp tlp-' + esc(x || "AMBER") + '" title="Traffic Light Protocol">TLP:' + esc(x || "AMBER") + "</span>"; }
function sla(i) {
  var due = new Date(i.due_at).getTime(), cr = new Date(i.created_at).getTime(), end = i.resolved_at ? new Date(i.resolved_at).getTime() : Date.now();
  var pct = Math.min(100, Math.max(3, (end - cr) / (due - cr) * 100)), txt;
  if (i.sla === "met") txt = t("Met"); else if (i.resolved_at && i.sla === "breached") txt = t("Breached by {x}", { x: dur(end - due) });
  else if (i.sla === "breached") txt = t("Overdue {x}", { x: dur(Date.now() - due) }); else txt = t("{x} left", { x: dur(due - Date.now()) });
  return '<div class="sla ' + i.sla + '"><div class="t">' + esc(txt) + '</div><div class="bar2"><i style="width:' + pct + '%"></i></div></div>';
}
var canWrite = function () { return ME && ME.role !== "viewer"; }, isAdmin = function () { return ME && ME.role === "admin"; };
function roleName(r) { return t({ admin: "Administrator", analyst: "Analyst", viewer: "Viewer" }[r] || r); }
function copyText(s) { try { navigator.clipboard.writeText(s); toast(t("Copied")); } catch (e) { toast(t("Copy failed"), "err"); } }

/* ---------- charts (SVG, token-coloured) ---------- */
var SEVCOL = { Critical: "var(--crit)", High: "var(--high)", Medium: "var(--med)", Low: "var(--low)" };
function hbars(rows, col, fixed) {
  var max = Math.max.apply(null, rows.map(function (r) { return r.value; }).concat([1]));
  if (!rows.length) return '<p class="mut sm">' + t("No data yet") + "</p>";
  return rows.map(function (r) { return '<div class="hb"><span class="nm" title="' + esc(t(r.name)) + '">' + esc(t(r.name)) + '</span><span class="tr"><i style="width:' + (r.value / max * 100) + "%;background:" + (fixed ? fixed[r.name] : col) + '"></i></span><b>' + r.value + "</b></div>"; }).join("");
}
function polar(cx, cy, r, a) { var x = a * Math.PI / 180; return [cx + r * Math.cos(x), cy + r * Math.sin(x)]; }
function arc(cx, cy, r, a1, a2) { var p1 = polar(cx, cy, r, a1), p2 = polar(cx, cy, r, a2); return "M" + p1[0].toFixed(2) + " " + p1[1].toFixed(2) + " A" + r + " " + r + " 0 " + (a2 - a1 > 180 ? 1 : 0) + " 1 " + p2[0].toFixed(2) + " " + p2[1].toFixed(2); }
function gauge(score) {
  var zones = [[0, 15, "--low"], [15, 40, "--med"], [40, 70, "--high"], [70, 100, "--crit"]], g = "", i;
  zones.forEach(function (z) { g += '<path class="g-zone" style="stroke:var(' + z[2] + ')" d="' + arc(150, 150, 120, 180 + z[0] * 1.8 + (z[0] ? .6 : 0), 180 + z[1] * 1.8 - .6) + '"/>'; });
  for (i = 0; i <= 20; i++) { var a = 180 + i * 9, major = i % 5 === 0, p1 = polar(150, 150, major ? 98 : 103, a), p2 = polar(150, 150, 108, a); g += '<line class="g-tick" x1="' + p1[0].toFixed(1) + '" y1="' + p1[1].toFixed(1) + '" x2="' + p2[0].toFixed(1) + '" y2="' + p2[1].toFixed(1) + '"' + (major ? ' style="stroke-width:1.6"' : "") + "/>"; }
  return '<svg viewBox="0 0 300 200" role="img" aria-label="' + esc(t("Threat level") + ": " + score + "/100") + '">' + g +
    '<line class="g-needle" id="needle" x1="150" y1="150" x2="150" y2="52" style="transform:rotate(-90deg)" data-deg="' + (score * 1.8 - 90) + '"/><circle class="g-hub" cx="150" cy="150" r="7"/>' +
    '<text class="g-num" x="150" y="192" text-anchor="middle">' + score + "</text></svg>";
}
function sweepNeedle() { var n = $("#needle"); if (n) requestAnimationFrame(function () { requestAnimationFrame(function () { n.style.transform = "rotate(" + n.dataset.deg + "deg)"; }); }); }
function donut(rows, colors) {
  var tot = rows.reduce(function (s, r) { return s + r.value; }, 0), a0 = -90, out = "", R = 52, C = 2 * Math.PI * R, off = 0;
  if (!tot) return '<p class="mut sm">' + t("No data yet") + "</p>";
  rows.forEach(function (r) { if (!r.value) return; var len = r.value / tot * C; out += '<circle cx="70" cy="70" r="' + R + '" fill="none" stroke="' + colors[r.name] + '" stroke-width="18" stroke-dasharray="' + (len - 1.5).toFixed(2) + " " + (C - len + 1.5).toFixed(2) + '" stroke-dashoffset="' + (-off).toFixed(2) + '" transform="rotate(-90 70 70)"><title>' + esc(t(r.name)) + ": " + r.value + "</title></circle>"; off += len; });
  return '<div class="donutw"><svg viewBox="0 0 140 140" role="img" aria-label="' + esc(t("Distribution")) + '">' + out + '<text x="70" y="76" text-anchor="middle" font-size="24" font-weight="700" fill="var(--ink)">' + tot + "</text></svg><div class=\"lg2\">" +
    rows.map(function (r) { return '<div><s style="background:' + colors[r.name] + '"></s>' + esc(t(r.name)) + "<b>" + r.value + "</b></div>"; }).join("") + "</div></div>";
}
function killChain(rows) {
  var map = {}; rows.forEach(function (r) { map[r.name] = r.value; });
  var max = Math.max.apply(null, rows.map(function (r) { return r.value; }).concat([1]));
  return '<div class="kill" role="list">' + META.mitre.map(function (m) {
    var v = map[m] || 0, a = v ? (0.25 + 0.75 * v / max) : 0;
    return '<div role="listitem" class="' + (v && a > .5 ? "h" : "") + '" style="' + (v ? "background:color-mix(in srgb,var(--accent) " + Math.round(a * 100) + '%,var(--surface))' + (a <= .5 ? ";color:var(--ink)" : "") : "") + '" title="' + esc(t(m)) + ": " + v + '"><b>' + (v || "·") + "</b><span>" + esc(t(m)) + "</span></div>";
  }).join("") + "</div>";
}
function hoursChart(utc) {
  var off = -new Date().getTimezoneOffset() / 60, a = [], i; for (i = 0; i < 24; i++) a[(i + Math.round(off) + 24) % 24] = utc[i];
  var max = Math.max.apply(null, a.concat([1]));
  return '<div class="hours" role="img" aria-label="' + esc(t("Incidents by hour of day")) + '">' + a.map(function (v, h) { return '<i class="' + (v ? "" : "z") + '" style="height:' + Math.max(3, v / max * 100) + '%" title="' + h + ":00 · " + v + '"></i>'; }).join("") + '</div><div class="hlab"><span>0:00</span><span>6:00</span><span>12:00</span><span>18:00</span><span>23:00</span></div>';
}
function trendChart(tr) {
  var W = 640, H = 220, L = 30, R = 10, T = 10, B = 26, n = tr.length;
  var mx = Math.max.apply(null, tr.map(function (d) { return Math.max(d.created, d.resolved); }).concat([4])); mx = Math.ceil(mx / 2) * 2;
  var x = function (i) { return L + i * (W - L - R) / (n - 1); }, y = function (v) { return T + (H - T - B) * (1 - v / mx); };
  var g = ""; for (var k = 0; k <= 4; k++) { var v = mx / 4 * k; g += '<line class="gl" x1="' + L + '" x2="' + (W - R) + '" y1="' + y(v) + '" y2="' + y(v) + '"/><text class="ax" x="' + (L - 6) + '" y="' + (y(v) + 4) + '" text-anchor="end">' + (Math.round(v * 10) / 10) + "</text>"; }
  var step = Math.ceil(n / 7), xl = ""; tr.forEach(function (d, i) { if ((n - 1 - i) % step === 0) xl += '<text class="ax" x="' + x(i) + '" y="' + (H - 6) + '" text-anchor="middle">' + new Date(d.date + "T12:00:00").toLocaleDateString(locale(), { day: "numeric", month: "short" }) + "</text>"; });
  var line = function (k) { return tr.map(function (d, i) { return (i ? "L" : "M") + x(i).toFixed(1) + " " + y(d[k]).toFixed(1); }).join(" "); };
  var area = line("created") + " L" + x(n - 1) + " " + y(0) + " L" + x(0) + " " + y(0) + " Z";
  return '<div class="legend"><span><i style="background:var(--accent)"></i>' + t("Reported") + '</span><span><i style="background:var(--faint)"></i>' + t("Resolved") + "</span></div>" +
    '<div class="chartw" id="tc"><svg viewBox="0 0 ' + W + " " + H + '" role="img" aria-label="' + esc(t("Incidents reported and resolved per day")) + '">' + g + xl +
    '<path d="' + area + '" fill="var(--accent)" opacity=".09"/><path d="' + line("resolved") + '" fill="none" stroke="var(--faint)" stroke-width="2" stroke-linejoin="round"/>' +
    '<path d="' + line("created") + '" fill="none" stroke="var(--accent)" stroke-width="2.4" stroke-linejoin="round"/>' +
    '<g id="tcHov" hidden><line id="tcL" y1="' + T + '" y2="' + (H - B) + '" stroke="var(--faint)" stroke-dasharray="3 3"/><circle id="tcA" r="5" fill="var(--accent)" stroke="var(--surface)" stroke-width="2"/><circle id="tcB" r="5" fill="var(--faint)" stroke="var(--surface)" stroke-width="2"/></g>' +
    '<rect id="tcR" x="' + L + '" y="0" width="' + (W - L - R) + '" height="' + (H - B) + '" fill="transparent"/></svg><div class="tip" id="tcT" hidden></div></div>';
}
function bindTrend(tr) {
  var r = $("#tcR"); if (!r) return; var svg = r.ownerSVGElement, W = 640, H = 220, L = 30, R = 10, T = 10, B = 26, n = tr.length;
  var mx = Math.max.apply(null, tr.map(function (d) { return Math.max(d.created, d.resolved); }).concat([4])); mx = Math.ceil(mx / 2) * 2;
  var y = function (v) { return T + (H - T - B) * (1 - v / mx); };
  function mv(ev) {
    var b = svg.getBoundingClientRect(), px = (ev.clientX - b.left) / b.width * W, i = Math.round((px - L) / ((W - L - R) / (n - 1))); i = Math.max(0, Math.min(n - 1, i));
    var d = tr[i], cx = L + i * (W - L - R) / (n - 1);
    $("#tcHov").removeAttribute("hidden"); $("#tcL").setAttribute("x1", cx); $("#tcL").setAttribute("x2", cx);
    $("#tcA").setAttribute("cx", cx); $("#tcA").setAttribute("cy", y(d.created)); $("#tcB").setAttribute("cx", cx); $("#tcB").setAttribute("cy", y(d.resolved));
    var tp = $("#tcT"); tp.hidden = false; tp.style.left = (cx / W * b.width) + "px"; tp.style.top = (Math.min(y(d.created), y(d.resolved)) / H * b.height) + "px";
    tp.textContent = new Date(d.date + "T12:00:00").toLocaleDateString(locale(), { weekday: "short", day: "numeric", month: "short" }) + " · " + t("{n} reported", { n: d.created }) + " · " + t("{n} resolved", { n: d.resolved });
  }
  r.addEventListener("mousemove", mv); r.addEventListener("touchmove", function (e) { mv(e.touches[0]); }, { passive: true });
  r.addEventListener("mouseleave", function () { $("#tcHov").setAttribute("hidden", ""); $("#tcT").hidden = true; });
}

/* ---------- shell ---------- */
function head(title, sub, acts) { $("#pgT").textContent = title; $("#pgS").textContent = sub || ""; $("#pgA").innerHTML = acts || ""; document.title = title + " · SentinelDesk"; }
function newBtn() { return canWrite() ? '<button class="btn pri" id="bNew">' + icon("plus") + t("New incident") + "</button>" : ""; }
function bindNew() { var b = $("#bNew"); if (b) b.onclick = openNew; }
function setNav(r) { $$("#nav a").forEach(function (a) { a.classList.toggle("on", a.dataset.r === r); }); }
function showLogin() { ME = null; $("#app").hidden = true; $("#login").hidden = false; $("#lp").value = ""; $("#lc").value = ""; $("#mfaRow").hidden = true; document.title = t("Sign in") + " · SentinelDesk"; }
function buildNav() {
  var it = [["dashboard", "Dashboard", "dashboard"], ["incidents", "Incidents", "incidents"], ["iocs", "Indicators", "target"], ["assets", "Assets", "asset"], ["reports", "Reports", "report"], ["help", "Quick guide", "help"]];
  var adm = [["users", "Users", "users"], ["audit", "Audit log", "audit"], ["system", "System health", "pulse"], ["database", "Database", "db"], ["settings", "Settings", "settings"]];
  var h = '<div class="grp">' + t("Operations") + "</div>" + it.map(link).join("");
  if (isAdmin()) h += '<div class="grp">' + t("Administration") + "</div>" + adm.map(link).join("");
  $("#nav").innerHTML = h;
  function link(i) { return '<a href="#/' + i[0] + '" data-r="' + i[0] + '">' + icon(i[2]) + t(i[1]) + (i[0] === "incidents" ? '<span class="badge" id="navBadge" hidden></span>' : "") + "</a>"; }
  $("#meName").textContent = ME.full_name; $("#meRole").textContent = roleName(ME.role);
  var r = location.hash.replace(/^#\//, "").split("/")[0]; setNav(r);
}
async function boot() {
  try { ME = await api("GET", "/api/me", null, true); } catch (e) { return showLogin(); }
  META = await api("GET", "/api/meta");
  $("#login").hidden = true; $("#app").hidden = false; $("#ver").textContent = "v" + META.version;
  buildNav();
  if (!location.hash || location.hash === "#") location.hash = "#/dashboard";
  render(); loadAlerts();
}
window.addEventListener("hashchange", function () { document.body.classList.remove("nav-open"); if (ME) render(); });
async function render(silent) {
  var parts = location.hash.replace(/^#\//, "").split("?")[0].split("/"), r = parts[0] || "dashboard", my = ++seq;
  setNav(r === "account" ? "" : r);
  try {
    if (r === "dashboard") await vDash(my, silent);
    else if (r === "incidents" && parts[1] && parts[2] === "report") await vReport(parts[1], my);
    else if (r === "incidents" && parts[1]) await vDetail(parts[1], my);
    else if (r === "incidents") await vList(my);
    else if (r === "iocs") await vIocs(my);
    else if (r === "assets") await vAssets(my);
    else if (r === "reports") await vReports(my);
    else if (r === "users" && isAdmin()) await vUsers(my);
    else if (r === "audit" && isAdmin()) await vAudit(my);
    else if (r === "system" && isAdmin()) await vSystem(my);
    else if (r === "api") await vApi(my);
    else if (r === "help") await vHelp(my);
    else if (r === "database" && isAdmin()) await vDb(my);
    else if (r === "settings" && isAdmin()) await vSettings(my);
    else if (r === "account") await vAccount(my);
    else location.hash = "#/dashboard";
  } catch (e) { if (e.message !== "auth" && my === seq && e.msg === undefined) $("#view").innerHTML = '<div class="empty"><b>' + t("Could not load this page") + "</b>" + t("Check that the server is still running, then reload.") + "</div>"; }
  if (!silent) window.scrollTo(0, 0);
}

/* ---------- notifications bell ---------- */
var ALERTS = null, MENT = { unread: 0, items: [] };
function bellCount() { var n = (ALERTS ? ALERTS.count : 0) + MENT.unread; var b = $("#bellN"); b.hidden = !n; b.textContent = n > 99 ? "99+" : n; }
async function loadAlerts() {
  try { ALERTS = await api("GET", "/api/alerts", null, true); } catch (e) { return; }
  try { MENT = await api("GET", "/api/mentions", null, true); } catch (e) { MENT = { unread: 0, items: [] }; }
  bellCount();
  var nb = $("#navBadge"); if (nb) { var n = ALERTS.counts.breached; nb.hidden = !n; nb.textContent = n; }
}
function bellPanel() {
  var p = $("#bellPop"); if (!p.hidden) { p.hidden = true; return; }
  var A = ALERTS || { breached: [], at_risk: [], unassigned: [] };
  var grp = function (title, list, cls) { return list.length ? '<h4>' + esc(title) + " (" + list.length + ")</h4>" + list.map(function (i) { return '<a href="#/incidents/' + esc(i.id) + '" class="sig s-' + i.severity + '"><span>' + sevPill(i.severity) + '</span><span><b>' + esc(i.title) + '</b><br><span class="mut sm">' + esc(i.id) + " · " + esc(cls(i)) + "</span></span></a>"; }).join("") : ""; };
  var mh = MENT.items.filter(function (m) { return !m.read; }).length ? "<h4>" + esc(t("Mentions")) + " (" + MENT.unread + ")</h4>" + MENT.items.filter(function (m) { return !m.read; }).slice(0, 6).map(function (m) { return '<a href="#/incidents/' + esc(m.incident_id) + '" class="sig"><span class="pill sev-Low">@</span><span><b>' + esc(t("{u} mentioned you", { u: person(m.by_user) || m.by_user })) + '</b><br><span class="mut sm">' + esc(m.incident_id) + " · " + esc(m.excerpt) + "</span></span></a>"; }).join("") : "";
  var h = mh + grp(t("Past response target"), A.breached, function (i) { return t("Overdue {x}", { x: dur(Date.now() - new Date(i.due_at)) }); }) +
    grp(t("At risk"), A.at_risk, function (i) { return t("{x} left", { x: dur(new Date(i.due_at) - Date.now()) }); }) +
    grp(t("High severity and unassigned"), A.unassigned, function () { return t("Unassigned"); });
  p.innerHTML = h || '<div class="empty"><b>' + t("All clear") + "</b>" + t("No incidents need attention right now.") + "</div>"; p.hidden = false;
  if (MENT.unread) { api("POST", "/api/mentions/read", {}, true).then(function () { MENT.unread = 0; MENT.items.forEach(function (m) { m.read = 1; }); bellCount(); }).catch(function () {}); }
}

/* ---------- command palette ---------- */
var PAL = { items: [], idx: 0 };
function palCommands() {
  var c = [["Go to Dashboard", "#/dashboard", "dashboard"], ["Go to Incidents", "#/incidents", "incidents"], ["Go to Indicators", "#/iocs", "target"], ["Go to Assets", "#/assets", "asset"], ["Go to API reference", "#/api", "code"], ["Go to Reports", "#/reports", "report"], ["My account and security", "#/account", "lock"]];
  if (isAdmin()) c.push(["Go to Users", "#/users", "users"], ["Go to Audit log", "#/audit", "audit"], ["Go to System health", "#/system", "pulse"], ["Go to Database", "#/database", "db"], ["Go to Settings", "#/settings", "settings"]);
  var out = c.map(function (x) { return { label: t(x[0]), href: x[1], ic: x[2] }; });
  if (canWrite()) out.push({ label: t("New incident"), act: openNew, ic: "plus" });
  out.push({ label: t(THEME === "dark" ? "Switch to light theme" : "Switch to dark theme"), act: function () { setTheme(THEME === "dark" ? "light" : "dark"); }, ic: "moon" });
  out.push({ label: t(LANG === "ar" ? "Switch to English" : "Switch to Arabic"), act: function () { setLang(LANG === "ar" ? "en" : "ar"); }, ic: "globe" });
  return out;
}
function openPalette() { var d = $("#pal"); if (d.open) return; $("#palQ").value = ""; palRender(""); d.showModal(); $("#palQ").focus(); }
var palT;
function palRender(q) {
  var cmds = palCommands().filter(function (c) { return !q || c.label.toLowerCase().indexOf(q.toLowerCase()) > -1; });
  PAL.items = []; var h = "";
  function add(it) { PAL.items.push(it); var i = PAL.items.length - 1; return '<a class="it' + (i === PAL.idx ? " on" : "") + '" data-i="' + i + '" href="' + esc(it.href || "#") + '">' + icon(it.ic || "file", "sm") + "<span>" + it.html + "</span><span class=\"mut sm\">" + (it.hint || "") + "</span></a>"; }
  var finish = function () { $("#palRes").innerHTML = h || '<div class="empty">' + t("No results") + "</div>"; palBind(); };
  if (q.length < 2) { cmds.forEach(function (c) { c.html = esc(c.label); h += add(c); }); finish(); return; }
  clearTimeout(palT); palT = setTimeout(async function () {
    var r; try { r = await api("GET", "/api/search?q=" + encodeURIComponent(q), null, true); } catch (e) { return; }
    if ($("#palQ").value !== q) return; PAL.items = []; h = "";
    if (r.incidents.length) { h += "<h5>" + t("Incidents") + "</h5>"; r.incidents.forEach(function (i) { h += add({ href: "#/incidents/" + i.id, ic: "incidents", html: '<span class="mono">' + esc(i.id) + "</span> " + esc(i.title), hint: esc(t(i.severity)) }); }); }
    if (r.iocs.length) { h += "<h5>" + t("Indicators") + "</h5>"; r.iocs.forEach(function (i) { h += add({ href: "#/incidents/" + i.incident_id, ic: "target", html: '<span class="mono">' + esc(i.value) + "</span>", hint: esc(i.incident_id) }); }); }
    if (r.assets.length) { h += "<h5>" + t("Assets") + "</h5>"; r.assets.forEach(function (a) { h += add({ act: function () { FILT.q = a.name; location.hash = "#/incidents"; }, ic: "db", html: esc(a.name), hint: t("{n} incidents", { n: a.count }) }); }); }
    var cm = cmds.slice(0, 4); if (cm.length) { h += "<h5>" + t("Actions") + "</h5>"; cm.forEach(function (c) { c.html = esc(c.label); h += add(c); }); }
    finish();
  }, 160);
}
function palBind() {
  $$("#palRes .it").forEach(function (a) { a.onclick = function (e) { var it = PAL.items[+a.dataset.i]; if (it.act) { e.preventDefault(); $("#pal").close(); it.act(); } else $("#pal").close(); }; });
}
function palMove(d) { PAL.idx = Math.max(0, Math.min(PAL.items.length - 1, PAL.idx + d)); $$("#palRes .it").forEach(function (a, i) { a.classList.toggle("on", i === PAL.idx); if (i === PAL.idx) a.scrollIntoView({ block: "nearest" }); }); }

/* ---------- wiring ---------- */
document.addEventListener("click", function (e) {
  var c = e.target.closest("[data-close]"); if (c) { var d = c.closest("dialog"); if (d) d.close(); }
  if (!e.target.closest(".bell")) { var bp = $("#bellPop"); if (bp) bp.hidden = true; }
  if (e.target.closest("aside a") || (document.body.classList.contains("nav-open") && !e.target.closest("aside") && !e.target.closest(".menu"))) document.body.classList.remove("nav-open");
  var g = e.target.closest("[data-go]"); if (g) { var f = g.dataset.go.split(":"); FILT = { q: "", status: "", severity: "", category: "", assignee: "", mine: false }; if (f[0] === "open") FILT.status = "open"; else if (f[0]) FILT[f[0]] = f[1]; location.hash = "#/incidents"; }
});
document.addEventListener("keydown", function (e) {
  if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === "k") { e.preventDefault(); if (ME) openPalette(); return; }
  var typing = /INPUT|TEXTAREA|SELECT/.test((e.target.tagName || ""));
  if (!typing && ME && e.key === "/" && !$("dialog[open]")) { e.preventDefault(); openPalette(); }
  if (!typing && ME && canWrite() && e.key === "n" && !$("dialog[open]") && !e.ctrlKey && !e.metaKey) { e.preventDefault(); openNew(); }
  if ($("#pal").open) { if (e.key === "Escape") { e.preventDefault(); $("#pal").close(); } else if (e.key === "ArrowDown") { e.preventDefault(); palMove(1); } else if (e.key === "ArrowUp") { e.preventDefault(); palMove(-1); } else if (e.key === "Enter") { var a = $("#palRes .it.on") || $("#palRes .it"); if (a) { e.preventDefault(); a.click(); if (a.getAttribute("href") && a.getAttribute("href") !== "#") location.hash = a.getAttribute("href"); } } }
});
document.addEventListener("DOMContentLoaded", function () {
  applyTheme(); applyLang();
  $("#palQ").addEventListener("input", function () { PAL.idx = 0; palRender(this.value); });
  $("#pal").addEventListener("click", function (e) { if (e.target === this) this.close(); });
  $$(".langBtn").forEach(function (b) { b.onclick = function () { setLang(LANG === "ar" ? "en" : "ar"); }; });
  $$(".themeBtn").forEach(function (b) { b.onclick = function () { setTheme(THEME === "dark" ? "light" : "dark"); }; });
  $("#finder").onclick = openPalette; $("#bellBtn").onclick = bellPanel;
  $("#menuBtn").onclick = function () { document.body.classList.toggle("nav-open"); };
  $("#bOut").onclick = async function () { try { await api("POST", "/api/logout"); } catch (e) {} showLogin(); };
  $("#bAcct").onclick = function () { location.hash = "#/account"; };
  $("#lf").onsubmit = async function (e) {
    e.preventDefault(); $("#lerr").textContent = "";
    try { await api("POST", "/api/login", { username: $("#lu").value, password: $("#lp").value, code: $("#lc").value }, true); await boot(); }
    catch (x) { if (x.data && x.data.mfa_required) { $("#mfaRow").hidden = false; $("#lc").focus(); } $("#lerr").textContent = x.msg || t("Could not sign in"); }
  };
  setInterval(function () { if (ME) loadAlerts(); }, 60000);
  setInterval(function () { if (ME && /^#\/dashboard/.test(location.hash) && !document.hidden && !$("dialog[open]")) render(true); }, 30000);
  boot();
});
