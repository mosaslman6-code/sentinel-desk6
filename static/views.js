"use strict";
/* SentinelDesk 2.0 - operational views: dashboard, incident list/board, incident detail, report, new incident. */
var FILT = { q: "", status: "", severity: "", category: "", assignee: "", mine: false };
var SORT = { key: "created_at", dir: -1 }, INC = [], SEL = new Set();
var VIEWMODE = store.get("sd.view") || "table", DTAB = "timeline";
var OPENST = ["New", "Investigating", "Contained"];
var STCOL = { New: "#8aa4f0", Investigating: "#7391ff", Contained: "#b98500", Resolved: "#2e8b57", Closed: "#8593a6" };
var LEVELS = {
  low: ["Low", "--low", "Few open incidents, and all are within their response targets."],
  guarded: ["Guarded", "--med", "Open incidents are being handled within their targets."],
  elevated: ["Elevated", "--high", "Serious incidents or missed targets need attention."],
  severe: ["Severe", "--crit", "Critical incidents or many missed targets. Act now."]
};

/* ============ LIVE ATTACK FEED (attack_lab) ============ */
async function liveAttackPanel() {
  var rows, lab = null;
  try { rows = await api("GET", "/api/incidents", null, true); } catch (x) { return ""; }
  if (isAdmin()) { try { lab = await api("GET", "/api/attack_lab/status", null, true); } catch (x) { lab = null; } }
  var atk = rows.filter(function (i) { return i.source === "Firewall / IDS"; })
    .sort(function (a, b) { return a.created_at < b.created_at ? 1 : -1; }).slice(0, 8);
  var ctl = "";
  if (lab && lab.available) {
    ctl = lab.running ? '<button class="btn sm" id="bLabStop" style="margin-inline-start:auto">' + t("Stop the attack lab") + "</button>"
      : '<button class="btn sm pri" id="bLabStart" style="margin-inline-start:auto">' + t("Start the attack lab") + "</button>";
  }
  var head = '<h3 style="display:flex;align-items:center;gap:8px;flex-wrap:wrap">' + icon("target", "sm") + " " + t("Live attack feed") +
    (atk.length ? '<span class="mut sm" style="font-weight:400">· ' + t("{n} detected", { n: atk.length }) + "</span>" : "") + ctl + "</h3>";
  if (!atk.length) {
    return '<div class="panel mt" id="liveAttacks">' + head + '<p class="mut sm" style="margin:8px 0 0">' +
      (lab && lab.available ? t("No attacks detected yet. Click \"Start the attack lab\" to launch a real, local practice target and watch genuine detected attacks turn into incidents here within seconds.") :
        t("No attacks detected yet. Run the attack lab (attack_lab/run_lab.sh) to see real, live-detected incidents appear here.")) + "</p></div>";
  }
  var rowsHtml = atk.map(function (i) {
    var fresh = (Date.now() - new Date(i.created_at).getTime()) < 120000;
    return '<a href="#/incidents/' + esc(i.id) + '" class="sig s-' + i.severity + '" style="text-decoration:none;display:flex;align-items:center;gap:10px;padding:8px 2px;border-bottom:1px solid var(--line)">' +
      '<span class="dot' + (fresh ? " pulse" : "") + '" style="width:8px;height:8px;border-radius:50%;background:var(--crit);flex:none"></span>' +
      sevPill(i.severity) + '<span style="flex:1;min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">' + esc(i.title) + '</span>' +
      '<span class="mut sm" style="white-space:nowrap">' + esc(i.asset) + "</span><span class=\"mut sm\" style=\"white-space:nowrap\">" + ago(i.created_at) + "</span></a>";
  }).join("");
  return '<div class="panel mt" id="liveAttacks">' + head + '<div class="body" style="padding-top:4px">' + rowsHtml + "</div></div>";
}
function bindLiveAttackPanel() {
  var bs = $("#bLabStart");
  if (bs) bs.onclick = async function () {
    bs.disabled = true; bs.textContent = t("Starting…");
    try {
      await api("POST", "/api/attack_lab/start");
      toast(t("Attack lab started. Real attacks and incidents will appear here within a few seconds."));
      setTimeout(function () { render(true); }, 4000);
      setTimeout(function () { render(true); }, 10000);
    } catch (x) { render(true); }
  };
  var bt = $("#bLabStop");
  if (bt) bt.onclick = async function () {
    try { await api("POST", "/api/attack_lab/stop"); toast(t("Attack lab stopped")); } catch (x) {}
    render(true);
  };
}

/* ============ DASHBOARD ============ */
async function vDash(my, silent) {
  var days = +(store.get("sd.days") || 14);
  var d = await api("GET", "/api/dashboard?days=" + days); if (my !== seq) return; var k = d.kpis;
  head(t("Dashboard"), t("Live overview of the incident queue"), newBtn()); bindNew();
  if (k.total === 0) {
    $("#view").innerHTML = '<div class="panel"><div class="empty"><b>' + t("No incidents yet") + "</b>" + (canWrite() ? t("Report the first incident") : t("Nothing has been reported")) +
      (isAdmin() ? ' <button class="btn sm" id="bDemo" style="margin-inline-start:8px">' + t("Load demo data") + "</button>" : "") + "</div></div>";
    bindNew(); var bd = $("#bDemo"); if (bd) bd.onclick = async function () { await api("POST", "/api/demo"); toast(t("Demo data loaded")); META = await api("GET", "/api/meta"); render(); };
    return;
  }
  var lv = LEVELS[d.posture.level], v = "";
  if (ME.default_password) v += '<div class="note warn banner"><span>' + icon("lock", "sm") + " " + t("You are still using a default password. Change it before sharing this system.") + '</span><button class="btn sm" id="bWeak">' + t("Change password") + "</button></div>";
  var kpi = function (n, l, s, cls, go) { return "<" + (go ? 'a href="#/incidents" data-go="' + go + '"' : "div") + ' class="kpi ' + (cls || "") + '"><div class="n">' + n + '</div><div class="l">' + l + '</div><div class="s">' + s + "</div></" + (go ? "a" : "div") + ">"; };
  v += '<div class="grid c-hero"><div class="panel posture"><h3 style="padding:0 0 4px;font-size:14px">' + t("Threat level") + "</h3>" + gauge(d.posture.score) +
    '<div class="lv" style="color:var(' + lv[1] + ')">' + t(lv[0]) + '</div><div class="ds">' + t(lv[2]) + "</div></div>" +
    '<div class="panel kpis">' +
    kpi(k.open, t("Open incidents"), t("of {n} total", { n: k.total }), "", "open") +
    kpi(k.critical_open, t("Critical and open"), t("{h} h response target", { h: META.sla_hours.Critical }), k.critical_open ? "bad" : "", "severity:Critical") +
    kpi(k.breached, t("Past response target"), t("{n} open and unassigned", { n: k.unassigned }), k.breached ? "bad" : "", "open") +
    kpi(hrs(k.mtta_hours), t("Mean time to acknowledge"), t("report to first response"), "") +
    kpi(hrs(k.mttr_hours), t("Mean time to resolve"), t("last 30 days · {n} resolved", { n: k.resolved_30d }), "") +
    kpi(k.sla_met_pct == null ? "-" : k.sla_met_pct + "%", t("Resolved within target"), t("last 30 days"), k.sla_met_pct != null && k.sla_met_pct >= 80 ? "good" : "") + "</div></div>";
  v += await liveAttackPanel();
  var dsel = '<select id="dDays" style="width:auto;padding:3px 8px" aria-label="' + t("Period") + '">' + [7, 14, 30, 90].map(function (x) { return '<option value="' + x + '"' + (x === d.days ? " selected" : "") + ">" + t("Last {n} days", { n: x }) + "</option>"; }).join("") + "</select>";
  v += '<div class="grid c-32 mt"><div class="panel"><div class="ph">' + t("Reported and resolved") + dsel + '</div><div class="body">' + trendChart(d.trend) + "</div></div>" +
    '<div class="panel"><h3>' + t("Open incidents by severity") + '</h3><div class="body" style="padding-top:18px">' + donut(d.open_by_severity, SEVCOL) +
    '<p class="mut sm" style="margin:12px 0 0">' + t("Response targets") + ": " + META.severities.slice().reverse().map(function (x) { return t(x) + " " + META.sla_hours[x] + t("h"); }).join(" · ") + "</p></div></div></div>";
  v += '<div class="panel mt"><h3>' + t("Attack tactics seen (MITRE ATT&CK)") + '</h3><div class="body">' + (d.by_mitre.length ? killChain(d.by_mitre) : '<p class="mut sm" style="margin:0">' + t("Tag incidents with ATT&CK tactics to see how attacks progress here.") + "</p>") + "</div></div>";
  var att = d.attention.length ? '<div class="att">' + d.attention.map(function (i) { return '<a href="#/incidents/' + esc(i.id) + '" class="sig s-' + i.severity + '"><span>' + sevPill(i.severity) + '</span><span><span class="tt">' + esc(i.title) + '</span><span class="mut sm"><span class="mono">' + esc(i.id) + "</span> · " + esc(i.asset) + " · " + esc(person(i.assignee) || t("Unassigned")) + " · " + t("Risk") + " " + i.risk + "</span></span>" + sla(i) + "</a>"; }).join("") + "</div>" : '<div class="empty"><b>' + t("Queue is clear") + "</b>" + t("No open incidents.") + "</div>";
  var maxw = Math.max.apply(null, d.workload.map(function (w) { return w.open; }).concat([1]));
  var wl = d.workload.length ? d.workload.map(function (w) { var rest = w.open - w.critical; return '<div class="wl"><span class="nm">' + (w.name === "Unassigned" ? '<span class="mut">' + t("Unassigned") + "</span>" : esc(person(w.name) || w.name)) + '</span><span class="tr" style="width:' + (w.open / maxw * 100) + '%"><i style="width:' + (w.critical / w.open * 100) + '%;background:var(--crit)"></i><i style="width:' + (rest / w.open * 100) + '%;background:var(--accent)"></i></span><b>' + w.open + "</b></div>"; }).join("") + '<div class="legend" style="margin-top:12px"><span><i style="background:var(--crit)"></i>' + t("Critical or high") + '</span><span><i style="background:var(--accent)"></i>' + t("Other") + "</span></div>" : '<p class="mut sm">' + t("No open incidents.") + "</p>";
  v += '<div class="grid c-32 mt"><div class="panel"><h3>' + t("Needs attention first") + "</h3>" + att + '</div><div class="panel"><h3>' + t("Open workload by person") + '</h3><div class="body" style="padding-top:18px">' + wl + "</div></div></div>";
  var rk = d.risk, rkTop = rk.top_assets.length ? rk.top_assets.map(function (a) { return '<li><a href="#/assets" style="text-decoration:none"><b>' + esc(a.name) + "</b></a> " + sevPill(a.crit) + "<small>" + t("{n} open", { n: a.open }) + "</small>" + riskPill({ risk: a.max, risk_band: a.max >= 75 ? "Critical" : a.max >= 50 ? "High" : a.max >= 25 ? "Medium" : "Low" }) + "</li>"; }).join("") : '<li class="mut">' + t("No open incidents.") + "</li>";
  v += '<div class="grid c-2 mt"><div class="panel"><h3>' + t("Open incidents by risk") + '</h3><div class="body" style="padding-top:18px">' + hbars(rk.bands, null, SEVCOL) + '<p class="mut sm" style="margin:12px 0 0">' + (rk.avg == null ? "" : t("Average risk score") + ": <b>" + rk.avg + "/100</b> · ") + t("Risk = incident severity × asset criticality (0-100).") + '</p></div></div><div class="panel"><h3>' + t("Highest-risk assets") + '</h3><ul class="act risk">' + rkTop + "</ul></div></div>";
  var rec = d.recent.map(function (e) { return '<li><a class="id" href="#/incidents/' + esc(e.incident_id) + '" style="text-decoration:none">' + esc(e.incident_id) + "</a> " + esc(e.text.length > 90 ? e.text.slice(0, 90) + "…" : e.text) + "<small>" + esc(person(e.username) || e.username) + " · " + ago(e.at) + "</small></li>"; }).join("");
  var tot = d.by_status.reduce(function (s, x) { return s + x.value; }, 0) || 1;
  var ready = '<div style="display:flex;height:12px;border-radius:3px;overflow:hidden;gap:2px;margin-bottom:12px">' + d.by_status.map(function (s) { return s.value ? '<i style="flex:' + s.value + ";background:" + STCOL[s.name] + '" title="' + esc(t(s.name)) + ": " + s.value + '"></i>' : ""; }).join("") + "</div>" +
    '<div class="lg2" style="margin-bottom:16px">' + d.by_status.map(function (s) { return '<div><s style="background:' + STCOL[s.name] + '"></s>' + esc(t(s.name)) + "<b>" + s.value + "</b></div>"; }).join("") + "</div>" +
    '<dl class="facts"><div><dt>' + t("Playbook steps completed (open incidents)") + '</dt><dd><div class="prog"><div class="meter"><i style="width:' + (k.playbook_pct || 0) + '%"></i></div><b>' + (k.playbook_pct == null ? "-" : k.playbook_pct + "%") + "</b></div></dd></div>" +
    '<div><dt>' + t("Indicators tracked") + '</dt><dd><a href="#/iocs"><b>' + k.iocs + "</b></a> · " + t("Evidence files") + ": <b>" + k.evidence + "</b></dd></div></dl>";
  v += '<div class="grid c-3 mt"><div class="panel"><h3>' + t("By category") + '</h3><div class="body" style="padding-top:18px">' + hbars(d.by_category.slice(0, 6), "var(--accent)") + "</div></div>" +
    '<div class="panel"><h3>' + t("Most affected assets") + '</h3><div class="body" style="padding-top:18px">' + hbars(d.top_assets, "#5f7fb0") + "</div></div>" +
    '<div class="panel"><h3>' + t("Incidents by hour of day") + '</h3><div class="body" style="padding-top:18px">' + hoursChart(d.by_hour_utc) + "</div></div></div>";
  v += '<div class="grid c-2 mt"><div class="panel"><h3 style="padding-bottom:4px">' + t("Recent activity") + '</h3><ul class="act">' + rec + '</ul></div><div class="panel"><h3>' + t("Response readiness") + '</h3><div class="body">' + ready + "</div></div></div>";
  $("#view").innerHTML = v; bindTrend(d.trend);
  var n = $("#needle"); if (silent && n) { n.style.transition = "none"; n.style.transform = "rotate(" + n.dataset.deg + "deg)"; } else sweepNeedle();
  $("#dDays").onchange = function () { store.set("sd.days", this.value); render(true); };
  var bw = $("#bWeak"); if (bw) bw.onclick = function () { openPw(null); };
  bindLiveAttackPanel();
}

/* ============ INCIDENT LIST + BOARD ============ */
function matches(i) {
  var f = FILT, q = f.q.toLowerCase();
  return (!f.status || (f.status === "open" ? OPENST.indexOf(i.status) > -1 : i.status === f.status)) && (!f.severity || i.severity === f.severity) && (!f.category || i.category === f.category) &&
    (!f.assignee || i.assignee === f.assignee) && (!f.mine || i.assignee === ME.username) && (!q || (i.id + " " + i.title + " " + i.asset + " " + i.category).toLowerCase().indexOf(q) > -1);
}
function extras(i) {
  var p = []; if (i.n_ioc) p.push(icon("target", "sm") + i.n_ioc); if (i.n_ev) p.push(icon("file", "sm") + i.n_ev); if (i.n_chk) p.push(icon("check", "sm") + i.n_chk_done + "/" + i.n_chk);
  return p.length ? '<span class="mut" style="display:inline-flex;gap:10px;margin-inline-start:6px;vertical-align:middle">' + p.map(function (x) { return '<span style="display:inline-flex;gap:3px;align-items:center">' + x + "</span>"; }).join("") + "</span>" : "";
}
async function vList(my) {
  INC = await api("GET", "/api/incidents"); if (my !== seq) return;
  head(t("Incidents"), t("{n} in total", { n: INC.length }), '<a class="btn" href="/api/export.csv">' + icon("download") + t("Export CSV") + "</a>" + (canWrite() ? '<button class="btn" id="bImport">' + icon("upload") + t("Import CSV") + "</button>" : "") + newBtn()); bindNew();
  if ($("#bImport")) $("#bImport").onclick = openImport;
  SEL = new Set();
  var opt = function (a, all, tr) { return '<option value="">' + all + "</option>" + a.map(function (x) { return '<option value="' + esc(x) + '">' + esc(tr ? t(x) : x) + "</option>"; }).join(""); };
  $("#view").innerHTML = '<div class="tools"><input type="search" id="fq" placeholder="' + esc(t("Search ID, title, asset")) + '" aria-label="' + t("Search") + '" value="' + esc(FILT.q) + '">' +
    '<select id="fs" aria-label="' + t("Status") + '"><option value="">' + t("All statuses") + '</option><option value="open">' + t("Open (not resolved)") + "</option>" + META.statuses.map(function (x) { return '<option value="' + x + '">' + t(x) + "</option>"; }).join("") + "</select>" +
    '<select id="fv" aria-label="' + t("Severity") + '">' + opt(META.severities, t("All severities"), 1) + '</select><select id="fc" aria-label="' + t("Category") + '">' + opt(META.categories, t("All categories"), 1) + "</select>" +
    '<select id="fa" aria-label="' + t("Assignee") + '"><option value="">' + t("Anyone") + '</option><option value="Unassigned">' + t("Unassigned") + "</option>" + META.people.map(function (p) { return '<option value="' + esc(p.username) + '">' + esc(p.full_name) + "</option>"; }).join("") + "</select>" +
    (canWrite() ? '<label class="chk"><input type="checkbox" id="fm"' + (FILT.mine ? " checked" : "") + "> " + t("Assigned to me") + "</label>" : "") +
    '<span class="seg2" style="margin-inline-start:auto"><button id="vmT" class="' + (VIEWMODE === "table" ? "on" : "") + '">' + icon("list", "sm") + t("Table") + '</button><button id="vmB" class="' + (VIEWMODE === "board" ? "on" : "") + '">' + icon("board", "sm") + t("Board") + "</button></span></div>" +
    '<div id="listBody"></div><div id="bulkBar"></div>';
  $("#fs").value = FILT.status; $("#fv").value = FILT.severity; $("#fc").value = FILT.category; $("#fa").value = FILT.assignee;
  var upd = function () { FILT.q = $("#fq").value; FILT.status = $("#fs").value; FILT.severity = $("#fv").value; FILT.category = $("#fc").value; FILT.assignee = $("#fa").value; FILT.mine = $("#fm") ? $("#fm").checked : false; SEL.clear(); drawList(); };
  ["fq", "fs", "fv", "fc", "fa", "fm"].forEach(function (id) { var e = $("#" + id); if (e) e.oninput = upd; });
  $("#vmT").onclick = function () { VIEWMODE = "table"; store.set("sd.view", "table"); vList(++seq); };
  $("#vmB").onclick = function () { VIEWMODE = "board"; store.set("sd.view", "board"); vList(++seq); };
  drawList();
}
function drawList() { if (VIEWMODE === "board") drawBoard(); else drawTable(); drawBulk(); }
function drawTable() {
  var k = SORT.key, dir = SORT.dir, w = canWrite(), list = INC.filter(matches);
  list.sort(function (a, b) { var x = k === "severity" ? META.severities.indexOf(a.severity) : a[k], y = k === "severity" ? META.severities.indexOf(b.severity) : b[k]; if (k === "status") { x = META.statuses.indexOf(a.status); y = META.statuses.indexOf(b.status); } return (x > y ? 1 : x < y ? -1 : 0) * dir; });
  var cols = [["id", "ID"], ["title", "Incident"], ["severity", "Severity"], ["status", "Status"], ["assignee", "Assignee"], ["due_at", "Response target"], ["created_at", "Reported"]];
  var th = (w ? '<th style="width:34px"><input type="checkbox" id="selAll" aria-label="' + t("Select all") + '"></th>' : "") + cols.map(function (c) { return '<th class="s" data-k="' + c[0] + '" aria-sort="' + (c[0] === k ? (dir > 0 ? "ascending" : "descending") : "none") + '">' + t(c[1]) + (c[0] === k ? (dir > 0 ? " ▲" : " ▼") : "") + "</th>"; }).join("");
  var rows = list.length ? list.map(function (i) {
    return '<tr class="link sig s-' + i.severity + (SEL.has(i.id) ? " sel" : "") + '" tabindex="0" data-id="' + esc(i.id) + '">' + (w ? '<td><input type="checkbox" class="sel" data-id="' + esc(i.id) + '"' + (SEL.has(i.id) ? " checked" : "") + ' aria-label="' + t("Select") + " " + esc(i.id) + '"></td>' : "") +
      '<td class="idc">' + esc(i.id) + '</td><td class="ttl">' + esc(i.title) + "<small>" + esc(t(i.category)) + " · " + esc(i.asset) + extras(i) + "</small></td><td>" + sevPill(i.severity) + '<span class="rk rk-' + esc(i.risk_band) + '">' + t("Risk") + " " + i.risk + "</span></td><td>" + stPill(i.status) + "</td><td>" + who(i.assignee) + "</td><td>" + sla(i) + '</td><td class="mut sm">' + fshort(i.created_at) + "</td></tr>";
  }).join("") : '<tr><td colspan="' + (cols.length + 1) + '"><div class="empty"><b>' + t("No incidents match") + "</b>" + t("Clear a filter or search term to see more.") + "</div></td></tr>";
  $("#listBody").innerHTML = '<div class="panel tw"><table><thead><tr>' + th + "</tr></thead><tbody>" + rows + "</tbody></table></div>";
  $$("th.s").forEach(function (h) { h.onclick = function () { var c = h.dataset.k; SORT = SORT.key === c ? { key: c, dir: -SORT.dir } : { key: c, dir: 1 }; drawTable(); }; });
  $$("#listBody tr.link").forEach(function (tr) { var go = function () { location.hash = "#/incidents/" + tr.dataset.id; }; tr.onclick = go; tr.onkeydown = function (e) { if (e.key === "Enter" && e.target === tr) go(); }; });
  $$("#listBody input.sel").forEach(function (c) { c.onclick = function (e) { e.stopPropagation(); c.checked ? SEL.add(c.dataset.id) : SEL.delete(c.dataset.id); c.closest("tr").classList.toggle("sel", c.checked); drawBulk(); }; });
  var sa = $("#selAll"); if (sa) sa.onchange = function () { SEL = new Set(sa.checked ? list.filter(function (i) { return i.status !== "Closed"; }).map(function (i) { return i.id; }) : []); drawTable(); drawBulk(); };
}
function drawBoard() {
  var list = INC.filter(matches), w = canWrite(), sev = function (s) { return META.severities.indexOf(s); };
  $("#listBody").innerHTML = '<div class="board">' + META.statuses.map(function (st) {
    var items = list.filter(function (i) { return i.status === st; }).sort(function (a, b) { return sev(b.severity) - sev(a.severity) || (a.due_at > b.due_at ? 1 : -1); });
    return '<section class="col" data-st="' + st + '" aria-label="' + t(st) + '"><h4>' + stPill(st) + "<span>" + items.length + '</span></h4><div class="cards">' + (items.map(function (i) {
      return '<article class="card sig s-' + i.severity + '" tabindex="0" data-id="' + esc(i.id) + '"' + (w && i.status !== "Closed" ? ' draggable="true"' : "") + '><div style="display:flex;justify-content:space-between;gap:6px;align-items:center"><span class="idc">' + esc(i.id) + "</span>" + sevPill(i.severity) + '</div><div class="t">' + esc(i.title) + '</div><div class="m"><span>' + esc(i.asset) + "</span>" + who(i.assignee).replace("white-space:nowrap", "") + "</div>" +
        (i.n_chk ? '<div class="meter" title="' + i.n_chk_done + "/" + i.n_chk + '"><i style="width:' + (i.n_chk_done / i.n_chk * 100) + '%"></i></div>' : "") + (i.status === "Closed" ? "" : "<div>" + sla(i) + "</div>") + "</article>";
    }).join("") || '<div class="mut sm" style="text-align:center;padding:14px 0">' + t("Nothing here") + "</div>") + "</div></section>";
  }).join("") + "</div>" + (w ? '<p class="mut sm">' + t("Drag a card to another column to change its status.") + "</p>" : "");
  $$(".card").forEach(function (c) {
    c.onclick = function () { location.hash = "#/incidents/" + c.dataset.id; }; c.onkeydown = function (e) { if (e.key === "Enter") c.click(); };
    c.ondragstart = function (e) { e.dataTransfer.setData("text/plain", c.dataset.id); c.classList.add("drag"); }; c.ondragend = function () { c.classList.remove("drag"); };
  });
  $$(".col").forEach(function (col) {
    if (!w) return;
    col.ondragover = function (e) { e.preventDefault(); col.classList.add("over"); }; col.ondragleave = function () { col.classList.remove("over"); };
    col.ondrop = async function (e) {
      e.preventDefault(); col.classList.remove("over"); var id = e.dataTransfer.getData("text/plain"), to = col.dataset.st, inc = INC.filter(function (i) { return i.id === id; })[0];
      if (!inc || inc.status === to) return;
      if (to === "Closed") { openClose(id); return; }
      try { await api("POST", "/api/incidents/" + encodeURIComponent(id) + "/status", { status: to }); toast(t("Status updated")); INC = await api("GET", "/api/incidents"); drawList(); } catch (x) {}
    };
  });
}
function drawBulk() {
  var b = $("#bulkBar"); if (!b) return; if (!SEL.size || VIEWMODE === "board") { b.innerHTML = ""; return; }
  b.innerHTML = '<div class="bulk"><b>' + t("{n} selected", { n: SEL.size }) + '</b><select id="bOp" aria-label="' + t("Action") + '"><option value="status">' + t("Change status") + '</option><option value="assign">' + t("Assign to") + '</option><option value="severity">' + t("Change severity") + '</option></select><select id="bVal" aria-label="' + t("Value") + '"></select><button class="btn pri" id="bGo">' + t("Apply") + '</button><button class="btn" id="bClr">' + t("Clear") + "</button></div>";
  var fill = function () { var op = $("#bOp").value; $("#bVal").innerHTML = op === "status" ? META.statuses.slice(0, 4).map(function (s) { return '<option value="' + s + '">' + t(s) + "</option>"; }).join("") : op === "severity" ? META.severities.map(function (s) { return '<option value="' + s + '">' + t(s) + "</option>"; }).join("") : '<option value="Unassigned">' + t("Unassigned") + "</option>" + META.people.map(function (p) { return '<option value="' + esc(p.username) + '">' + esc(p.full_name) + "</option>"; }).join(""); };
  fill(); $("#bOp").onchange = fill; $("#bClr").onclick = function () { SEL.clear(); drawTable(); drawBulk(); };
  $("#bGo").onclick = async function () { try { var r = await api("POST", "/api/incidents/bulk", { ids: Array.from(SEL), op: $("#bOp").value, value: $("#bVal").value }); toast(t("{n} updated, {s} skipped", { n: r.updated, s: r.skipped })); SEL.clear(); INC = await api("GET", "/api/incidents"); drawTable(); drawBulk(); } catch (x) {} };
}

/* ============ INCIDENT DETAIL ============ */
var KIND = { created: "Reported", comment: "Comment", note: "Action taken", status: "Status", assign: "Assignment", severity: "Severity", close: "Closed", evidence: "Evidence", ioc: "Indicator", check: "Checklist", classify: "Classification", edit: "Edited" };
function taskText(c) { return LANG === "ar" && c.text_ar ? c.text_ar : c.text; }
function readB64(file) { return new Promise(function (res, rej) { var r = new FileReader(); r.onload = function () { res(String(r.result).split(",")[1] || ""); }; r.onerror = rej; r.readAsDataURL(file); }); }
async function vDetail(id, my) {
  var i; try { i = await api("GET", "/api/incidents/" + encodeURIComponent(id), null, true); } catch (e) { if (e.message === "auth") throw e; head(t("Incident not found")); $("#view").innerHTML = '<a class="back" href="#/incidents">' + icon("back", "sm flip") + t("All incidents") + '</a><div class="panel"><div class="empty"><b>' + t("Incident not found") + "</b>" + t("It may have been deleted.") + "</div></div>"; return; }
  if (my !== seq) return;
  var open = i.status !== "Closed", w = canWrite(), enc = encodeURIComponent(i.id);
  head(i.id, t("Reported {d} by {u}", { d: fdate(i.created_at), u: person(i.reporter) || i.reporter }),
    '<a class="btn" href="#/incidents/' + enc + '/report">' + icon("report") + t("Generate report") + "</a>" + (w && !open ? '<button class="btn" id="bReopen">' + t("Reopen") + "</button>" : "") + (w && open ? '<button class="btn pri" id="bClose">' + icon("check") + t("Close incident") + "</button>" : "") + (isAdmin() ? '<button class="btn dng" id="bDel">' + icon("trash") + t("Delete") + "</button>" : ""));
  var steps = ["New", "Investigating", "Contained", "Resolved"];
  var step = i.status === "Closed" ? "<div>" + stPill("Closed") + "</div>" : '<div class="stepper" role="group" aria-label="' + t("Status") + '">' + steps.map(function (s) { return '<button data-s="' + s + '" class="' + (i.status === s ? "on" : "") + '"' + (!w ? " disabled" : "") + ">" + t(s) + "</button>"; }).join("") + "</div>";
  var asg = '<option value="Unassigned">' + t("Unassigned") + "</option>" + META.people.map(function (p) { return '<option value="' + esc(p.username) + '">' + esc(p.full_name) + "</option>"; }).join("");
  var done = i.checklist.filter(function (c) { return c.done; }).length;
  var tabs = [["timeline", t("Timeline"), i.events.length], ["checklist", t("Checklist"), done + "/" + i.checklist.length], ["iocs", t("Indicators"), i.iocs.length], ["evidence", t("Evidence"), i.evidence.length], ["related", t("Related"), i.related.length]];
  if (!tabs.some(function (x) { return x[0] === DTAB; })) DTAB = "timeline";
  var main = '<div class="panel hero sig s-' + i.severity + '"><div class="dhead"><h2>' + esc(i.title) + (w && open ? ' <button class="btn ghost sm icon" id="bEdit" title="' + t("Edit details") + '" aria-label="' + t("Edit details") + '">' + icon("edit", "sm") + "</button>" : "") + '</h2></div><div class="dhead" style="margin:6px 0 12px">' + sevPill(i.severity) + stPill(i.status) + tlpTag(i.tlp) + '<span class="mut sm">' + esc(t(i.category)) + "</span></div><div class=\"desc\">" + esc(i.description) + "</div>" +
    (i.resolution ? '<div class="note" style="margin-top:14px"><b>' + t("Resolution") + ":</b> " + esc(i.resolution) + (i.root_cause ? "<br><b>" + t("Root cause") + ":</b> " + esc(i.root_cause) : "") + (i.lessons ? "<br><b>" + t("Lessons learned") + ":</b> " + esc(i.lessons) : "") + "</div>" : "") + "</div>" +
    '<div class="panel mt"><div class="body" style="padding-top:6px"><div class="tabs" role="tablist">' + tabs.map(function (x) { return '<button role="tab" data-tab="' + x[0] + '" class="' + (DTAB === x[0] ? "on" : "") + '">' + x[1] + '<span class="ct">' + x[2] + "</span></button>"; }).join("") + '</div><div id="tabBody"></div></div></div>';
  var side = '<div class="panel"><div class="body"><dl class="facts"><div><dt>' + t("Status") + "</dt><dd>" + step + "</dd></div>" +
    "<div><dt>" + t("Response target") + "</dt><dd>" + sla(i) + '<span class="mut sm">' + t("Due {d}", { d: fdate(i.due_at) }) + (i.resolved_at ? " · " + t("resolved {d}", { d: fdate(i.resolved_at) }) : "") + "</span></dd></div>" +
    "<div><dt>" + t("Assignee") + "</dt><dd>" + (w && open ? '<select id="sAsg" aria-label="' + t("Assignee") + '">' + asg + "</select>" : who(i.assignee)) + "</dd></div>" +
    "<div><dt>" + t("Severity") + "</dt><dd>" + (w && open ? '<select id="sSev" aria-label="' + t("Severity") + '">' + META.severities.map(function (s) { return '<option value="' + s + '">' + t(s) + "</option>"; }).join("") + "</select>" : sevPill(i.severity)) + "</dd></div>" +
    "<div><dt>" + t("Classification") + "</dt><dd>" + tlpTag(i.tlp) + (w && open ? ' <button class="btn ghost sm" id="bCls">' + t("Edit") + "</button>" : "") + '<div class="chips" style="margin-top:8px">' + (i.mitre.length ? i.mitre.map(function (m) { return '<span class="tag mitre">' + esc(t(m)) + "</span>"; }).join("") : '<span class="mut sm">' + t("No ATT&CK tactics tagged") + "</span>") + "</div></dd></div>" +
    "<div><dt>" + t("Affected asset") + "</dt><dd>" + esc(i.asset) + (i.asset_registered ? " " + sevPill(i.asset_crit) : ' <span class="tag" title="' + esc(t("Add it to the asset inventory to set its criticality")) + '">' + t("Unregistered asset") + "</span>") + "</dd></div><div><dt>" + t("Risk score") + "</dt><dd>" + riskPill(i) + ' <span class="mut sm">' + t("severity × asset criticality") + "</span></dd></div><div><dt>" + t("Detected by") + "</dt><dd>" + esc(t(i.source)) + "</dd></div><div><dt>" + t("Last updated") + "</dt><dd>" + fdate(i.updated_at) + "</dd></div></dl>" + frameworkBox(i.framework) + "</div></div>";
  $("#view").innerHTML = '<a class="back" href="#/incidents">' + icon("back", "sm flip") + t("All incidents") + '</a><div class="dgrid"><div>' + main + "</div><div>" + side + "</div></div>";
  if ($("#sAsg")) $("#sAsg").value = i.assignee; if ($("#sSev")) $("#sSev").value = i.severity;
  var act = async function (op, body, msg) { await api("POST", "/api/incidents/" + enc + "/" + op, body || {}); if (msg) toast(msg); render(true); };
  $$(".stepper button").forEach(function (b) { b.onclick = function () { if (b.dataset.s !== i.status) act("status", { status: b.dataset.s }, t("Status updated")); }; });
  if ($("#sAsg")) $("#sAsg").onchange = function () { act("assign", { assignee: this.value }, t("Assignee updated")); };
  if ($("#sSev")) $("#sSev").onchange = function () { act("severity", { severity: this.value }, t("Severity updated")); };
  if ($("#bReopen")) $("#bReopen").onclick = function () { act("reopen", {}, t("Incident reopened")); };
  if ($("#bClose")) $("#bClose").onclick = function () { openClose(i.id); };
  if ($("#bDel")) $("#bDel").onclick = async function () { if (confirm(t("Delete {id} permanently? This cannot be undone.", { id: i.id }))) { await api("DELETE", "/api/incidents/" + enc); toast(t("Incident deleted")); location.hash = "#/incidents"; } };
  if ($("#bEdit")) $("#bEdit").onclick = function () { openEdit(i); };
  if ($("#bCls")) $("#bCls").onclick = function () { openCls(i); };
  $$(".tabs button").forEach(function (b) { b.onclick = function () { DTAB = b.dataset.tab; $$(".tabs button").forEach(function (x) { x.classList.toggle("on", x === b); }); drawTab(i, act, w && open); }; });
  drawTab(i, act, w && open);
}
function drawTab(i, act, can) {
  var el = $("#tabBody"), enc = encodeURIComponent(i.id), h = "";
  if (DTAB === "timeline") {
    h = '<ul class="tl">' + i.events.map(function (e) { return '<li class="' + esc(e.kind) + '"><div class="m"><b>' + esc(e.kind === "note" ? t("Action taken") + (e.tag ? " · " + t(e.tag) : "") : t(KIND[e.kind] || e.kind)) + "</b> · " + esc(person(e.username) || e.username) + " · " + fdate(e.at) + '</div><div class="tx">' + (e.kind === "comment" ? mentionText(e.text) : esc(e.text)) + "</div></li>"; }).join("") + "</ul>" +
      (canWrite() ? '<form id="fComment" class="noprint cmt"><label for="cmT">' + t("Discuss with the team") + '</label><textarea id="cmT" required maxlength="2000" placeholder="' + esc(t("Write a comment. Type @username to notify a colleague.")) + '" style="min-height:60px"></textarea><div class="chips">' + META.people.filter(function (p) { return p.username !== ME.username; }).map(function (p) { return '<button type="button" class="chip" data-at="' + esc(p.username) + '">@' + esc(p.username) + "</button>"; }).join("") + '</div><div style="margin-top:8px"><button class="btn">' + t("Post comment") + "</button></div></form>" : "") +
      (can ? '<form id="fNote" class="noprint"><label for="noteT">' + t("Record an action taken") + '</label><div class="g2" style="grid-template-columns:190px 1fr;align-items:start"><select id="noteTag" aria-label="' + t("Action type") + '">' + META.action_types.map(function (x) { return '<option value="' + esc(x) + '">' + esc(t(x)) + "</option>"; }).join("") + '</select><textarea id="noteT" required maxlength="2000" placeholder="' + esc(t("What was done, found or decided")) + '" style="min-height:70px"></textarea></div><div style="margin-top:8px"><button class="btn pri">' + t("Add action") + "</button></div></form>" : "");
  } else if (DTAB === "checklist") {
    var d = i.checklist.filter(function (c) { return c.done; }).length, n = i.checklist.length;
    h = (n ? '<div class="prog"><b>' + d + "/" + n + '</b><div class="meter"><i style="width:' + (d / n * 100) + '%"></i></div></div>' : "") + '<ul class="checks">' + i.checklist.map(function (c) {
      return '<li class="' + (c.done ? "done" : "") + '"><input type="checkbox" data-cid="' + c.id + '"' + (c.done ? " checked" : "") + (can ? "" : " disabled") + ' aria-label="' + esc(taskText(c)) + '"><div style="flex:1"><span class="txt">' + esc(taskText(c)) + "</span>" + (c.done ? '<span class="by">' + t("Done by {u} · {d}", { u: esc(person(c.done_by) || c.done_by), d: fshort(c.done_at) }) + "</span>" : "") + "</div>" + (can ? '<button class="btn ghost sm icon" data-cdel="' + c.id + '" aria-label="' + t("Remove") + '">' + icon("trash", "sm") + "</button>" : "") + "</li>";
    }).join("") + "</ul>" + (n ? "" : '<div class="empty"><b>' + t("No checklist yet") + "</b>" + t("A playbook checklist guides the response step by step.") + (can ? ' <button class="btn sm" id="bPb" style="margin-inline-start:8px">' + t("Apply playbook for {c}", { c: t(i.category) }) + "</button>" : "") + "</div>") +
      (can ? '<form id="fChk" class="addrow"><input id="chkT" maxlength="200" placeholder="' + esc(t("Add a task")) + '" aria-label="' + t("Add a task") + '"><button class="btn">' + t("Add") + "</button></form>" : "");
  } else if (DTAB === "iocs") {
    h = (i.iocs.length ? '<div class="tw"><table><thead><tr><th>' + t("Type") + "</th><th>" + t("Indicator") + "</th><th>" + t("Note") + "</th><th>" + t("Added") + "</th><th></th></tr></thead><tbody>" + i.iocs.map(function (x) {
      return '<tr><td><span class="tag">' + esc(t(x.type)) + '</span></td><td><span class="mono" style="overflow-wrap:anywhere">' + esc(x.value) + "</span>" + (x.seen && x.seen.length ? '<div class="sm" style="color:var(--crit);font-weight:600">' + t("Also seen in {n} other incidents", { n: x.seen.length }) + ": " + x.seen.map(function (s) { return '<a href="#/incidents/' + esc(s) + '">' + esc(s) + "</a>"; }).join(", ") + "</div>" : "") + '</td><td class="sm">' + esc(x.note) + '</td><td class="mut sm">' + esc(person(x.added_by) || x.added_by) + "<br>" + fshort(x.added_at) + '</td><td style="white-space:nowrap"><button class="btn ghost sm icon" data-copy="' + esc(x.value) + '" aria-label="' + t("Copy") + '">' + icon("copy", "sm") + "</button>" + (can ? '<button class="btn ghost sm icon" data-idel="' + x.id + '" aria-label="' + t("Remove") + '">' + icon("trash", "sm") + "</button>" : "") + "</td></tr>";
    }).join("") + "</tbody></table></div>" : '<div class="empty"><b>' + t("No indicators yet") + "</b>" + t("Add IPs, domains, URLs, hashes or emails seen in this incident. Matches in other incidents are flagged automatically.") + "</div>") +
      (can ? '<form id="fIoc" class="tools" style="margin-top:14px"><select id="iocT" style="width:130px" aria-label="' + t("Type") + '"><option value="">' + t("Auto-detect") + "</option>" + META.ioc_types.map(function (x) { return '<option value="' + x + '">' + t(x) + "</option>"; }).join("") + '</select><input id="iocV" required maxlength="500" style="flex:2;min-width:200px;width:auto;direction:ltr" placeholder="185.220.101.47, evil[.]com, hxxp://…" aria-label="' + t("Indicator") + '"><input id="iocN" maxlength="300" style="flex:1;min-width:140px;width:auto" placeholder="' + esc(t("Note (optional)")) + '" aria-label="' + t("Note") + '"><button class="btn pri">' + t("Add indicator") + "</button></form>" : "");
  } else if (DTAB === "evidence") {
    h = (i.evidence.length ? '<div class="tw"><table><thead><tr><th>' + t("File") + "</th><th>SHA-256</th><th>" + t("Added") + "</th><th></th></tr></thead><tbody>" + i.evidence.map(function (x) {
      return "<tr><td><b>" + esc(x.filename) + '</b><div class="mut sm">' + kb(x.size) + (x.note ? " · " + esc(x.note) : "") + '</div></td><td class="hash" style="max-width:280px">' + esc(x.sha256) + '</td><td class="mut sm">' + esc(person(x.uploaded_by) || x.uploaded_by) + "<br>" + fshort(x.uploaded_at) + '</td><td style="white-space:nowrap"><a class="btn sm" href="/api/incidents/' + enc + "/evidence/" + x.id + '">' + icon("download", "sm") + t("Download") + "</a>" + (can && isAdmin() ? ' <button class="btn ghost sm icon" data-edel="' + x.id + '" aria-label="' + t("Remove") + '">' + icon("trash", "sm") + "</button>" : "") + "</td></tr>";
    }).join("") + '</tbody></table></div><p class="mut sm">' + t("Every file is hashed when it is uploaded and verified again on every download, so tampering is detected.") + "</p>" : "") +
      (can ? '<div class="drop" id="drop">' + icon("upload") + '<div style="margin:6px 0"><b>' + t("Drop a file here") + "</b> " + t("or") + ' <label for="evF" class="btn sm" style="display:inline-flex;margin:0;cursor:pointer">' + t("choose a file") + '</label><input id="evF" type="file" hidden></div><div class="sm">' + t("Logs, screenshots, memory images or e-mails. Up to 8 MB each.") + '</div></div>' : (i.evidence.length ? "" : '<div class="empty"><b>' + t("No evidence attached") + "</b></div>"));
  } else if (DTAB === "related") {
    h = i.related.length ? i.related.map(function (r) { return '<a class="rel" href="#/incidents/' + esc(r.id) + '"><span>' + sevPill(r.severity) + "</span><span><b>" + esc(r.title) + '</b><br><span class="mut sm"><span class="mono">' + esc(r.id) + "</span> · " + t(r.status) + " · " + r.reasons.map(function (x) { return x.kind === "ioc" ? t("shared indicator {v}", { v: x.value }) : t("same asset {v}", { v: x.value }); }).join(", ") + "</span></span></a>"; }).join("") : '<div class="empty"><b>' + t("No related incidents") + "</b>" + t("Incidents that share an indicator or an asset with this one appear here.") + "</div>";
  }
  el.innerHTML = h;
  if ($("#fComment")) {
    $("#fComment").onsubmit = function (e) { e.preventDefault(); act("comment", { text: $("#cmT").value }, t("Comment posted")); };
    $$("[data-at]").forEach(function (b) { b.onclick = function () { var ta = $("#cmT"); ta.value += (ta.value && !/\s$/.test(ta.value) ? " " : "") + "@" + b.dataset.at + " "; ta.focus(); }; });
  }
  if ($("#fNote")) $("#fNote").onsubmit = function (e) { e.preventDefault(); act("notes", { text: $("#noteT").value, tag: $("#noteTag").value }, t("Action recorded")); };
  $$("[data-cid]").forEach(function (c) { c.onchange = function () { act("checklist/" + c.dataset.cid + "/toggle"); }; });
  $$("[data-cdel]").forEach(function (b) { b.onclick = function () { act("checklist/" + b.dataset.cdel + "/delete"); }; });
  if ($("#bPb")) $("#bPb").onclick = function () { act("playbook", {}, t("Playbook applied")); };
  if ($("#fChk")) $("#fChk").onsubmit = function (e) { e.preventDefault(); if ($("#chkT").value.trim()) act("checklist", { text: $("#chkT").value }); };
  if ($("#fIoc")) $("#fIoc").onsubmit = async function (e) {
    e.preventDefault(); try { var r = await api("POST", "/api/incidents/" + enc + "/iocs", { type: $("#iocT").value, value: $("#iocV").value, note: $("#iocN").value }); toast(r.matches.length ? t("Added. Also seen in {n} other incidents.", { n: r.matches.length }) : t("Indicator added"), r.matches.length ? "err" : ""); render(true); } catch (x) {}
  };
  $$("[data-idel]").forEach(function (b) { b.onclick = function () { act("iocs/" + b.dataset.idel + "/delete"); }; });
  $$("[data-copy]").forEach(function (b) { b.onclick = function () { copyText(b.dataset.copy); }; });
  $$("[data-edel]").forEach(function (b) { b.onclick = function () { if (confirm(t("Delete this evidence file? This is recorded in the audit log."))) act("evidence/" + b.dataset.edel + "/delete", {}, t("Evidence removed")); }; });
  var up = async function (file) {
    if (!file) return; if (file.size > 8 * 1048576) return toast(t("File is larger than 8 MB"), "err");
    try { var data = await readB64(file); var r = await api("POST", "/api/incidents/" + enc + "/evidence", { filename: file.name, data: data }); toast(t("Evidence stored · SHA-256 {h}…", { h: r.sha256.slice(0, 12) })); render(true); } catch (x) {}
  };
  if ($("#evF")) $("#evF").onchange = function () { up(this.files[0]); };
  var dz = $("#drop"); if (dz) { dz.ondragover = function (e) { e.preventDefault(); dz.classList.add("over"); }; dz.ondragleave = function () { dz.classList.remove("over"); }; dz.ondrop = function (e) { e.preventDefault(); dz.classList.remove("over"); up(e.dataTransfer.files[0]); }; }
}

/* ---------- dialogs: new / close / edit / classify ---------- */
var CHIPSEL = {};
function mitreChips(host, sel) {
  var draw = function () { $(host).innerHTML = META.mitre.map(function (m) { return '<button type="button" class="chip' + (sel.has(m) ? " on" : "") + '" data-m="' + esc(m) + '" aria-pressed="' + sel.has(m) + '">' + esc(t(m)) + "</button>"; }).join(""); $$(host + " .chip").forEach(function (b) { b.onclick = function () { sel.has(b.dataset.m) ? sel.delete(b.dataset.m) : sel.add(b.dataset.m); draw(); }; }); };
  draw();
}
function mentionText(s) {
  return esc(s).replace(/(^|[\s(])@([A-Za-z0-9._-]{3,32})/g, function (m, p, n) {
    return META.people.some(function (x) { return x.username.toLowerCase() === n.toLowerCase(); }) ? p + '<span class="mention">@' + n + "</span>" : m; });
}
function frameworkBox(f) {
  if (!f) return "";
  var row = function (x) { return '<li><b class="mono">' + esc(x.id) + "</b> " + esc(x.name) + "</li>"; };
  return '<details class="fw noprint"><summary>' + t("Framework mapping") + '</summary><div class="mut sm" style="margin:6px 0 2px">ISO/IEC 27001:2022 Annex A</div><ul>' + f.iso.map(row).join("") + '</ul><div class="mut sm" style="margin:6px 0 2px">NIST CSF 2.0</div><ul>' + f.nist.map(row).join("") + '</ul><p class="mut sm" style="margin:6px 0 0">' + t("Indicative mapping to support reporting; it is not a compliance assessment.") + "</p></details>";
}
function fillAssetList() { $("#assetList").innerHTML = (META.assets || []).map(function (a) { return '<option value="' + esc(a.name) + '">' + esc(t(a.type) + " · " + t(a.criticality)) + "</option>"; }).join(""); }
function openNew() {
  fillAssetList();
  var o = function (a, tr) { return a.map(function (x) { return '<option value="' + esc(x) + '">' + esc(tr ? t(x) : x) + "</option>"; }).join(""); };
  $("#nCat").innerHTML = o(META.categories, 1); $("#nSev").innerHTML = o(META.severities, 1); $("#nSrc").innerHTML = o(META.sources, 1); $("#nTlp").innerHTML = o(META.tlp); $("#nSev").value = "Medium"; $("#nTlp").value = "AMBER";
  $("#nAsg").innerHTML = '<option value="Unassigned">' + t("Unassigned") + "</option>" + META.people.map(function (p) { return '<option value="' + esc(p.username) + '">' + esc(p.full_name) + "</option>"; }).join("");
  ["nTitle", "nDesc", "nAsset"].forEach(function (id) { $("#" + id).value = ""; }); $("#nErr").textContent = ""; CHIPSEL.n = new Set(); mitreChips("#nMit", CHIPSEL.n);
  var s = function () { $("#nSla").textContent = t("Response target for {s} severity: {h} hours from now.", { s: t($("#nSev").value), h: META.sla_hours[$("#nSev").value] }); }; s(); $("#nSev").onchange = s;
  $("#dNew").showModal();
}
$("#fNew").onsubmit = async function (e) {
  e.preventDefault();
  try { var r = await api("POST", "/api/incidents", { title: $("#nTitle").value, description: $("#nDesc").value, category: $("#nCat").value, severity: $("#nSev").value, asset: $("#nAsset").value, source: $("#nSrc").value, assignee: $("#nAsg").value, tlp: $("#nTlp").value, mitre: Array.from(CHIPSEL.n) }, true); $("#dNew").close(); toast(t("Incident {id} reported", { id: r.id })); location.hash = "#/incidents/" + r.id; }
  catch (x) { $("#nErr").textContent = x.msg || t("Could not save"); }
};
function openClose(id) {
  $("#cNote").value = ""; $("#cRoot").value = ""; $("#cLes").value = ""; $("#cErr").textContent = ""; $("#dClose").showModal();
  $("#fClose").onsubmit = async function (e) { e.preventDefault(); try { await api("POST", "/api/incidents/" + encodeURIComponent(id) + "/close", { note: $("#cNote").value, root_cause: $("#cRoot").value, lessons: $("#cLes").value }, true); $("#dClose").close(); toast(t("Incident closed")); if (/^#\/incidents\/?$/.test(location.hash)) { INC = await api("GET", "/api/incidents"); drawList(); } else render(true); } catch (x) { $("#cErr").textContent = x.msg || t("Could not close"); } };
}
function openEdit(i) {
  fillAssetList();
  $("#eTitle").value = i.title; $("#eDesc").value = i.description; $("#eAsset").value = i.asset; $("#eErr").textContent = ""; $("#dEdit").showModal();
  $("#fEdit").onsubmit = async function (e) { e.preventDefault(); try { await api("POST", "/api/incidents/" + encodeURIComponent(i.id) + "/edit", { title: $("#eTitle").value, description: $("#eDesc").value, asset: $("#eAsset").value }, true); $("#dEdit").close(); toast(t("Details updated")); render(true); } catch (x) { $("#eErr").textContent = x.msg || t("Could not save"); } };
}
function openCls(i) {
  $("#kTlp").innerHTML = META.tlp.map(function (x) { return "<option>" + x + "</option>"; }).join(""); $("#kTlp").value = i.tlp; $("#kErr").textContent = ""; CHIPSEL.k = new Set(i.mitre); mitreChips("#kMit", CHIPSEL.k); $("#dCls").showModal();
  $("#fCls").onsubmit = async function (e) { e.preventDefault(); try { await api("POST", "/api/incidents/" + encodeURIComponent(i.id) + "/classify", { tlp: $("#kTlp").value, mitre: Array.from(CHIPSEL.k) }, true); $("#dCls").close(); toast(t("Classification updated")); render(true); } catch (x) { $("#kErr").textContent = x.msg || t("Could not save"); } };
}

/* ============ INCIDENT REPORT ============ */
async function vReport(id, my) {
  var i; try { i = await api("GET", "/api/incidents/" + encodeURIComponent(id), null, true); } catch (e) { if (e.message === "auth") throw e; location.hash = "#/incidents"; return; }
  if (my !== seq) return;
  head(t("Incident report"), i.id, '<a class="btn" href="#/incidents/' + encodeURIComponent(i.id) + '">' + icon("back", "sm flip") + t("Back to incident") + '</a><button class="btn pri" id="bP">' + icon("report") + t("Print / Save as PDF") + "</button>");
  $("#bP").onclick = function () { window.print(); };
  var ttr = i.resolved_at ? dur(new Date(i.resolved_at) - new Date(i.created_at)) : t("Not resolved yet");
  var slaTxt = i.sla === "met" ? t("Met") : i.sla === "breached" ? (i.resolved_at ? t("Breached") : t("Overdue")) : i.sla === "at_risk" ? t("At risk") : t("Within target");
  var kv = function (a, b) { return "<div><small>" + a + "</small>" + b + "</div>"; };
  var acts = i.events.filter(function (e) { return e.kind === "note"; }), other = i.events.filter(function (e) { return e.kind !== "note"; });
  var row = function (e, withTag) { return '<tr><td style="white-space:nowrap">' + fdate(e.at) + "</td><td>" + esc(withTag ? t(e.tag || "Other") : t(KIND[e.kind] || e.kind)) + "</td><td>" + esc(person(e.username) || e.username) + '</td><td style="white-space:pre-wrap">' + esc(e.text) + "</td></tr>"; };
  var tbl = function (rows, w, first) { return rows.length ? "<table><thead><tr><th>" + t("Time") + "</th><th>" + first + "</th><th>" + t("By") + "</th><th>" + t("Details") + "</th></tr></thead><tbody>" + rows.map(function (e) { return row(e, w); }).join("") + "</tbody></table>" : '<p class="mut">' + t("None recorded.") + "</p>"; };
  var d = i.checklist.filter(function (c) { return c.done; }).length;
  $("#view").innerHTML = '<article class="rpt"><div class="rh"><div><div class="mut sm">SentinelDesk · ' + t("Cybersecurity Incident Report") + "</div><h1>" + esc(i.title) + '</h1></div><div style="text-align:end"><div class="idc" style="font-size:16px">' + esc(i.id) + "</div>" + stPill(i.status) + "<br>" + tlpTag(i.tlp) + "</div></div>" +
    "<h2>1. " + t("Incident summary") + '</h2><div class="kv">' + kv(t("Incident type"), esc(t(i.category))) + kv(t("Severity"), sevPill(i.severity)) + kv(t("Affected asset"), esc(i.asset)) + kv(t("Detection source"), esc(t(i.source))) +
    kv(t("Reported by"), esc(person(i.reporter) || i.reporter)) + kv(t("Responsible analyst"), esc(person(i.assignee) || t("Unassigned"))) + kv(t("Reported"), fdate(i.created_at)) + kv(t("Response target"), fdate(i.due_at) + " (" + slaTxt + ")") +
    kv(t("Resolved"), fdate(i.resolved_at)) + kv(t("Closed"), fdate(i.closed_at)) + kv(t("Time to resolve"), ttr) + kv(t("ATT&CK tactics"), i.mitre.length ? esc(i.mitre.map(function (m) { return t(m); }).join(", ")) : "-") + "</div>" +
    "<h2>2. " + t("Description") + '</h2><p class="desc" style="margin:0">' + esc(i.description) + "</p>" +
    "<h2>3. " + t("Indicators of compromise") + "</h2>" + (i.iocs.length ? "<table><thead><tr><th>" + t("Type") + "</th><th>" + t("Indicator") + "</th><th>" + t("Note") + "</th></tr></thead><tbody>" + i.iocs.map(function (x) { return "<tr><td>" + esc(t(x.type)) + '</td><td class="mono" style="overflow-wrap:anywhere">' + esc(x.value.replace(/\./g, "[.]")) + "</td><td>" + esc(x.note) + "</td></tr>"; }).join("") + '</tbody></table><p class="mut sm">' + t("Indicators are defanged in this report so they cannot be clicked by accident.") + "</p>" : '<p class="mut">' + t("None recorded.") + "</p>") +
    "<h2>4. " + t("Evidence") + "</h2>" + (i.evidence.length ? "<table><thead><tr><th>" + t("File") + "</th><th>SHA-256</th><th>" + t("Added") + "</th></tr></thead><tbody>" + i.evidence.map(function (x) { return "<tr><td>" + esc(x.filename) + " (" + kb(x.size) + ')</td><td class="mono" style="overflow-wrap:anywhere">' + esc(x.sha256) + "</td><td>" + fdate(x.uploaded_at) + " · " + esc(person(x.uploaded_by) || x.uploaded_by) + "</td></tr>"; }).join("") + "</tbody></table>" : '<p class="mut">' + t("None recorded.") + "</p>") +
    "<h2>5. " + t("Response checklist") + " (" + d + "/" + i.checklist.length + ")</h2>" + (i.checklist.length ? '<table><tbody>' + i.checklist.map(function (c) { return '<tr><td style="width:28px">' + (c.done ? "☑" : "☐") + "</td><td>" + esc(taskText(c)) + "</td><td>" + (c.done ? esc(person(c.done_by) || c.done_by) + " · " + fdate(c.done_at) : "") + "</td></tr>"; }).join("") + "</tbody></table>" : '<p class="mut">' + t("None recorded.") + "</p>") +
    "<h2>6. " + t("Actions taken") + "</h2>" + tbl(acts, true, t("Type")) + "<h2>7. " + t("Status and assignment history") + "</h2>" + tbl(other, false, t("Event")) +
    "<h2>8. " + t("Resolution and closure") + '</h2><p class="desc" style="margin:0">' + (i.resolution ? esc(i.resolution) : t("This incident has not been closed yet.")) + "</p>" +
    (i.root_cause ? "<p><b>" + t("Root cause") + ":</b> " + esc(i.root_cause) + "</p>" : "") + (i.lessons ? "<p><b>" + t("Lessons learned") + ":</b> " + esc(i.lessons) + "</p>" : "") +
    '<div class="sigs"><div>' + t("Prepared by") + ": " + esc(ME.full_name) + "<br>" + fdate(new Date().toISOString()) + "</div><div>" + t("Reviewed and approved by") + "</div></div></article>";
}
