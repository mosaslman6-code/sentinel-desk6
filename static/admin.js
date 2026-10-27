"use strict";
/* SentinelDesk 2.0 - indicators hub, period reports, users, audit, database manager, settings, account. */

/* ============ INDICATORS HUB ============ */
var IOCF = { q: "", type: "", multi: false };
async function vIocs(my) {
  var all = await api("GET", "/api/iocs"); if (my !== seq) return;
  head(t("Indicators"), t("{n} unique indicators across all incidents", { n: all.length }), '<a class="btn" href="/api/iocs.csv">' + icon("download") + t("Export CSV") + "</a>");
  $("#view").innerHTML = '<div class="tools"><input type="search" id="iq" placeholder="' + esc(t("Search indicators")) + '" value="' + esc(IOCF.q) + '" aria-label="' + t("Search indicators") + '"><select id="it" aria-label="' + t("Type") + '"><option value="">' + t("All types") + "</option>" + META.ioc_types.map(function (x) { return '<option value="' + x + '">' + t(x) + "</option>"; }).join("") + '</select><label class="chk"><input type="checkbox" id="im"' + (IOCF.multi ? " checked" : "") + "> " + t("Seen in more than one incident") + '</label></div><div id="iocBody"></div>';
  $("#it").value = IOCF.type;
  var draw = function () {
    IOCF.q = $("#iq").value; IOCF.type = $("#it").value; IOCF.multi = $("#im").checked; var q = IOCF.q.toLowerCase();
    var l = all.filter(function (g) { return (!IOCF.type || g.type === IOCF.type) && (!IOCF.multi || g.count > 1) && (!q || g.value.toLowerCase().indexOf(q) > -1 || g.notes.join(" ").toLowerCase().indexOf(q) > -1); });
    $("#iocBody").innerHTML = '<div class="panel tw"><table><thead><tr><th>' + t("Type") + "</th><th>" + t("Indicator") + "</th><th>" + t("Incidents") + "</th><th>" + t("Last seen") + "</th><th></th></tr></thead><tbody>" + (l.length ? l.map(function (g) {
      return '<tr class="' + (g.count > 1 ? "sig s-High" : "") + '"><td><span class="tag">' + esc(t(g.type)) + '</span></td><td><span class="mono" style="overflow-wrap:anywhere">' + esc(g.value) + "</span>" + (g.notes.length ? '<div class="mut sm">' + esc(g.notes[0]) + "</div>" : "") + '</td><td>' + (g.count > 1 ? '<div style="color:var(--high);font-weight:700" class="sm">' + t("Correlated across {n} incidents", { n: g.count }) + "</div>" : "") + g.incidents.map(function (i) { return '<a class="idc" href="#/incidents/' + esc(i.id) + '" title="' + esc(i.title) + '">' + esc(i.id) + "</a>"; }).join(" · ") + '</td><td class="mut sm">' + fshort(g.last_seen) + '</td><td><button class="btn ghost sm icon" data-copy="' + esc(g.value) + '" aria-label="' + t("Copy") + '">' + icon("copy", "sm") + "</button></td></tr>";
    }).join("") : '<tr><td colspan="5"><div class="empty"><b>' + t("No indicators match") + "</b>" + t("Add indicators from an incident's Indicators tab.") + "</div></td></tr>") + "</tbody></table></div>";
    $$("[data-copy]").forEach(function (b) { b.onclick = function () { copyText(b.dataset.copy); }; });
  };
  ["iq", "it", "im"].forEach(function (id) { $("#" + id).oninput = draw; }); draw();
}

var FW_BASE_ISO = ["A.5.24", "A.5.25", "A.5.26", "A.5.27", "A.5.28"], FW_BASE_NIST = ["DE.AE", "RS.MA", "RS.AN", "RS.MI", "RC.RP"];
/* ============ CSV IMPORT ============ */
var IMPORT_CSV = "";
function openImport() { IMPORT_CSV = ""; $("#iFile").value = ""; $("#iOut").innerHTML = ""; $("#iErr").textContent = ""; $("#iGo").disabled = true; $("#dImport").showModal(); }
$("#iFile").onchange = function () {
  var f = this.files[0]; IMPORT_CSV = ""; $("#iGo").disabled = true; $("#iErr").textContent = ""; $("#iOut").innerHTML = "";
  if (!f) return;
  if (f.size > 400000) { $("#iErr").textContent = t("Provide CSV text (400 KB at most)"); return; }
  var rd = new FileReader();
  rd.onload = async function () {
    IMPORT_CSV = String(rd.result);
    try {
      var r = await api("POST", "/api/incidents/import", { csv: IMPORT_CSV, dry_run: true }, true);
      $("#iOut").innerHTML = "<p><b>" + t("{n} rows read", { n: r.total }) + "</b> · " + t("{n} ready to import", { n: r.valid }) + (r.skipped_duplicates ? " · " + t("{n} duplicates skipped", { n: r.skipped_duplicates }) : "") + (r.error_count ? ' · <span style="color:var(--crit)">' + t("{n} with errors", { n: r.error_count }) + "</span>" : "") + "</p>" +
        (r.errors.length ? '<ul class="errs">' + r.errors.map(function (e) { return "<li>" + t("Row {n}", { n: e.row }) + ": " + esc(e.error) + "</li>"; }).join("") + "</ul><p class=\"mut\">" + t("Fix these rows and choose the file again. Nothing is imported while errors remain.") + "</p>" : "");
      $("#iGo").disabled = !(r.valid && !r.error_count); $("#iGo").dataset.n = r.valid;
    } catch (x) { $("#iErr").textContent = x.msg || t("Could not read the file"); }
  };
  rd.readAsText(f);
};
$("#iGo").onclick = async function () {
  this.disabled = true;
  try { var r = await api("POST", "/api/incidents/import", { csv: IMPORT_CSV, dry_run: false }, true); $("#dImport").close(); toast(t("{n} incidents imported", { n: r.created })); render(true); }
  catch (x) { $("#iErr").textContent = x.msg || t("Could not import"); }
};

/* ============ SYSTEM HEALTH ============ */
function humanBytes(n) { return n < 1024 ? n + " B" : n < 1048576 ? (n / 1024).toFixed(1) + " KB" : (n / 1048576).toFixed(1) + " MB"; }
async function vSystem(my) {
  var s = await api("GET", "/api/admin/system"); if (my !== seq) return;
  head(t("System health"), t("Security posture and operating status"), '<button class="btn" id="bRefresh">' + icon("pulse") + t("Refresh") + "</button>");
  var up = s.uptime_seconds, upTxt = up >= 86400 ? Math.floor(up / 86400) + " d " + Math.floor(up % 86400 / 3600) + " h" : up >= 3600 ? Math.floor(up / 3600) + " h " + Math.floor(up % 3600 / 60) + " min" : Math.floor(up / 60) + " min";
  var stat = function (k, v) { return '<div class="stat"><div class="k">' + k + '</div><div class="v">' + v + "</div></div>"; };
  var col = s.score >= 80 ? "var(--low)" : s.score >= 50 ? "var(--med)" : "var(--crit)";
  var ico = { ok: "●", warn: "▲", bad: "✖", info: "ℹ" };
  $("#view").innerHTML = '<div class="grid c-2"><div class="panel"><h3>' + t("Security checks") + '</h3><div class="body"><div class="score" style="color:' + col + '">' + s.score + '<small>/100</small></div><ul class="checks">' + s.checks.map(function (k) { return '<li class="lv-' + k.level + '"><span class="ck" aria-hidden="true">' + ico[k.level] + "</span><span>" + esc(tcheck(k.text)) + "</span></li>"; }).join("") + "</ul></div></div>" +
    '<div class="panel"><h3>' + t("Operating status") + '</h3><div class="body stats">' + stat(t("Version"), "v" + esc(s.version)) + stat("Python", esc(s.python)) + stat(t("Uptime"), upTxt) + stat(t("Database size"), humanBytes(s.db_bytes)) + stat(t("Evidence files"), s.evidence.files + " · " + humanBytes(s.evidence.bytes)) +
    stat(t("Backups"), s.backups.count + (s.backups.age_hours != null ? " · " + t("last {n} h ago", { n: s.backups.age_hours }) : "")) + stat(t("Incidents"), s.counts.incidents + " (" + t("{n} open", { n: s.counts.open }) + ")") + stat(t("Users"), s.counts.users) + stat(t("Assets"), s.counts.assets) + stat(t("Indicators"), s.counts.indicators) + stat(t("Active sessions"), s.sessions) + stat(t("API tokens"), s.api_tokens) + "</div></div></div>";
  $("#bRefresh").onclick = function () { render(true); };
}
function tcheck(txt) {
  var m;
  if ((m = txt.match(/^Default password still in use for: (.*)$/))) return t("Default password still in use for: {u}", { u: m[1] });
  if ((m = txt.match(/^Administrators without two-factor: (.*)$/))) return t("Administrators without two-factor: {u}", { u: m[1] });
  if ((m = txt.match(/^Last backup ([\d.]+) hours ago$/))) return t("Last backup {n} hours ago", { n: m[1] });
  if ((m = txt.match(/^The last backup is (\d+) days old$/))) return t("The last backup is {n} days old", { n: m[1] });
  if ((m = txt.match(/^Audit log chain intact \((\d+) entries\)$/))) return t("Audit log chain intact ({n} entries)", { n: m[1] });
  if ((m = txt.match(/^Audit log was tampered with at entry #(\d+)$/))) return t("Audit log was tampered with at entry #{n}", { n: m[1] });
  return t(txt);
}

/* ============ API REFERENCE ============ */
async function vApi(my) {
  head(t("API reference"), t("Automate SentinelDesk with scripts and tools"), '<a class="btn" href="#/account">' + icon("code") + t("Create API token") + "</a>");
  var base = location.origin, E = [
    ["GET", "/api/health", "Service status (public, no token needed).", "-"], ["GET", "/api/me", "Who the token belongs to and the effective role.", "R"],
    ["GET", "/api/incidents", "List every incident (summary with risk score).", "R"], ["GET", "/api/incidents/{id}", "One incident with timeline, checklist, indicators, evidence and framework mapping.", "R"],
    ["POST", "/api/incidents", "Create an incident. Body: title, description, category, severity, asset, source; optional assignee, tlp, mitre[].", "W"],
    ["POST", "/api/incidents/{id}/notes", "Record an action. Body: text, tag.", "W"], ["POST", "/api/incidents/{id}/comment", "Comment; @username notifies a colleague. Body: text.", "W"],
    ["POST", "/api/incidents/{id}/status", "Change status. Body: status = New | Investigating | Contained | Resolved.", "W"], ["POST", "/api/incidents/{id}/assign", "Assign. Body: assignee (username).", "W"],
    ["POST", "/api/incidents/import", "Bulk import from CSV text. Body: csv, dry_run (true to validate only).", "W"], ["GET", "/api/export.csv", "All incidents as CSV.", "R"],
    ["GET", "/api/assets", "Asset inventory with open incident counts.", "R"], ["POST", "/api/assets", "Register an asset. Body: name, type, criticality, owner, department, address, notes.", "W"],
    ["GET", "/api/iocs", "All indicators of compromise across incidents.", "R"], ["GET", "/api/report/summary?days=30", "Management report data: totals, risk, team performance, SLA, control mapping.", "R"],
    ["POST", "/api/integrations/webhook", "Ingest an alert from a SIEM/EDR. Uses the server's SENTINEL_WEBHOOK_TOKEN, not a personal token.", "-"]];
  var ex = 'curl -H "Authorization: Bearer sdk_YOUR_TOKEN" ' + base + "/api/incidents\n\n" + 'curl -X POST ' + base + '/api/incidents \\\n  -H "Authorization: Bearer sdk_YOUR_TOKEN" -H "Content-Type: application/json" \\\n  -d \'{"title":"Suspicious login","description":"Impossible travel","category":"Unauthorized Access","severity":"High","asset":"Mail gateway","source":"SIEM alert"}\'';
  $("#view").innerHTML = '<div class="panel"><h3>' + t("Authentication") + '</h3><div class="body"><p style="margin-top:0">' + t("Create a token on your Account page, then send it in the Authorization header. Read-only tokens can only call GET endpoints. A token never has more than analyst rights and cannot manage users, passwords or other tokens.") + "</p><pre class=\"code\" dir=\"ltr\">" + esc(ex) + '</pre><p class="mut sm" style="margin-bottom:0">' + t("Responses are JSON. Errors look like {\"error\": \"message\"} with an HTTP status code (401 invalid token, 403 not allowed, 400 invalid input).") + '</p></div></div><div class="panel tw" style="margin-top:16px"><table><thead><tr><th>' + t("Method") + "</th><th>" + t("Endpoint") + "</th><th>" + t("What it does") + "</th><th>" + t("Needs") + "</th></tr></thead><tbody>" + E.map(function (e) { return '<tr><td><span class="mth mth-' + e[0] + '">' + e[0] + '</span></td><td class="mono" dir="ltr">' + esc(e[1]) + "</td><td>" + esc(t(e[2])) + "</td><td style=\"white-space:nowrap\">" + (e[3] === "-" ? "-" : e[3] === "R" ? t("Read token") : t("Write token")) + "</td></tr>"; }).join("") + "</tbody></table></div>";
}

/* ============ ASSET INVENTORY ============ */
var ASSF = { q: "", crit: "", type: "" }, AID = null;
async function vAssets(my) {
  var all = await api("GET", "/api/assets"); if (my !== seq) return;
  head(t("Asset inventory"), t("{n} registered assets", { n: all.length }), (canWrite() ? '<button class="btn pri" id="bAsset">' + icon("plus") + t("Add asset") + "</button>" : "") + '<a class="btn" href="/api/assets.csv">' + icon("download") + t("Export CSV") + "</a>");
  var opts = function (list, cur, all) { return '<option value="">' + t(all) + "</option>" + list.map(function (x) { return '<option value="' + esc(x) + '"' + (x === cur ? " selected" : "") + ">" + esc(t(x)) + "</option>"; }).join(""); };
  $("#view").innerHTML = '<div class="tools"><input type="search" id="asq" placeholder="' + esc(t("Search assets")) + '" aria-label="' + t("Search assets") + '" value="' + esc(ASSF.q) + '"><select id="asc" aria-label="' + t("Criticality") + '">' + opts(META.criticality, ASSF.crit, "All criticality levels") + '</select><select id="ast" aria-label="' + t("Type") + '">' + opts(META.asset_types, ASSF.type, "All types") + '</select></div><div id="asBody"></div><p class="mut sm" style="margin-top:12px">' + t("Risk = incident severity × asset criticality (0-100).") + "</p>";
  if (canWrite()) $("#bAsset").onclick = function () { openAsset(null); };
  var draw = function () {
    ASSF.q = $("#asq").value; ASSF.crit = $("#asc").value; ASSF.type = $("#ast").value; var q = ASSF.q.toLowerCase();
    var l = all.filter(function (x) { return (!ASSF.crit || x.criticality === ASSF.crit) && (!ASSF.type || x.type === ASSF.type) && (!q || (x.name + " " + x.owner + " " + x.department + " " + x.address).toLowerCase().indexOf(q) > -1); });
    $("#asBody").innerHTML = '<div class="panel tw"><table><thead><tr><th>' + t("Asset") + "</th><th>" + t("Criticality") + "</th><th>" + t("Owner") + "</th><th>" + t("Open incidents") + "</th><th>" + t("Open risk") + "</th><th></th></tr></thead><tbody>" + (l.length ? l.map(function (x) {
      return '<tr><td><b>' + esc(x.name) + '</b><div class="mut sm">' + esc(t(x.type)) + (x.address ? ' · <span class="mono" dir="ltr">' + esc(x.address) + "</span>" : "") + "</div></td><td>" + sevPill(x.criticality) + "</td><td>" + (x.owner || x.department ? esc(x.owner) + '<div class="mut sm">' + esc(x.department) + "</div>" : '<span class="mut">-</span>') + "</td><td>" +
        (x.incidents ? '<a href="#/incidents" data-inc="' + esc(x.name) + '" dir="ltr" style="display:inline-block"><b>' + x.open_incidents + "</b> / " + x.incidents + "</a>" : '<span class="mut">0</span>') + "</td><td>" + (x.open_incidents ? riskPill({ risk: x.open_risk, risk_band: x.open_risk >= 75 ? "Critical" : x.open_risk >= 50 ? "High" : x.open_risk >= 25 ? "Medium" : "Low" }) : '<span class="mut">-</span>') + '</td><td style="text-align:end;white-space:nowrap">' +
        (canWrite() ? '<button class="btn sm" data-ea="' + x.id + '">' + t("Edit") + "</button> " : "") + (isAdmin() ? '<button class="btn sm dng" data-da="' + x.id + '">' + t("Delete") + "</button>" : "") + "</td></tr>";
    }).join("") : '<tr><td colspan="6"><div class="empty"><b>' + t("No assets match") + "</b>" + t("Register the systems you protect so incidents can be ranked by business impact.") + "</div></td></tr>") + "</tbody></table></div>";
    $$("[data-inc]").forEach(function (b) { b.onclick = function () { FILT = { q: b.dataset.inc, status: "", severity: "", category: "", assignee: "", mine: false }; }; });
    $$("[data-ea]").forEach(function (b) { b.onclick = function () { openAsset(all.filter(function (x) { return x.id === +b.dataset.ea; })[0]); }; });
    $$("[data-da]").forEach(function (b) { b.onclick = async function () { var x = all.filter(function (y) { return y.id === +b.dataset.da; })[0]; if (confirm(t("Delete asset {n}? Existing incidents keep the asset name.", { n: x.name }))) { await api("DELETE", "/api/assets/" + x.id); toast(t("Asset deleted")); META = await api("GET", "/api/meta"); render(true); } }; });
  };
  ["asq", "asc", "ast"].forEach(function (id) { $("#" + id).oninput = draw; }); draw();
}
function openAsset(x) {
  AID = x ? x.id : null; $("#aT").textContent = x ? t("Edit asset") : t("Add asset");
  $("#aType").innerHTML = META.asset_types.map(function (v) { return '<option value="' + esc(v) + '">' + esc(t(v)) + "</option>"; }).join("");
  $("#aCrit").innerHTML = META.criticality.map(function (v) { return '<option value="' + esc(v) + '">' + esc(t(v)) + "</option>"; }).join("");
  $("#aName").value = x ? x.name : ""; $("#aType").value = x ? x.type : "Server"; $("#aCrit").value = x ? x.criticality : "Medium";
  $("#aOwner").value = x ? x.owner : ""; $("#aDept").value = x ? x.department : ""; $("#aAddr").value = x ? x.address : ""; $("#aNotes").value = x ? x.notes : ""; $("#aErr").textContent = ""; $("#dAsset").showModal();
}
$("#fAsset").onsubmit = async function (e) {
  e.preventDefault();
  var body = { name: $("#aName").value, type: $("#aType").value, criticality: $("#aCrit").value, owner: $("#aOwner").value, department: $("#aDept").value, address: $("#aAddr").value, notes: $("#aNotes").value };
  try { await api("POST", AID ? "/api/assets/" + AID + "/update" : "/api/assets", body, true); $("#dAsset").close(); toast(t("Asset saved")); META = await api("GET", "/api/meta"); render(true); }
  catch (x) { $("#aErr").textContent = x.msg || t("Could not save"); }
};

/* ============ PERIOD REPORT ============ */
async function vReports(my) {
  var days = +(store.get("sd.rdays") || 30);
  var r = await api("GET", "/api/report/summary?days=" + days); if (my !== seq) return; var T = r.totals;
  head(t("Reports"), t("Management summary for a chosen period"), '<select id="rDays" style="width:auto" aria-label="' + t("Period") + '">' + [7, 14, 30, 90, 365].map(function (x) { return '<option value="' + x + '"' + (x === days ? " selected" : "") + ">" + t("Last {n} days", { n: x }) + "</option>"; }).join("") + '</select><button class="btn pri" id="rPrint">' + icon("report") + t("Print / Save as PDF") + "</button>");
  var st = function (n, l) { return "<div><b>" + n + "</b><small>" + l + "</small></div>"; };
  $("#view").innerHTML = '<article class="rpt"><div class="rh"><div><div class="mut sm">SentinelDesk · ' + t("Security Operations Report") + "</div><h1>" + t("Incident summary for the last {n} days", { n: r.days }) + '</h1></div><div class="mut sm" style="text-align:end">' + fdate(r.since) + " – " + fdate(r.until) + "</div></div>" +
    '<h2>1. ' + t("Key figures") + '</h2><div class="stats">' + st(T.reported, t("Reported")) + st(T.resolved, t("Resolved")) + st(T.closed, t("Closed")) + st(T.open_now, t("Open now")) + "</div>" +
    '<div class="stats" style="border-top:0">' + st(hrs(T.mtta_hours), t("Mean time to acknowledge")) + st(hrs(T.mttr_hours), t("Mean time to resolve")) + st(T.sla_met_pct == null ? "-" : T.sla_met_pct + "%", t("Resolved within target")) + st(T.breached_now, t("Past response target now")) + "</div>" +
    '<h2>2. ' + t("What was reported") + '</h2><div class="grid c-2" style="gap:28px"><div><div class="lbl">' + t("By severity") + "</div>" + hbars(r.by_severity, null, SEVCOL) + '</div><div><div class="lbl">' + t("By category") + "</div>" + hbars(r.by_category.slice(0, 6), "var(--accent)") + "</div></div>" +
    '<div class="grid c-2" style="gap:28px;margin-top:14px"><div><div class="lbl">' + t("By detection source") + "</div>" + hbars(r.by_source.slice(0, 6), "#5f7fb0") + '</div><div><div class="lbl">' + t("Most affected assets") + "</div>" + hbars(r.top_assets, "#5f7fb0") + "</div></div>" +
    "<h2>3. " + t("Risk and recurring assets") + '</h2><div class="grid c-2" style="gap:28px"><div><div class="lbl">' + t("Incidents by risk level") + "</div>" + hbars(r.risk.bands, null, SEVCOL) + '<p class="mut sm" style="margin:10px 0 0">' + (r.risk.avg == null ? t("None recorded.") : t("Average risk score") + ": <b>" + r.risk.avg + "/100</b>") + '</p></div><div><div class="lbl">' + t("Assets with repeated incidents") + "</div>" + (r.risk.repeat_assets.length ? hbars(r.risk.repeat_assets, "var(--high)") : '<p class="mut">' + t("None recorded.") + "</p>") + "</div></div>" +
    "<h2>4. " + t("Attack tactics seen (MITRE ATT&CK)") + "</h2>" + (r.by_mitre.length ? killChain(r.by_mitre) : '<p class="mut">' + t("None recorded.") + "</p>") +
    "<h2>5. " + t("Critical and high incidents in this period") + "</h2>" + (r.notable.length ? "<table><thead><tr><th>ID</th><th>" + t("Incident") + "</th><th>" + t("Severity") + "</th><th>" + t("Status") + "</th><th>" + t("Reported") + "</th></tr></thead><tbody>" + r.notable.map(function (i) { return '<tr><td class="idc"><a href="#/incidents/' + esc(i.id) + '">' + esc(i.id) + "</a></td><td>" + esc(i.title) + "</td><td>" + sevPill(i.severity) + "</td><td>" + esc(t(i.status)) + "</td><td>" + fshort(i.created_at) + "</td></tr>"; }).join("") + "</tbody></table>" : '<p class="mut">' + t("None recorded.") + "</p>") +
    "<h2>6. " + t("Team performance and SLA") + '</h2><div style="display:grid;gap:22px"><div><div class="lbl">' + t("SLA by severity (resolved in period)") + "</div><table><thead><tr><th>" + t("Severity") + "</th><th>" + t("Resolved") + "</th><th>" + t("Avg time to resolve") + "</th><th>" + t("Within target") + "</th></tr></thead><tbody>" + r.sla_by_severity.map(function (x) { return "<tr><td>" + sevPill(x.name) + "</td><td>" + x.resolved + "</td><td>" + (x.mttr_hours == null ? "-" : x.mttr_hours + " h") + "</td><td>" + (x.sla_met_pct == null ? "-" : x.sla_met_pct + "%") + "</td></tr>"; }).join("") + "</tbody></table></div><div><div class=\"lbl\">" + t("Workload and results by analyst") + "</div>" + (r.team.length ? "<table><thead><tr><th>" + t("Analyst") + "</th><th>" + t("Assigned") + "</th><th>" + t("Open") + "</th><th>" + t("Resolved") + "</th><th>" + t("Avg time to resolve") + "</th><th>" + t("Within target") + "</th></tr></thead><tbody>" + r.team.map(function (x) { return "<tr><td>" + esc(person(x.name) || x.name) + "</td><td>" + x.assigned + "</td><td>" + x.open + "</td><td>" + x.resolved + "</td><td>" + (x.mttr_hours == null ? "-" : x.mttr_hours + " h") + "</td><td>" + (x.sla_met_pct == null ? "-" : x.sla_met_pct + "%") + "</td></tr>"; }).join("") + "</tbody></table>" : '<p class="mut">' + t("None recorded.") + "</p>") + "</div></div>" +
    "<h2>7. " + t("Control mapping") + " (ISO/IEC 27001:2022 · NIST CSF 2.0)</h2>" + (r.framework.length ? '<p class="sm" style="margin-top:0"><b>' + t("Applies to every incident") + ':</b> <span class="mono">' + FW_BASE_ISO.join(", ") + " · " + FW_BASE_NIST.join(", ") + "</span><br>" + t("Additional controls by category:") + "</p><table><thead><tr><th>" + t("Category") + "</th><th>" + t("Incidents") + "</th><th>ISO/IEC 27001:2022 Annex A</th><th>NIST CSF 2.0</th></tr></thead><tbody>" + r.framework.map(function (f) { var sp = function (l, base) { var x = l.filter(function (y) { return base.indexOf(y.id) < 0; }).map(function (y) { return esc(y.id); }); return x.length ? x.join(", ") : "-"; }; return "<tr><td>" + esc(t(f.category)) + "</td><td>" + f.count + '</td><td class="mono sm">' + sp(f.iso, FW_BASE_ISO) + '</td><td class="mono sm">' + sp(f.nist, FW_BASE_NIST) + "</td></tr>"; }).join("") + '</tbody></table><p class="mut sm">' + t("Indicative mapping to support reporting; it is not a compliance assessment.") + "</p>" : '<p class="mut">' + t("None recorded.") + "</p>") +
    '<div class="sigs"><div>' + t("Prepared by") + ": " + esc(ME.full_name) + "<br>" + fdate(new Date().toISOString()) + "</div><div>" + t("Reviewed and approved by") + "</div></div></article>";
  $("#rDays").onchange = function () { store.set("sd.rdays", this.value); render(true); }; $("#rPrint").onclick = function () { window.print(); };
}

/* ============ USERS ============ */
async function vUsers(my) {
  var us = await api("GET", "/api/users"); if (my !== seq) return;
  head(t("Users"), t("{n} accounts", { n: us.length }), '<button class="btn pri" id="bAdd">' + icon("plus") + t("Add user") + "</button>");
  $("#bAdd").onclick = function () { ["uName", "uFull", "uMail", "uPw"].forEach(function (i) { $("#" + i).value = ""; }); $("#uErr").textContent = ""; $("#dUser").showModal(); };
  $("#view").innerHTML = '<div class="panel tw"><table><thead><tr><th>' + t("User") + "</th><th>" + t("Role") + "</th><th>" + t("Status") + "</th><th>" + t("Two-factor") + "</th><th>" + t("Last sign-in") + "</th><th></th></tr></thead><tbody>" + us.map(function (u) {
    var me = u.username === ME.username;
    return '<tr><td><b>' + esc(u.full_name) + '</b><div class="mut sm mono">' + esc(u.username) + (u.email ? " · " + esc(u.email) : "") + "</div></td><td>" + (me ? esc(roleName(u.role)) : '<select data-role="' + esc(u.username) + '" aria-label="' + t("Role") + " " + esc(u.username) + '" style="width:auto">' + ["admin", "analyst", "viewer"].map(function (r) { return '<option value="' + r + '"' + (r === u.role ? " selected" : "") + ">" + roleName(r) + "</option>"; }).join("") + "</select>") + "</td>" +
      "<td>" + (u.active ? '<span class="pill sev-Low">' + t("Active") + "</span>" : '<span class="tag">' + t("Disabled") + "</span>") + "</td><td>" + (u.mfa ? '<span class="pill sev-Low">' + t("On") + "</span>" + (me ? "" : ' <button class="btn ghost sm" data-mfa="' + esc(u.username) + '">' + t("Reset") + "</button>") : '<span class="mut sm">' + t("Off") + "</span>") + '</td><td class="mut sm">' + (u.last_login ? fdate(u.last_login) : t("Never")) + "</td>" +
      '<td style="text-align:end;white-space:nowrap"><button class="btn sm" data-pw="' + esc(u.username) + '">' + t("Reset password") + "</button> " + (me ? "" : '<button class="btn sm" data-so="' + esc(u.username) + '">' + t("Sign out everywhere") + "</button> ") + (me ? "" : '<button class="btn sm ' + (u.active ? "dng" : "") + '" data-tg="' + esc(u.username) + '">' + (u.active ? t("Disable") : t("Enable")) + "</button>") + "</td></tr>";
  }).join("") + "</tbody></table></div>";
  $$("[data-role]").forEach(function (s) { s.onchange = async function () { await api("POST", "/api/users/" + s.dataset.role + "/role", { role: s.value }); toast(t("Role updated")); render(true); }; });
  $$("[data-tg]").forEach(function (b) { b.onclick = async function () { await api("POST", "/api/users/" + b.dataset.tg + "/toggle"); toast(t("Account updated")); render(true); }; });
  $$("[data-so]").forEach(function (b) { b.onclick = async function () { if (confirm(t("Sign {u} out of every device?", { u: b.dataset.so }))) { await api("POST", "/api/users/" + b.dataset.so + "/signout"); toast(t("User signed out")); } }; });
  $$("[data-pw]").forEach(function (b) { b.onclick = function () { openPw(b.dataset.pw); }; });
  $$("[data-mfa]").forEach(function (b) { b.onclick = async function () { if (confirm(t("Reset two-factor authentication for {u}? They will sign in with a password only until they set it up again.", { u: b.dataset.mfa }))) { await api("POST", "/api/users/" + b.dataset.mfa + "/mfa_reset"); toast(t("Two-factor reset")); render(true); } }; });
}
$("#fUser").onsubmit = async function (e) {
  e.preventDefault();
  try { await api("POST", "/api/users", { username: $("#uName").value, full_name: $("#uFull").value, email: $("#uMail").value, role: $("#uRole").value, password: $("#uPw").value }, true); $("#dUser").close(); toast(t("User added")); META = await api("GET", "/api/meta"); render(true); }
  catch (x) { $("#uErr").textContent = x.msg || t("Could not add user"); }
};
var PWT = null;
function openPw(target) { PWT = target || null; $("#pwT").textContent = target ? t("Reset password for {u}", { u: target }) : t("Change password"); $("#pwCurW").hidden = !!target; $("#pwCur").required = !target; ["pwCur", "pwNew"].forEach(function (i) { $("#" + i).value = ""; }); $("#pwErr").textContent = ""; $("#dPw").showModal(); }
$("#fPw").onsubmit = async function (e) {
  e.preventDefault();
  try { if (PWT) await api("POST", "/api/users/" + PWT + "/password", { password: $("#pwNew").value }, true); else await api("POST", "/api/password", { current: $("#pwCur").value, new: $("#pwNew").value }, true); $("#dPw").close(); toast(t("Password saved")); if (!PWT) { showLogin(); } }
  catch (x) { $("#pwErr").textContent = x.msg || t("Could not save"); }
};

/* ============ AUDIT ============ */
async function vAudit(my) {
  var a = await api("GET", "/api/audit"); if (my !== seq) return;
  head(t("Audit log"), t("Latest {n} recorded actions", { n: a.length }), '<button class="btn" id="bVerify">' + icon("pulse") + t("Verify integrity") + '</button><a class="btn" href="/api/audit.csv">' + icon("download") + t("Export CSV") + "</a>");
  $("#view").innerHTML = '<div id="vOut" aria-live="polite"></div><div class="tools"><input type="search" id="aq" placeholder="' + esc(t("Filter by user, action or detail")) + '" aria-label="' + t("Filter audit log") + '"></div><div class="panel tw"><table><thead><tr><th>' + t("Time") + "</th><th>" + t("User") + "</th><th>" + t("Action") + "</th><th>" + t("Detail") + '</th></tr></thead><tbody id="ab"></tbody></table></div>';
  var draw = function () { var q = $("#aq").value.toLowerCase(); var l = a.filter(function (r) { return !q || (r.username + " " + r.action + " " + (r.detail || "")).toLowerCase().indexOf(q) > -1; });
    $("#ab").innerHTML = l.length ? l.map(function (r) { return '<tr><td class="mut sm" style="white-space:nowrap">' + fdate(r.at) + "</td><td>" + esc(r.username) + '</td><td class="mono sm">' + esc(r.action) + '</td><td class="sm" style="overflow-wrap:anywhere">' + esc(r.detail || "") + "</td></tr>"; }).join("") : '<tr><td colspan="4"><div class="empty">' + t("Nothing matches that filter.") + "</div></td></tr>"; };
  $("#aq").oninput = draw; draw();
  $("#bVerify").onclick = async function () {
    var r = await api("GET", "/api/audit/verify");
    $("#vOut").innerHTML = r.ok ? '<div class="note ok">' + icon("pulse") + " " + t("Audit chain intact: {n} entries verified. No entry was changed or removed.", { n: r.checked }) + "</div>"
      : '<div class="note bad">' + icon("pulse") + " <b>" + t("Tampering detected at entry #{id}", { id: r.bad_id }) + "</b> - " + esc(t(r.reason)) + "</div>";
  };
}

/* ============ ACCOUNT + TWO-FACTOR ============ */
async function vAccount(my) {
  var me = await api("GET", "/api/me"); ME = me; if (my !== seq) return;
  head(t("Account"), t("Your profile and sign-in security"), "");
  $("#view").innerHTML = '<div class="grid c-2" style="max-width:980px"><div class="panel"><h3>' + t("Profile") + '</h3><div class="body"><dl class="facts"><div><dt>' + t("Name") + "</dt><dd>" + esc(me.full_name) + "</dd></div><div><dt>" + t("Username") + '</dt><dd class="mono">' + esc(me.username) + "</dd></div><div><dt>" + t("Role") + "</dt><dd>" + esc(roleName(me.role)) + "</dd></div></dl>" +
    '<div style="margin-top:18px;display:flex;gap:8px;flex-wrap:wrap"><button class="btn" id="bPw">' + t("Change password") + '</button><button class="btn langBtn2" id="bLang">' + icon("globe", "sm") + (LANG === "ar" ? "English" : "العربية") + '</button><button class="btn" id="bTheme">' + icon(THEME === "dark" ? "sun" : "moon", "sm") + t(THEME === "dark" ? "Light theme" : "Dark theme") + "</button></div>" +
    (me.default_password ? '<div class="note warn" style="margin-top:14px">' + t("You are still using a default password. Change it before sharing this system.") + "</div>" : "") + "</div></div>" +
    '<div class="panel"><h3>' + t("Two-factor authentication") + '</h3><div class="body" id="mfaBox"></div></div><div class="panel" style="grid-column:1/-1"><h3>' + t("Active sessions") + '</h3><div class="body" id="sesBox"></div></div><div class="panel" style="grid-column:1/-1"><h3>' + t("API tokens") + '</h3><div class="body" id="tokBox"></div></div></div>';
  loadSessions(); loadTokens();
  $("#bPw").onclick = function () { openPw(null); }; $("#bLang").onclick = function () { setLang(LANG === "ar" ? "en" : "ar"); }; $("#bTheme").onclick = function () { setTheme(THEME === "dark" ? "light" : "dark"); render(true); };
  var box = $("#mfaBox");
  var showOn = function () {
    box.innerHTML = '<p><span class="pill sev-Low">' + t("On") + "</span></p><p class=\"mut\">" + t("Sign-in requires your password and a 6-digit code from your authenticator app.") + '</p><div class="fld"><label for="mP">' + t("Password") + '</label><input id="mP" type="password" autocomplete="current-password"></div><div class="fld"><label for="mC">' + t("Current code") + '</label><input id="mC" inputmode="numeric" maxlength="8" style="direction:ltr"></div><p class="err" id="mE"></p><button class="btn dng" id="mOff">' + t("Turn off two-factor") + "</button>";
    $("#mOff").onclick = async function () { try { await api("POST", "/api/2fa/disable", { password: $("#mP").value, code: $("#mC").value }, true); toast(t("Two-factor turned off")); render(true); } catch (x) { $("#mE").textContent = x.msg; } };
  };
  var showOff = function () {
    box.innerHTML = '<p class="mut">' + t("Add a second step to sign-in. You will need an authenticator app such as Microsoft Authenticator, Google Authenticator or Authy.") + '</p><button class="btn pri" id="mOn">' + icon("shield", "sm") + t("Set up two-factor") + "</button>";
    $("#mOn").onclick = async function () {
      var s = await api("POST", "/api/2fa/setup", {});
      var qr = ""; try { qr = QR.svg("otpauth://totp/SentinelDesk:" + encodeURIComponent(me.username) + "?secret=" + s.secret + "&issuer=SentinelDesk", 200); } catch (x) { qr = ""; }
      box.innerHTML = '<ol class="mut" style="padding-inline-start:18px;margin:0 0 12px"><li>' + t("Open your authenticator app and scan this QR code.") + "</li><li>" + t("Cannot scan? Choose “Enter a setup key” and type this key (spaces do not matter):") + "</li></ol>" + (qr ? '<div class="qrbox" aria-label="' + esc(t("QR code")) + '">' + qr + "</div>" : "") + '<div class="secret" id="sk">' + esc(s.secret.replace(/(.{4})/g, "$1 ").trim()) + '</div><p style="margin:8px 0"><button class="btn sm" id="mCp">' + icon("copy", "sm") + t("Copy key") + '</button></p><div class="fld"><label for="mC">' + t("Then enter the 6-digit code it shows") + '</label><input id="mC" inputmode="numeric" maxlength="8" style="direction:ltr" autocomplete="one-time-code"></div><p class="err" id="mE"></p><button class="btn pri" id="mGo">' + t("Turn on two-factor") + "</button>";
      $("#mCp").onclick = function () { copyText(s.secret); };
      $("#mGo").onclick = async function () { try { await api("POST", "/api/2fa/enable", { code: $("#mC").value }, true); toast(t("Two-factor turned on")); render(true); } catch (x) { $("#mE").textContent = x.msg; } };
    };
  };
  me.mfa ? showOn() : showOff();
}

async function loadTokens() {
  var box = $("#tokBox"); if (!box) return;
  var rows = await api("GET", "/api/tokens");
  box = $("#tokBox"); if (!box) return;                 // the user may have left the page while loading
  box.innerHTML = '<p class="mut sm" style="margin-top:0">' + t("Tokens let scripts and tools call the API as you. See the API page for examples.") + '</p><div class="tw"><table><thead><tr><th>' + t("Name") + "</th><th>" + t("Token") + "</th><th>" + t("Access") + "</th><th>" + t("Expires") + "</th><th>" + t("Last used") + "</th><th></th></tr></thead><tbody>" + (rows.length ? rows.map(function (r) {
    var dead = r.revoked || r.expired;
    return "<tr" + (dead ? ' style="opacity:.55"' : "") + "><td><b>" + esc(r.name) + '</b></td><td class="mono" dir="ltr">' + esc(r.prefix) + "…</td><td>" + t(r.scope === "write" ? "Read and write" : "Read only") + "</td><td class=\"mut sm\">" + (r.revoked ? t("Revoked") : r.expired ? t("Expired") : fdate(r.expires_at)) + '</td><td class="mut sm">' + (r.last_used ? ago(r.last_used) : t("Never")) + '</td><td style="text-align:end">' + (dead ? "" : '<button class="btn sm dng" data-rt="' + r.id + '">' + t("Revoke") + "</button>") + "</td></tr>";
  }).join("") : '<tr><td colspan="6"><div class="empty">' + t("No API tokens yet.") + "</div></td></tr>") + "</tbody></table></div>" + '<p style="margin:12px 0 0"><button class="btn pri" id="tokNew">' + icon("plus") + t("Create API token") + "</button></p>";
  $("#tokNew").onclick = function () { $("#tName").value = ""; $("#tScope").value = "read"; $("#tScope").querySelector('[value="write"]').disabled = !canWrite(); $("#tErr").textContent = ""; $("#dToken").showModal(); };
  $$("[data-rt]").forEach(function (b) { b.onclick = async function () { if (confirm(t("Revoke this token? Anything using it stops working immediately."))) { await api("POST", "/api/tokens/" + b.dataset.rt + "/revoke", {}); toast(t("Token revoked")); loadTokens(); } }; });
}
$("#fToken").onsubmit = async function (e) {
  e.preventDefault();
  try {
    var r = await api("POST", "/api/tokens", { name: $("#tName").value, scope: $("#tScope").value, days: +$("#tDays").value }, true);
    $("#dToken").close(); $("#tokVal").textContent = r.token; $("#dTokenShow").showModal(); loadTokens();
  } catch (x) { $("#tErr").textContent = x.msg || t("Could not save"); }
};
$("#tokCopy").onclick = function () {
  var v = $("#tokVal").textContent;
  (navigator.clipboard ? navigator.clipboard.writeText(v) : Promise.reject()).then(function () { toast(t("Copied")); }).catch(function () { var r = document.createRange(); r.selectNodeContents($("#tokVal")); var s = getSelection(); s.removeAllRanges(); s.addRange(r); toast(t("Press Ctrl+C to copy")); });
};
function uaName(ua) {
  var b = /Edg\//.test(ua) ? "Edge" : /OPR\//.test(ua) ? "Opera" : /Firefox\//.test(ua) ? "Firefox" : /Chrome\//.test(ua) ? "Chrome" : /Safari\//.test(ua) ? "Safari" : t("Browser");
  var o = /Windows/.test(ua) ? "Windows" : /Android/.test(ua) ? "Android" : /iPhone|iPad/.test(ua) ? "iOS" : /Mac OS X/.test(ua) ? "macOS" : /Linux/.test(ua) ? "Linux" : "";
  return b + (o ? " · " + o : "");
}
async function loadSessions() {
  var box = $("#sesBox"); if (!box) return;
  var rows = await api("GET", "/api/sessions");
  box = $("#sesBox"); if (!box) return;
  box.innerHTML = '<div class="tw"><table><thead><tr><th>' + t("Device") + "</th><th>" + t("IP address") + "</th><th>" + t("Signed in") + "</th><th>" + t("Last active") + "</th><th></th></tr></thead><tbody>" + rows.map(function (r) {
    return "<tr><td><b>" + esc(uaName(r.ua)) + "</b>" + (r.current ? ' <span class="pill sev-Low">' + t("This device") + "</span>" : "") + '</td><td class="mono" dir="ltr">' + esc(r.ip) + "</td><td class=\"mut sm\">" + fdate(r.created) + '</td><td class="mut sm">' + ago(r.last) + '</td><td style="text-align:end">' + (r.current ? "" : '<button class="btn sm dng" data-rs="' + esc(r.id) + '">' + t("Sign out") + "</button>") + "</td></tr>";
  }).join("") + "</tbody></table></div>" + (rows.length > 1 ? '<p style="margin:12px 0 0"><button class="btn" id="rsAll">' + t("Sign out all other sessions") + "</button></p>" : "");
  $$("[data-rs]").forEach(function (b) { b.onclick = async function () { await api("POST", "/api/sessions/revoke", { id: b.dataset.rs }); toast(t("Session ended")); loadSessions(); }; });
  if ($("#rsAll")) $("#rsAll").onclick = async function () { await api("POST", "/api/sessions/revoke_others", {}); toast(t("Other sessions ended")); loadSessions(); };
}

/* ============ DATABASE MANAGER ============ */
var DB = { tab: "data", table: "incidents", page: 1, q: "", sort: "", dir: "desc", meta: null };
var LONG = { description: 1, text: 1, resolution: 1, detail: 1, root_cause: 1, lessons: 1, note: 1 };
function isDate(n) { return /(_at|^at)$/.test(n); }
function cellVal(n, v) { if (v === null || v === undefined || v === "") return '<span class="nul">–</span>'; var s = isDate(n) ? fdate(v) : String(v); return '<div class="cell" title="' + esc(String(v)) + '">' + esc(s) + "</div>"; }
function toLocalInput(s) { if (!s) return ""; var d = new Date(s), p = function (x) { return String(x).padStart(2, "0"); }; return d.getFullYear() + "-" + p(d.getMonth() + 1) + "-" + p(d.getDate()) + "T" + p(d.getHours()) + ":" + p(d.getMinutes()); }
async function vDb(my) {
  head(t("Database"), t("Browse, add, edit, query and back up every table"), "");
  $("#view").innerHTML = '<div class="tabs" role="tablist">' + [["data", t("Tables")], ["sql", t("SQL console")], ["bk", t("Backups")]].map(function (x) { return '<button role="tab" data-t="' + x[0] + '" class="' + (DB.tab === x[0] ? "on" : "") + '">' + x[1] + "</button>"; }).join("") + '</div><div id="dbBody"></div>';
  $$(".tabs button").forEach(function (b) { b.onclick = function () { DB.tab = b.dataset.t; vDb(++seq); }; });
  if (DB.tab === "data") await dbData(my); else if (DB.tab === "sql") dbSql(); else await dbBackups(my);
}
async function dbData(my) {
  var m = await api("GET", "/api/db/tables"); if (my !== seq) return; DB.meta = m;
  var tb = m.tables.filter(function (x) { return x.name === DB.table; })[0] || m.tables[0]; DB.table = tb.name;
  var r = await api("GET", "/api/db/rows?table=" + encodeURIComponent(tb.name) + "&page=" + DB.page + "&q=" + encodeURIComponent(DB.q) + "&sort=" + encodeURIComponent(DB.sort) + "&dir=" + DB.dir); if (my !== seq) return;
  var cols = tb.columns, sortCol = DB.sort || tb.pk, pages = Math.max(1, Math.ceil(r.total / r.page_size));
  var list = '<div class="panel tlist">' + m.tables.map(function (x) { return '<button data-tb="' + x.name + '" class="' + (x.name === tb.name ? "on" : "") + '"><span>' + x.name + (x.readonly ? " 🔒" : "") + '</span><span class="cnt">' + x.rows + "</span></button>"; }).join("") + "</div>";
  var hd = "<tr>" + cols.map(function (c) { return '<th class="s" data-c="' + c.name + '">' + esc(c.name) + (c.name === sortCol ? (DB.dir === "asc" ? " ▲" : " ▼") : "") + "</th>"; }).join("") + (tb.readonly ? "" : "<th></th>") + "</tr>";
  var body = r.rows.length ? r.rows.map(function (row) { return "<tr>" + cols.map(function (c) { return "<td>" + cellVal(c.name, row[c.name]) + "</td>"; }).join("") + (tb.readonly ? "" : '<td style="text-align:end"><button class="btn sm" data-ed="' + esc(row[tb.pk]) + '">' + t("Edit") + "</button> " + (tb.no_delete ? "" : '<button class="btn sm dng" data-del="' + esc(row[tb.pk]) + '">' + t("Delete") + "</button>") + "</td>") + "</tr>"; }).join("") : '<tr><td colspan="' + (cols.length + 1) + '"><div class="empty"><b>' + t("No rows") + "</b>" + (DB.q ? t("Nothing matches your search.") : t("This table is empty.")) + "</div></td></tr>";
  var from = r.total ? (r.page - 1) * r.page_size + 1 : 0, to = Math.min(r.total, r.page * r.page_size);
  $("#dbBody").innerHTML = '<div class="dbwrap">' + list + '<div><div class="tools"><input type="search" id="dq" placeholder="' + esc(t("Search every column in {t}", { t: tb.name })) + '" aria-label="' + t("Search table") + '" value="' + esc(DB.q) + '">' + (tb.no_insert ? "" : '<button class="btn pri" id="dAdd">' + icon("plus") + t("Add row") + "</button>") + '<a class="btn" href="/api/db/export?table=' + encodeURIComponent(tb.name) + '">' + icon("download") + t("Export CSV") + "</a></div>" +
    (tb.readonly ? '<div class="note" style="margin-bottom:12px">' + t("This table is read-only so the history can never be altered here. Evidence, indicators and checklists are managed from each incident.") + "</div>" : "") +
    '<div class="panel"><div class="tw"><table class="dbt"><thead>' + hd + "</thead><tbody>" + body + '</tbody></table></div><div class="pager"><span class="mut">' + t("Showing {a}–{b} of {n} rows · {c} columns", { a: from, b: to, n: r.total, c: cols.length }) + '</span><span><button class="btn sm" id="dPrev"' + (r.page <= 1 ? " disabled" : "") + ">" + t("Previous") + '</button> <span class="mut" style="margin:0 8px">' + t("Page {p} of {n}", { p: r.page, n: pages }) + '</span><button class="btn sm" id="dNext"' + (r.page >= pages ? " disabled" : "") + ">" + t("Next") + "</button></span></div></div></div></div>";
  $$("[data-tb]").forEach(function (b) { b.onclick = function () { DB.table = b.dataset.tb; DB.page = 1; DB.q = ""; DB.sort = ""; DB.dir = "desc"; vDb(++seq); }; });
  var qt; $("#dq").oninput = function () { clearTimeout(qt); var v = this.value; qt = setTimeout(function () { DB.q = v; DB.page = 1; dbData(++seq).then(function () { var e = $("#dq"); if (e) { e.focus(); e.setSelectionRange(v.length, v.length); } }); }, 350); };
  $$("th.s").forEach(function (th) { th.onclick = function () { var c = th.dataset.c; if (sortCol === c) DB.dir = DB.dir === "asc" ? "desc" : "asc"; else { DB.sort = c; DB.dir = "asc"; } DB.page = 1; dbData(++seq); }; });
  $("#dPrev").onclick = function () { DB.page--; dbData(++seq); }; $("#dNext").onclick = function () { DB.page++; dbData(++seq); };
  if ($("#dAdd")) $("#dAdd").onclick = function () { openRow(tb, null); };
  $$("[data-ed]").forEach(function (b) { b.onclick = function () { openRow(tb, r.rows.filter(function (x) { return String(x[tb.pk]) === b.dataset.ed; })[0]); }; });
  $$("[data-del]").forEach(function (b) { b.onclick = async function () { var extra = tb.name === "incidents" ? " " + t("Its timeline, indicators, checklist and evidence will be deleted too.") : tb.name === "users" ? " " + t("This account will no longer be able to sign in.") : ""; if (!confirm(t("Delete this row from {t} permanently?", { t: tb.name }) + extra)) return; try { await api("POST", "/api/db/row", { table: tb.name, op: "delete", pk: b.dataset.del }); toast(t("Row deleted")); dbData(++seq); } catch (e) {} }; });
}
function openRow(tb, row) {
  var ch = DB.meta.choices, f = "", isNew = !row;
  tb.columns.forEach(function (c) {
    if (isNew && c.pk && c.type.indexOf("INT") === 0) return;
    var key = tb.name + "." + c.name, opts = ch[key], val = row ? row[c.name] : "", dis = (row && c.pk) || (row && tb.name === "users" && c.name === "username") || (row && tb.name === "lookups" && c.name === "kind"), ctl;
    if (opts) ctl = '<select data-c="' + c.name + '"' + (dis ? " disabled" : "") + ">" + ((isNew || !c.notnull) ? '<option value="">' + (isNew ? t("(automatic / blank)") : t("(none)")) + "</option>" : "") + opts.map(function (o) { return '<option value="' + esc(o) + '"' + (String(val) === String(o) ? " selected" : "") + ">" + esc(o === "" ? t("(none)") : o) + "</option>"; }).join("") + "</select>";
    else if (isDate(c.name)) ctl = '<input type="datetime-local" data-c="' + c.name + '" data-date="1" value="' + esc(toLocalInput(val)) + '"' + (dis ? " disabled" : "") + ">";
    else if (LONG[c.name]) ctl = '<textarea data-c="' + c.name + '">' + esc(val == null ? "" : val) + "</textarea>";
    else ctl = '<input data-c="' + c.name + '" type="' + (c.type.indexOf("INT") === 0 ? "number" : "text") + '" value="' + esc(val == null ? "" : val) + '"' + (dis ? " disabled" : "") + ">";
    f += '<div class="fld"' + (LONG[c.name] ? ' style="grid-column:1/-1"' : "") + "><label>" + esc(c.name) + (c.notnull && !c.pk ? ' <span class="mut" style="font-weight:400">· ' + t("required") + "</span>" : "") + "</label>" + ctl + "</div>";
  });
  if (tb.name === "users") f += '<div class="fld"><label>password <span class="mut" style="font-weight:400">' + (isNew ? t("required") : t("leave blank to keep the current one")) + '</span></label><input type="password" data-c="password" autocomplete="new-password"></div>';
  var hint = isNew && tb.name === "incidents" ? '<div class="note" style="margin-bottom:14px">' + t("Leave ID, dates, status and due time blank to fill them in automatically.") + "</div>" : isNew && tb.name === "events" ? '<div class="note" style="margin-bottom:14px">' + t("Use the incident ID exactly as shown in the incidents table, for example INC-2026-0001.") + "</div>" : "";
  $("#rowT").textContent = (isNew ? t("Add row to {t}", { t: tb.name }) : t("Edit row in {t}", { t: tb.name })); $("#rowF").innerHTML = hint + '<div class="g2">' + f + "</div>"; $("#rowE").textContent = "";
  $("#fRow").onsubmit = async function (e) {
    e.preventDefault(); var v = {};
    $$("#rowF [data-c]").forEach(function (el) { if (el.disabled) return; var x = el.value; if (el.dataset.date && x) x = new Date(x).toISOString(); v[el.dataset.c] = x; });
    try { await api("POST", "/api/db/row", { table: tb.name, op: isNew ? "insert" : "update", pk: row ? row[tb.pk] : undefined, values: v }, true); $("#dRow").close(); toast(isNew ? t("Row added") : t("Row saved")); META = await api("GET", "/api/meta"); dbData(++seq); }
    catch (x) { $("#rowE").textContent = x.msg || t("Could not save"); }
  };
  $("#dRow").showModal();
}
var SAMPLES = [["Open incidents by severity", "SELECT severity, COUNT(*) AS open_incidents\nFROM incidents\nWHERE status IN ('New','Investigating','Contained')\nGROUP BY severity\nORDER BY open_incidents DESC"],
  ["Incidents per category", "SELECT category, COUNT(*) AS total\nFROM incidents\nGROUP BY category\nORDER BY total DESC"],
  ["Average hours to resolve", "SELECT category,\n       ROUND(AVG((julianday(resolved_at) - julianday(created_at)) * 24), 1) AS avg_hours,\n       COUNT(*) AS resolved\nFROM incidents\nWHERE resolved_at IS NOT NULL\nGROUP BY category"],
  ["Indicators seen in several incidents", "SELECT type, value, COUNT(DISTINCT incident_id) AS incidents\nFROM iocs\nGROUP BY type, value\nHAVING incidents > 1\nORDER BY incidents DESC"],
  ["Open workload per person", "SELECT assignee, COUNT(*) AS open_items\nFROM incidents\nWHERE status != 'Closed'\nGROUP BY assignee\nORDER BY open_items DESC"],
  ["Evidence with hashes", "SELECT incident_id, filename, size, sha256, uploaded_by\nFROM evidence\nORDER BY id DESC"]];
function dbSql() {
  $("#dbBody").innerHTML = '<div class="panel"><div class="body"><p class="mut" style="margin:0 0 4px">' + t("Run read-only SELECT queries against the live database. Nothing you run here can change data, and password hashes and 2FA secrets are never readable.") + "</p>" +
    '<div class="chips" style="margin:10px 0 14px">' + SAMPLES.map(function (x, i) { return '<button class="chip" data-s="' + i + '">' + t(x[0]) + "</button>"; }).join("") + "</div>" +
    '<textarea id="sql" class="sqlbox" spellcheck="false" aria-label="SQL">' + esc(SAMPLES[0][1]) + '</textarea><div style="margin:10px 0 0;display:flex;gap:10px;align-items:center"><button class="btn pri" id="sqlRun">' + t("Run query") + '</button><span class="mut sm">' + t("Ctrl + Enter also runs it") + '</span></div></div></div><div id="sqlOut" style="margin-top:16px"></div>';
  var run = async function () {
    var out = $("#sqlOut");
    try { var r = await api("POST", "/api/db/query", { sql: $("#sql").value }, true); out.innerHTML = '<div class="panel"><div class="tw"><table class="dbt"><thead><tr>' + r.columns.map(function (c) { return "<th>" + esc(c) + "</th>"; }).join("") + "</tr></thead><tbody>" + (r.rows.length ? r.rows.map(function (row) { return "<tr>" + row.map(function (v) { return "<td>" + cellVal("", v) + "</td>"; }).join("") + "</tr>"; }).join("") : '<tr><td colspan="' + Math.max(1, r.columns.length) + '"><div class="empty">' + t("The query returned no rows.") + "</div></td></tr>") + '</tbody></table></div><div class="pager"><span class="mut">' + t("{n} row(s)", { n: r.rows.length }) + (r.truncated ? " " + t("(first 500 shown)") : "") + " · " + r.ms + " ms</span></div></div>"; }
    catch (x) { out.innerHTML = '<div class="note bad">' + esc(x.msg || t("Query failed")) + "</div>"; }
  };
  $$("[data-s]").forEach(function (b) { b.onclick = function () { $("#sql").value = SAMPLES[+b.dataset.s][1]; run(); }; });
  $("#sqlRun").onclick = run; $("#sql").onkeydown = function (e) { if ((e.ctrlKey || e.metaKey) && e.key === "Enter") run(); }; run();
}
async function dbBackups(my) {
  var b = await api("GET", "/api/db/backups"); if (my !== seq) return;
  $("#dbBody").innerHTML = '<div class="grid c-32"><div class="panel"><h3 style="padding-bottom:6px">' + t("Backups") + "</h3>" + (b.backups.length ? '<div class="tw"><table class="dbt"><thead><tr><th>' + t("File") + "</th><th>" + t("Created") + "</th><th>" + t("Size") + "</th><th></th></tr></thead><tbody>" + b.backups.map(function (x) { return '<tr><td class="mono">' + esc(x.name) + "</td><td>" + fdate(x.at) + "</td><td>" + kb(x.size) + '</td><td style="text-align:end;white-space:nowrap"><a class="btn sm" href="/api/db/backups/' + encodeURIComponent(x.name) + '">' + t("Download") + '</a> <button class="btn sm dng" data-restore="' + esc(x.name) + '">' + t("Restore") + "</button></td></tr>"; }).join("") + "</tbody></table></div>" : '<div class="empty"><b>' + t("No backups yet") + "</b>" + t("Create the first one.") + "</div>") + "</div>" +
    '<div class="panel"><h3>' + t("Your database") + '</h3><div class="body"><dl class="facts"><div><dt>' + t("File") + '</dt><dd class="mono">' + esc(b.database) + "</dd></div><div><dt>" + t("Engine") + "</dt><dd>SQLite</dd></div><div><dt>" + t("Size") + "</dt><dd>" + kb(b.size) + "</dd></div><div><dt>" + t("Backup folder") + '</dt><dd class="mono sm" style="overflow-wrap:anywhere;direction:ltr">' + esc(b.folder) + "</dd></div></dl>" +
    '<button class="btn pri" id="bkNow" style="margin-top:16px;width:100%">' + t("Create backup now") + '</button><p class="mut sm" style="margin:12px 0 0">' + t("A backup is also taken every time the server starts (the last 10 are kept). To restore: stop the server, replace incidents.db with a backup file renamed to that name, then start again. Evidence files are stored separately in the evidence folder and should be copied with it.") + "</p></div></div></div>";
  $("#bkNow").onclick = async function () { await api("POST", "/api/db/backups"); toast(t("Backup created")); vDb(++seq); };
  $$("[data-restore]").forEach(function (b) { b.onclick = async function () {
    var n = b.dataset.restore, a = prompt(t("Restoring replaces ALL current data with this backup. A safety copy of the current database is taken first. Type the backup file name to confirm:") + "\n\n" + n);
    if (a === null) return;
    try { await api("POST", "/api/db/backups/" + encodeURIComponent(n) + "/restore", { confirm: a.trim() }); toast(t("Database restored. Reloading...")); setTimeout(function () { location.reload(); }, 900); } catch (e) {}
  }; });
}

/* ============ SETTINGS ============ */
async function vSettings(my) {
  var d = await api("GET", "/api/settings"), nd = await api("GET", "/api/settings/notifications"); if (my !== seq) return;
  head(t("Settings"), t("Response targets, notification channels, integrations and the lists used across the system"), "");
  var sl = '<div class="panel"><h3>' + t("Response targets") + '</h3><div class="body"><p class="mut" style="margin:0 0 14px">' + t("Hours allowed to resolve an incident, by severity.") + '</p><div class="slag">' + META.severities.slice().reverse().map(function (sv) { return '<div><label for="sla' + sv + '">' + t(sv) + '</label><input id="sla' + sv + '" type="number" min="1" max="720" value="' + d.sla[sv] + '"></div>'; }).join("") + "</div>" +
    '<label class="chk" style="margin-bottom:6px"><input type="checkbox" id="slaApply"> ' + t("Also recalculate the due time of incidents that are still open") + '</label><p class="err" id="slaE"></p><button class="btn pri" id="slaSave">' + t("Save response targets") + "</button></div></div>";
  var lists = Object.keys(d.lists).map(function (kind) {
    var titles = { category: [t("Incident types"), "e.g. Ransomware"], source: [t("Detection sources"), "e.g. Antivirus alert"], action_type: [t("Action types"), "e.g. Forensics"] }[kind];
    return '<div class="panel"><h3>' + titles[0] + '</h3><div class="body">' + d.lists[kind].map(function (x) { return '<div class="lrow"><input type="text" data-ren="' + x.id + '" data-old="' + esc(x.name) + '" value="' + esc(x.name) + '" maxlength="60" aria-label="' + t("Name") + '"><label class="chk"><input type="checkbox" data-act="' + x.id + '"' + (x.active ? " checked" : "") + "> " + t("Active") + '</label><button class="btn sm dng" data-ldel="' + x.id + '"' + (x.usage ? ' disabled title="' + esc(t("Used by {n} record(s). Disable it instead.", { n: x.usage })) + '"' : "") + ">" + t("Delete") + "</button></div>"; }).join("") +
      '<div class="addrow"><input type="text" data-new="' + kind + '" placeholder="' + esc(titles[1]) + '" maxlength="60" aria-label="' + t("New name") + '"><button class="btn pri" data-add="' + kind + '">' + t("Add") + "</button></div></div></div>";
  }).join("");
  var cn = { email: "Email (SMTP)", telegram: "Telegram", slack: "Slack", discord: "Discord" };
  var rows = Object.keys(cn).map(function (k) { return '<div class="lrow" style="grid-template-columns:1fr auto"><span>' + cn[k] + '</span><span class="pill" style="color:var(' + (nd.channels[k] ? "--low" : "--faint") + ')">' + (nd.channels[k] ? t("Configured") : t("Not configured")) + "</span></div>"; }).join("");
  var nt = '<div class="panel"><h3>' + t("Automatic notifications") + '</h3><div class="body"><p class="mut">' + t("When configured, SentinelDesk sends a notification for each new incident and once when an open incident breaches its response target. Credentials are read from environment variables and are never displayed here.") + "</p>" + rows + '<p class="mut" style="margin-top:12px">' + t("Recipients") + ": " + esc(nd.email_recipients.join(", ") || t("Not configured")) + " · " + t("SLA check interval: {n} seconds", { n: nd.sla_check_seconds }) + '</p><button class="btn pri" id="notifyTest">' + t("Send test notification") + '</button><p class="err" id="notifyResult" aria-live="polite"></p></div></div>';
  var hook = location.origin + "/api/integrations/webhook";
  var ig = '<div class="panel"><h3>' + t("SIEM / EDR integration") + '</h3><div class="body"><p><span class="pill" style="color:var(' + (nd.webhook_configured ? "--low" : "--faint") + ')">' + (nd.webhook_configured ? t("Token configured") : t("Not configured")) + "</span></p><p class=\"mut\">" + t("Security tools can open incidents automatically by sending alerts to this address. Set SENTINEL_WEBHOOK_TOKEN on the server to enable it. Repeated alerts with the same provider and external_id are merged.") + '</p><pre class="code">POST ' + esc(hook) + "\nAuthorization: Bearer &lt;SENTINEL_WEBHOOK_TOKEN&gt;\nContent-Type: application/json\n\n" + esc(JSON.stringify({ provider: "ExampleSIEM", external_id: "alert-0001", title: "Suspicious PowerShell", description: "Encoded command on DC-01", severity: "critical", category: "Malware", asset: "DC-01", tlp: "AMBER", mitre: ["Execution"], iocs: ["update-cdn-sync[.]net"] }, null, 2)) + "</pre></div></div>";
  $("#view").innerHTML = '<div class="grid" style="max-width:1000px">' + sl + nt + ig + '<div class="note">' + t("Renaming an item updates every incident that uses it. Disabled items disappear from the forms but old incidents keep them. Items that are in use cannot be deleted.") + '</div><div class="setgrid">' + lists + "</div></div>";
  $("#notifyTest").onclick = async function () { var b = this; b.disabled = true; $("#notifyResult").textContent = t("Sending test..."); try { var r = await api("POST", "/api/settings/notifications/test", {}, true); var msg = Object.keys(r.channels || {}).map(function (k) { return k + ": " + (r.channels[k].ok ? t("sent") : t("failed") + " — " + r.channels[k].detail); }).join("; "); $("#notifyResult").textContent = msg || t(r.message); toast(r.ok ? t("Test notifications sent") : t("Test finished; check channel results"), r.ok ? "" : "err"); } catch (e) { $("#notifyResult").textContent = e.msg || t("Could not send test"); } finally { b.disabled = false; } };
  var reload = async function (msg) { META = await api("GET", "/api/meta"); if (msg) toast(msg); vSettings(++seq); };
  $("#slaSave").onclick = async function () { var h = {}; META.severities.forEach(function (sv) { h[sv] = $("#sla" + sv).value; }); try { var r = await api("POST", "/api/settings/sla", { hours: h, apply_open: $("#slaApply").checked }, true); reload(t("Response targets saved") + (r.recalculated ? " · " + t("{n} open incidents updated", { n: r.recalculated }) : "")); } catch (x) { $("#slaE").textContent = x.msg || t("Could not save"); } };
  $$("[data-ren]").forEach(function (i) { i.onchange = async function () { var v = this.value.trim(); if (!v || v === this.dataset.old) { this.value = this.dataset.old; return; } try { await api("POST", "/api/lookups/" + this.dataset.ren, { name: v }); reload(t("Renamed")); } catch (e) { this.value = this.dataset.old; } }; });
  $$("[data-act]").forEach(function (i) { i.onchange = async function () { try { await api("POST", "/api/lookups/" + this.dataset.act, { active: this.checked ? 1 : 0 }); reload(this.checked ? t("Enabled") : t("Disabled")); } catch (e) {} }; });
  $$("[data-ldel]").forEach(function (b) { b.onclick = async function () { if (confirm(t("Delete this item?"))) { try { await api("POST", "/api/lookups/" + b.dataset.ldel + "/delete"); reload(t("Deleted")); } catch (e) {} } }; });
  $$("[data-add]").forEach(function (b) { var k = b.dataset.add, inp = document.querySelector('[data-new="' + k + '"]'); var go = async function () { var v = inp.value.trim(); if (!v) return; try { await api("POST", "/api/lookups", { kind: k, name: v }); reload(t("Added")); } catch (e) {} }; b.onclick = go; inp.onkeydown = function (e) { if (e.key === "Enter") go(); }; });
}
