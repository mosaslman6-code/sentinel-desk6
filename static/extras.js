"use strict";
/* SentinelDesk 3.3 - easy extras: incident templates, copy summary, quick guide. */

/* ---- 1) Incident templates (fills the "Report an incident" form) ---- */
var TEMPLATES = [
  { k: "Phishing email", title: "Suspicious phishing email reported", desc: "A user received an email asking for a password or a click on a link. Sender, subject, and whether the link was opened:", cat: "Phishing", sev: "Medium", src: "Email gateway" },
  { k: "Ransomware", title: "Files encrypted - possible ransomware", desc: "Files were renamed or encrypted and a ransom note appeared. Affected machine, time first noticed, and whether it was disconnected:", cat: "Malware", sev: "Critical", src: "EDR alert" },
  { k: "Malware on a workstation", title: "Malware detected on a workstation", desc: "Antivirus/EDR detected a malicious file. File name, path, and action taken:", cat: "Malware", sev: "High", src: "EDR alert" },
  { k: "Brute-force login attempts", title: "Repeated failed logins (brute force)", desc: "Many failed sign-in attempts on an account or service. Source IP, targeted account, and number of attempts:", cat: "Unauthorized Access", sev: "High", src: "SIEM alert" },
  { k: "DDoS / service slowdown", title: "Service slowdown caused by a flood of requests", desc: "A site or service became slow or unreachable because of abnormal traffic. Start time and traffic source:", cat: "DDoS", sev: "High", src: "Firewall / IDS" },
  { k: "Lost or stolen device", title: "Lost or stolen device", desc: "A laptop or phone was lost or stolen. Owner, what data it holds, and whether it was encrypted or locked:", cat: "Data Leak", sev: "High", src: "User report" },
  { k: "Data leak", title: "Sensitive data exposed", desc: "Sensitive data was sent or published to the wrong place. What data, how many people affected, and where it went:", cat: "Data Leak", sev: "Critical", src: "Audit / review" },
  { k: "Malicious mobile app or SMS", title: "Malicious mobile app or phishing SMS", desc: "A phone user installed a suspicious app or opened a phishing SMS link. Phone model, app or link name, and permissions granted:", cat: "Malware", sev: "Medium", src: "User report" }
];
(function () {
  var base = openNew;
  openNew = function () {
    base();
    var sel = $("#nTpl"); if (!sel) return;
    sel.innerHTML = '<option value="">' + esc(t("Start from a blank form")) + "</option>" + TEMPLATES.map(function (x, n) { return '<option value="' + n + '">' + esc(t(x.k)) + "</option>"; }).join("");
    sel.value = "";
    sel.onchange = function () {
      var x = TEMPLATES[parseInt(sel.value, 10)]; if (!x) return;
      $("#nTitle").value = t(x.title); $("#nDesc").value = t(x.desc) + " ";
      $("#nCat").value = x.cat; $("#nSev").value = x.sev; $("#nSrc").value = x.src;
      $("#nSev").dispatchEvent(new Event("change")); $("#nDesc").focus();
    };
  };
})();

/* ---- 2) Copy a short summary of an incident (for WhatsApp / Telegram / e-mail) ---- */
(function () {
  var base = vDetail;
  vDetail = async function (id, my) {
    await base(id, my);
    if (my !== seq || $("#bCopy")) return;
    var i; try { i = await api("GET", "/api/incidents/" + encodeURIComponent(id), null, true); } catch (e) { return; }
    if (my !== seq || !$("#pgA")) return;
    var b = document.createElement("button"); b.className = "btn"; b.id = "bCopy"; b.type = "button"; b.innerHTML = icon("copy") + t("Copy summary");
    b.onclick = function () {
      copyText(["[" + i.id + "] " + i.title,
        t("Severity") + ": " + t(i.severity) + " | " + t("Status") + ": " + t(i.status) + " | " + t("Category") + ": " + t(i.category),
        t("Affected asset") + ": " + i.asset + " | " + t("Assignee") + ": " + (person(i.assignee) || t("Unassigned")),
        t("Risk score") + ": " + (i.risk == null ? "-" : i.risk + "/100") + " | " + t("Due {d}", { d: fdate(i.due_at) }),
        location.origin + "/#/incidents/" + encodeURIComponent(i.id)].join("\n"));
    };
    $("#pgA").insertBefore(b, $("#pgA").firstChild);
  };
})();

/* ---- 3) Quick guide page (#/help) ---- */
async function vHelp(my) {
  head(t("Quick guide"), t("How to use SentinelDesk in 5 minutes"), "");
  var steps = [
    ["1", "Report", "Press \"New incident\" (choose a template to fill it for you), then add the affected asset."],
    ["2", "Triage", "Set the severity, assign someone, and move the status to Investigating."],
    ["3", "Record", "Add actions to the timeline, tick the checklist, and attach indicators and evidence."],
    ["4", "Contain and fix", "Move the status to Contained and then Resolved when the problem is fixed."],
    ["5", "Close and report", "Close with the root cause and lessons learned, then press \"Generate report\"."]
  ];
  var tips = ["Press Ctrl+K to search anything or run a command.", "Drag cards in the Board view to change their status.", "Use \"Copy summary\" on an incident to send it quickly to a colleague.", "Change the default passwords before showing the system to anyone."];
  var li = function (a) { return a.map(function (x) { return "<li>" + esc(t(x)) + "</li>"; }).join(""); };
  $("#view").innerHTML = '<div class="panel"><h3>' + t("The incident life cycle") + '</h3><div class="body"><ol style="margin:0;padding-inline-start:22px;line-height:2">' +
    steps.map(function (s) { return "<li><b>" + esc(t(s[1])) + ":</b> " + esc(t(s[2])) + "</li>"; }).join("") + "</ol></div></div>" +
    '<div class="panel mt"><h3>' + t("Handy tips") + '</h3><div class="body"><ul style="margin:0;padding-inline-start:22px;line-height:2">' + li(tips) + "</ul></div></div>" +
    '<div class="grid c-2 mt"><div class="panel"><h3>' + t("Severity guide") + '</h3><div class="body"><p class="mut sm" style="margin:0 0 6px">' +
    META.severities.slice().reverse().map(function (s) { return sevPill(s) + " " + META.sla_hours[s] + t("h"); }).join(" &nbsp; ") + '</p><p class="mut sm" style="margin:0">' + t("The number is the response target in hours.") + "</p></div></div>" +
    '<div class="panel"><h3>' + t("Need more?") + '</h3><div class="body"><a class="btn" href="#/api">' + icon("code") + t("API reference") + '</a></div></div></div>';
}
