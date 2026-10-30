// Builds Warden_Executive_Summary.pptx from out/report.json.
const fs = require("fs");
const path = require("path");
const pptxgen = require("pptxgenjs");
const SKILL = process.env.PPTX_SKILL_DIR;
const { applyTheme } = require(path.join(SKILL, "scripts", "apply_theme.js"));
const R = JSON.parse(fs.readFileSync(path.join(__dirname, "..", "out", "report.json"), "utf8"));
const pct = (x) => `${Math.round(x * 1000) / 10}%`;

const THEME = {
  name: "Warden", headFontFace: "Cambria", bodyFontFace: "Calibri",
  colors: { dk1: "1B1F24", lt1: "FFFFFF", dk2: "10302F", lt2: "EEF4F3", accent1: "10302F", accent2: "D9822B", accent3: "3B8C86", accent4: "8A9A99", accent5: "F0B561", accent6: "B5483F", hlink: "10302F", folHlink: "3B8C86" },
};
const pres = new pptxgen();
pres.layout = "LAYOUT_16x9";
pres.title = "Warden Executive Summary";
pres.author = "Christian Kouadio Kouassi";
pres.theme = { headFontFace: THEME.headFontFace, bodyFontFace: THEME.bodyFontFace };
const C = pres.SchemeColor;

pres.defineSlideMaster({ title: "DARK", background: { color: C.text2 }, objects: [], slideNumber: { x: 9.2, y: 5.2, w: 0.5, h: 0.3, fontSize: 10, color: C.accent4 } });
pres.defineSlideMaster({
  title: "CONTENT", background: { color: C.background1 },
  objects: [{ placeholder: { options: { name: "title", type: "title", x: 0.6, y: 0.35, w: 8.8, h: 0.8, fontSize: 26, bold: true, color: C.text2, fontFace: "Cambria", margin: 0, valign: "top", align: "left" }, text: "" } }],
  slideNumber: { x: 9.2, y: 5.2, w: 0.5, h: 0.3, fontSize: 10, color: C.accent4 },
});
const card = (s, x, y, w, h, name, fill) => s.addShape(pres.ShapeType.roundRect, { x, y, w, h, rectRadius: 0.08, fill: { color: fill || C.background2 }, line: { color: fill || C.background2, width: 0 }, objectName: name });
const txt = (s, t, o) => s.addText(t, { margin: 0, isTextBox: true, ...o });

const b = R.scan.baseline, c = R.scan.current, a = R.agent_security, n = R.nhi, v = R.vulnerability_management;
const allowed = R.sdlc.scenarios.filter((x) => x.allow).length;

// 1. Title
let s = pres.addSlide({ masterName: "DARK" });
txt(s, "Warden", { x: 0.7, y: 1.3, w: 8.6, h: 1.0, fontFace: "Cambria", fontSize: 54, bold: true, color: C.background1, objectName: "Title" });
txt(s, "Security that keeps pace with AI-written code: find the real risks, fix the identities, and keep AI from approving itself or leaking PHI", { x: 0.7, y: 2.4, w: 8.2, h: 1.1, fontSize: 20, color: C.background2, objectName: "Subtitle" });
txt(s, "Python  |  AWS  |  HIPAA  |  agentic SDLC  |  Christian Kouadio Kouassi", { x: 0.7, y: 4.55, w: 8.6, h: 0.4, fontSize: 14, color: C.accent5, objectName: "Byline" });
s.addNotes("Warden is a working demonstration of what a first dedicated security engineer at a healthcare SaaS builds. It runs real scanners on a deliberately vulnerable member API and its Terraform, and adds identity, AI-code governance, agent controls, vendor review, detection and a HIPAA map on top.");

// 2. Why it matters (numbers)
s = pres.addSlide({ masterName: "CONTENT" });
txt(s, "One engineer cannot review everything, so the work has to rank itself", { x: 0.6, y: 0.35, w: 8.8, h: 0.8, fontFace: "Cambria", fontSize: 26, bold: true, color: C.text2, valign: "top", objectName: "Title2" });
const stats = [
  [`${b.unique}`, `unique findings on the starting code, ${b.by_severity.high} of them high risk`],
  [`${v.in_kev} of ${v.components_with_cves}`, "vulnerable components are on CISA's known-exploited list, so they go first"],
  [`${n.issues_before}`, `issues across ${n.identities} machine identities: orphaned owners, stale keys, admin wildcards`],
  [pct(a.none.attack_success_rate), "of prompt injection attacks reach a tool when the AI agent has no controls around it"],
];
stats.forEach(([big, label], i) => {
  const x = 0.6 + (i % 2) * 4.5, y = 1.4 + Math.floor(i / 2) * 1.75;
  card(s, x, y, 4.2, 1.5, `StatCard${i + 1}`);
  txt(s, big, { x: x + 0.25, y: y + 0.1, w: 3.7, h: 0.7, fontFace: "Cambria", fontSize: 36, bold: true, color: C.accent2, objectName: `StatValue${i + 1}` });
  txt(s, label, { x: x + 0.25, y: y + 0.82, w: 3.7, h: 0.62, fontSize: 13, color: C.text1, objectName: `StatLabel${i + 1}` });
});
s.addNotes("The target is a fictional GI care platform called CareLoop. The data is synthetic except the CISA catalog, which is the real file from the day of the run. Numbers on this slide are read from out/report.json.");

// 3. Pipeline
s = pres.addSlide({ masterName: "CONTENT" });
s.addText("Eight capabilities, one finding model", { placeholder: "title" });
const steps = [
  ["Scan", "Bandit, Semgrep, Checkov, secrets"], ["Prioritize", "KEV first, then exposure"], ["Identities", "inventory, rotate, disable"], ["AI code gate", "human + code owner + signed CI"],
  ["Clawback", "revoke, revert, rotate, verify"], ["Agent controls", "scopes, egress, DLP, provenance"], ["Vendors", "claims checked against evidence"], ["Detect + map", "11 rules, HIPAA 164.312"],
];
steps.forEach(([t, d], i) => {
  const col = i % 4, row = Math.floor(i / 4);
  const x = 0.6 + col * 2.25, y = 1.5 + row * 1.7;
  card(s, x, y, 1.9, 1.15, `Step${i + 1}`, i === 3 ? C.accent5 : C.background2);
  s.addText([{ text: t, options: { bold: true, breakLine: true, fontSize: 14, color: C.text2 } }, { text: d, options: { fontSize: 11, color: C.text1 } }], { x: x + 0.1, y: y + 0.08, w: 1.7, h: 1.0, valign: "middle", align: "center", margin: 0, isTextBox: true, objectName: `StepText${i + 1}` });
  if (col < 3) s.addShape(pres.ShapeType.line, { x: x + 1.93, y: y + 0.575, w: 0.3, h: 0, line: { color: C.accent4, width: 1.5, endArrowType: "triangle" }, objectName: `Arrow${i + 1}` });
});
txt(s, "Every module has tests, and every defect found along the way has a failing-test commit followed by a fix commit.", { x: 0.6, y: 4.75, w: 8.8, h: 0.4, fontSize: 12, color: C.accent4, objectName: "PipelineNote" });

// 4. Findings before and after (chart)
s = pres.addSlide({ masterName: "CONTENT" });
s.addText(`High-risk findings went from ${b.by_severity.high} to ${c.by_severity.high || 0}`, { placeholder: "title" });
const sevs = ["high", "medium", "low"];
s.addChart(pres.charts.BAR, [
  { name: "Starting code", labels: ["High", "Medium", "Low"], values: sevs.map((k) => b.by_severity[k] || 0) },
  { name: "After remediation", labels: ["High", "Medium", "Low"], values: sevs.map((k) => c.by_severity[k] || 0) },
], { x: 0.6, y: 1.3, w: 5.6, h: 3.8, barDir: "col", barGrouping: "clustered", chartColors: ["B5483F", "10302F"], showLegend: true, legendPos: "b", legendFontFace: "+mn-lt", legendFontSize: 12,
     showValue: true, dataLabelPosition: "outEnd", dataLabelFontFace: "+mn-lt", dataLabelFontSize: 12, catAxisLabelFontFace: "+mn-lt", catAxisLabelFontSize: 12,
     valAxisHidden: true, valAxisMinVal: 0, valGridLine: { style: "none" }, catGridLine: { style: "none" }, objectName: "FindingsChart" });
card(s, 6.5, 1.4, 3.0, 3.6, "FindingsCard");
s.addText([
  { text: "What changed", options: { bold: true, breakLine: true, color: C.text2, fontSize: 15 } },
  { text: "Another member's record, SQL injection, an open export route, unsafe YAML, committed secrets and weak password hashing, all fixed with an exploit test first.", options: { breakLine: true } },
  { text: "Terraform: private encrypted storage and database, no SSH, scoped IAM, audit trail.", options: { breakLine: true } },
  { text: "The Semgrep rule for broken access control first matched nothing; no scanner reported the worst bug until it was fixed.", options: {} },
], { x: 6.65, y: 1.55, w: 2.7, h: 3.3, fontSize: 11.5, color: C.text1, paraSpaceAfter: 8, valign: "top", margin: 0, isTextBox: true, objectName: "FindingsNotes" });
s.addNotes("Counts are unique findings after merging reports of the same weakness from different tools. 61 raw findings became 39 unique on the starting code, then 10 raw and 8 unique after remediation.");

// 5. AI-written code gate
s = pres.addSlide({ masterName: "CONTENT" });
s.addText("AI-written code never approves itself", { placeholder: "title" });
const rows = [[{ text: "Scenario", options: { bold: true, color: C.background1, fill: { color: C.text2 } } }, { text: "Decision", options: { bold: true, color: C.background1, fill: { color: C.text2 } } }]];
R.sdlc.scenarios.forEach((x) => rows.push([{ text: x.scenario.replace(/^S\d /, "") }, { text: x.allow ? "Allow" : "Deny", options: { bold: true, color: x.allow ? "2E7D5B" : "B5483F" } }]));
s.addTable(rows, { x: 0.6, y: 1.35, w: 5.7, colW: [4.7, 1.0], fontSize: 12, fontFace: "Calibri", color: "1B1F24", border: { type: "solid", color: "D5DEDD", pt: 0.75 }, rowH: 0.42, valign: "middle", objectName: "GateTable" });
card(s, 6.6, 1.4, 2.9, 3.4, "GateCard");
s.addText([
  { text: "The rule", options: { bold: true, breakLine: true, color: C.text2, fontSize: 15 } },
  { text: "A change by an agent needs a human who did not write it, a code owner on sensitive paths, and a CI attestation signed by a key the agent cannot reach.", options: { breakLine: true } },
  { text: "Clawback", options: { bold: true, breakLine: true, color: C.text2, fontSize: 15 } },
  { text: `Tested end to end: access cut, commits reverted on a branch, keys rotated, checks run. Drill ${R.sdlc.clawback_drill.ok ? "passed" : "failed"}.`, options: {} },
], { x: 6.75, y: 1.55, w: 2.6, h: 3.2, fontSize: 11.5, color: C.text1, paraSpaceAfter: 6, valign: "top", margin: 0, isTextBox: true, objectName: "GateNotes" });
s.addNotes(`${allowed} of ${R.sdlc.scenarios.length} scenarios are allowed. A CODEOWNERS file whose catch-all rule sat last silently disabled every security owner rule; it was found by tests and a lint now guards it.`);

// 6. Agent controls
s = pres.addSlide({ masterName: "CONTENT" });
s.addText(`Attacks on the AI agent: ${pct(a.none.attack_success_rate)} to ${pct(a.full.attack_success_rate)} with layered controls`, { placeholder: "title" });
const names = { none: "None", authz: "Scopes", "authz+egress": "+ Egress", "authz+egress+dlp": "+ DLP", full: "+ Provenance" };
const keys = Object.keys(names);
s.addChart(pres.charts.BAR, [{ name: "Attack success rate (%)", labels: keys.map((k) => names[k]), values: keys.map((k) => Math.round(a[k].attack_success_rate * 1000) / 10) }],
  { x: 0.6, y: 1.3, w: 5.8, h: 3.8, barDir: "col", chartColors: ["B5483F"], showLegend: false, showValue: true, dataLabelPosition: "outEnd", dataLabelFontFace: "+mn-lt", dataLabelFontSize: 12,
    dataLabelFormatCode: "0.0", catAxisLabelFontFace: "+mn-lt", catAxisLabelFontSize: 12, valAxisHidden: true, valAxisMinVal: 0, valAxisMaxVal: 115, valGridLine: { style: "none" }, catGridLine: { style: "none" }, objectName: "AgentChart" });
card(s, 6.7, 1.4, 2.8, 3.6, "AgentCard");
s.addText([
  { text: "The cost", options: { bold: true, breakLine: true, color: C.text2, fontSize: 15 } },
  { text: `${a.full.benign.escalated} of ${a.full.benign.completed + a.full.benign.escalated + a.full.benign.blocked} legitimate requests need a human confirmation, because an email planned from untrusted text is held.`, options: { breakLine: true } },
  { text: "The caveat", options: { bold: true, breakLine: true, color: C.text2, fontSize: 15 } },
  { text: "The agent here is a simulation that obeys everything. The numbers measure the controls, not any model.", options: {} },
], { x: 6.85, y: 1.55, w: 2.5, h: 3.4, fontSize: 11.5, color: C.text1, paraSpaceAfter: 6, valign: "top", margin: 0, isTextBox: true, objectName: "AgentNotes" });
s.addNotes("22 attacks across direct injection, excessive agency, cross-member access, indirect injection through documents, encoded instructions, lookalike domains and PHI sent to an allowlisted vendor host. Two bugs in the controls were found by the corpus: a suffix check that let notcareloop.test pass as internal, and DLP patterns that missed 'Social 123 45 6789'.");

// 7. Priorities: KEV + identities
s = pres.addSlide({ masterName: "CONTENT" });
s.addText("Fix what attackers already use, and the credentials nobody owns", { placeholder: "title" });
const vr = [[...["CVE", "Component", "KEV", "Due"].map((h) => ({ text: h, options: { bold: true, color: C.background1, fill: { color: C.text2 } } }))]];
v.ranked.slice(0, 6).concat(v.ranked.slice(-1)).forEach((x) => vr.push([x.cve, x.component, x.kev ? "yes" : "no", x.due]));
s.addTable(vr, { x: 0.6, y: 1.35, w: 5.6, colW: [1.6, 1.8, 0.6, 1.6], fontSize: 11, fontFace: "Calibri", color: "1B1F24", border: { type: "solid", color: "D5DEDD", pt: 0.75 }, rowH: 0.38, valign: "middle", objectName: "KevTable" });
card(s, 6.5, 1.4, 3.0, 3.6, "NhiCard");
s.addText([
  { text: "Machine identities", options: { bold: true, breakLine: true, color: C.text2, fontSize: 15 } },
  { text: `${n.issues_before} issues became ${n.issues_after}: two keys with no live owner were disabled, tested against IAM through boto3.`, options: { breakLine: true } },
  { text: `The rest (${n.by_rule_after["over-scoped"] || 0} over-scoped grants, 2 escalation paths) need an owner decision, not automation.`, options: { breakLine: true } },
  { text: "Seven-day clocks for known-exploited vulnerabilities, 30 days for the one that is not.", options: {} },
], { x: 6.65, y: 1.55, w: 2.7, h: 3.4, fontSize: 11.5, color: C.text1, paraSpaceAfter: 6, valign: "top", margin: 0, isTextBox: true, objectName: "NhiNotes" });
s.addNotes("The KEV file is the real CISA catalog, version 2026.10.29. Component and CVE pairings use real public CVEs; the CVSS values were entered by hand and should be re-verified before real use.");

// 8. Incidents
s = pres.addSlide({ masterName: "CONTENT" });
s.addText("Seventeen defects, each reproduced then fixed", { placeholder: "title" });
const groups = [
  ["Seeded in the target (7)", "BOLA on member records\nSQL injection in search\nOpen export route and debug endpoint\nUnsafe YAML, TLS verification off\nSecrets in source, MD5 passwords\nTokens that never expire\nExposed Terraform"],
  ["Found in the tooling (4)", "Secret counted twice by two tools\nCustom Semgrep rule matched nothing\nSecret scanner silent outside git\nFalse positive on a Terraform boolean"],
  ["Found in the controls (4)", "CODEOWNERS catch-all listed last\nLookalike email domain passed\nDLP missed labeled SSN and MRN\nBurst alert undercounted PHI reads"],
  ["Found in the procedures (2)", "Clawback crashed on a revert conflict\nControl map left 20 checks unmapped"],
];
groups.forEach(([t, body], i) => {
  const x = 0.6 + (i % 2) * 4.5, y = 1.3 + Math.floor(i / 2) * 1.95;
  card(s, x, y, 4.3, 1.8, `Group${i + 1}`);
  txt(s, t, { x: x + 0.2, y: y + 0.1, w: 3.9, h: 0.35, fontFace: "Cambria", fontSize: 15, bold: true, color: C.accent2, objectName: `GroupTitle${i + 1}` });
  s.addText(body.split("\n").map((l, j, arr) => ({ text: l, options: { breakLine: j < arr.length - 1 } })), { x: x + 0.2, y: y + 0.48, w: 3.95, h: 1.28, fontSize: 11, color: C.text1, valign: "top", margin: 0, isTextBox: true, objectName: `GroupBody${i + 1}` });
});
txt(s, "Each incident is a failing-test commit followed by a separate fix commit; a script re-runs both to prove it.", { x: 0.6, y: 5.0, w: 8.2, h: 0.3, fontSize: 11, color: C.accent4, objectName: "IncNote" });

// 9. HIPAA map (chart of open findings per control)
s = pres.addSlide({ masterName: "CONTENT" });
s.addText("HIPAA technical safeguards: gaps closed where code can close them", { placeholder: "title" });
const cb = R.compliance.before, ca = R.compliance.after;
const lab = cb.map((x) => x.id.replace("164.", "").replace("(ii)(A)", ""));
s.addChart(pres.charts.BAR, [
  { name: "Before", labels: lab, values: cb.map((x) => x.open_findings) },
  { name: "After", labels: lab, values: ca.map((x) => x.open_findings) },
], { x: 0.6, y: 1.3, w: 6.2, h: 3.8, barDir: "col", barGrouping: "clustered", chartColors: ["8A9A99", "10302F"], showLegend: true, legendPos: "b", legendFontFace: "+mn-lt", legendFontSize: 12,
     showValue: true, dataLabelPosition: "outEnd", dataLabelFontFace: "+mn-lt", dataLabelFontSize: 10, catAxisLabelFontFace: "+mn-lt", catAxisLabelFontSize: 9, valAxisHidden: true, valAxisMinVal: 0, valGridLine: { style: "none" }, catGridLine: { style: "none" }, objectName: "HipaaChart" });
card(s, 7.0, 1.4, 2.5, 3.6, "HipaaCard");
s.addText([
  { text: "Open findings per control", options: { bold: true, breakLine: true, color: C.text2, fontSize: 14 } },
  { text: "What remains is mostly vulnerable dependencies and the identity decisions above. A control with none open means the technical checks found nothing, never that it is met.", options: {} },
], { x: 7.15, y: 1.55, w: 2.2, h: 3.3, fontSize: 11.5, color: C.text1, paraSpaceAfter: 6, valign: "top", margin: 0, isTextBox: true, objectName: "HipaaNotes" });

// 10. Limits
s = pres.addSlide({ masterName: "DARK" });
txt(s, "What this shows, and what it does not", { x: 0.7, y: 0.5, w: 8.6, h: 0.8, fontFace: "Cambria", fontSize: 32, bold: true, color: C.background1, objectName: "ClosingTitle" });
s.addText([
  { text: "Shows", options: { bold: true, color: C.accent5, breakLine: true, fontSize: 18 } },
  { text: "Real scanners, KEV-based triage, IAM work through the AWS API", options: { bullet: true, breakLine: true } },
  { text: "A gate and a clawback for AI-written code", options: { bullet: true, breakLine: true } },
  { text: "Measured controls for an AI agent that touches PHI", options: { bullet: true } },
], { x: 0.7, y: 1.5, w: 4.2, h: 2.7, fontSize: 15, color: C.background1, paraSpaceAfter: 8, valign: "top", margin: 0, isTextBox: true, objectName: "ShowsText" });
s.addText([
  { text: "Does not show", options: { bold: true, color: C.accent5, breakLine: true, fontSize: 18 } },
  { text: "A live AWS, Okta or GitHub organization (mocked or config only)", options: { bullet: true, breakLine: true } },
  { text: "A language model: the agent is a simulation", options: { bullet: true, breakLine: true } },
  { text: "Years of on-call and incident experience", options: { bullet: true } },
], { x: 5.2, y: 1.5, w: 4.2, h: 2.7, fontSize: 15, color: C.background1, paraSpaceAfter: 8, valign: "top", margin: 0, isTextBox: true, objectName: "NotShownText" });
txt(s, "105 tests  |  17 incidents  |  sole-author git history  |  nothing pushed", { x: 0.7, y: 4.55, w: 8.6, h: 0.4, fontSize: 14, color: C.accent3, objectName: "Footer" });

(async () => {
  const out = path.join(__dirname, "..", "Warden_Executive_Summary.pptx");
  await pres.writeFile({ fileName: out });
  await applyTheme(out, THEME);
  console.log("wrote", out);
})();
