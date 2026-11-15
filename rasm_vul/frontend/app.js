"use strict";
/* RASM-Vul front-end (plain JavaScript, no libraries). All user/server text is inserted with textContent, never innerHTML. */

const $ = (s, r = document) => r.querySelector(s);
const $$ = (s, r = document) => [...r.querySelectorAll(s)];
const NS = "http://www.w3.org/2000/svg";
function el(tag, cls, text) {
  const e = document.createElement(tag);
  if (cls) e.className = cls;
  if (text !== undefined && text !== null) e.textContent = text;
  return e;
}
function sv(tag, attrs = {}, text) {
  const e = document.createElementNS(NS, tag);
  for (const [k, v] of Object.entries(attrs)) e.setAttribute(k, v);
  if (text !== undefined) e.textContent = text;
  return e;
}
const f2 = v => Number(v).toFixed(2);
const pct = v => Math.round(v * 100) + "%";
const pct1 = v => (v * 100).toFixed(1) + "%";
const store = {
  get(k) { try { return localStorage.getItem(k); } catch { return null; } },
  set(k, v) { try { localStorage.setItem(k, v); } catch { /* storage can be blocked */ } },
  sget(k) { try { return sessionStorage.getItem(k); } catch { return null; } },
  sset(k, v) { try { v === null ? sessionStorage.removeItem(k) : sessionStorage.setItem(k, v); } catch { /* ignore */ } },
};

const SAMPLE = "void copy_name(char *src) {\n    char buf[32];\n    strcpy(buf, src);\n    printf(\"%s\", buf);\n}";
const SAMPLE_FIXED = "void copy_name(char *src) {\n    char buf[32];\n    strncpy(buf, src, sizeof(buf) - 1);\n    buf[sizeof(buf) - 1] = 0;\n    printf(\"%s\", buf);\n}";
const SAMPLE_FILE = `#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void copy_into(char *dst, const char *src)
{
    strcpy(dst, src);
}

void handle_request(const char *name)
{
    char buf[32];
    copy_into(buf, name);
    printf("%s\\n", buf);
}

int add_checked(int a, int b)
{
    if (a > 1000 || b > 1000)
        return -1;
    return a + b;
}

int *make_table(int n)
{
    int *p = malloc(n * sizeof(int));
    p[0] = 0;
    return p;
}
`;

const state = { threshold: 0.5, defaultThr: 0.5, health: null, updaters: {}, scan: null, evalData: null };

const PAGES = {
  detect: ["Detect", "Score one function against historical vulnerability fixes."],
  scan: ["Scan file", "Rank every function in a file by risk, built for nightly checks."],
  patch: ["Patch check", "Compare a function before and after a fix."],
  eval: ["Evaluation", "Precision and recall on the held-out test pairs."],
  review: ["Review", "Analyst feedback waiting to join the knowledge base."],
};
const SIGNALS = {
  llm: ["LLM verdict", "LLM not configured"],
  alignment: ["Matches the unfixed lines of the closest case", "no close case"],
  neighbor: ["Closer to the vulnerable version", "no close case"],
  knowledge: ["Risky API calls", "n/a"],
  static: ["Static analyzers", "no analyzer ran"],
};
const CHANNELS = { code: "Code", ast: "AST", knowledge: "Knowledge", line: "Line changes", ast_change: "AST changes" };

/* ------------------------------------------------------------------ plumbing */
async function api(path, body, headers = {}) {
  const init = body !== undefined
    ? { method: "POST", headers: { "Content-Type": "application/json", ...headers }, body: JSON.stringify(body) }
    : { headers };
  const r = await fetch(path, init);
  if (!r.ok) {
    let msg = r.statusText || "Request failed";
    try {
      const j = await r.json();
      msg = typeof j.detail === "string" ? j.detail
        : Array.isArray(j.detail) ? j.detail.map(d => (d.loc ? d.loc.slice(1).join(".") + ": " : "") + d.msg).join("; ") : msg;
    } catch { /* keep status text */ }
    const err = new Error(msg); err.status = r.status; throw err;
  }
  return r.json();
}
function toast(msg, kind = "info") {
  const t = el("div", "toast " + kind, msg);
  $("#toasts").append(t);
  setTimeout(() => t.remove(), kind === "error" ? 8000 : 4500);
}
async function run(btn, label, fn) {
  const orig = btn.textContent;
  btn.disabled = true; btn.classList.add("busy"); btn.textContent = label;
  try { await fn(); } catch (e) { toast(e.message, "error"); }
  finally { btn.disabled = false; btn.classList.remove("busy"); btn.textContent = orig; }
}
function download(name, mime, text) {
  const a = el("a"); a.href = URL.createObjectURL(new Blob([text], { type: mime })); a.download = name;
  document.body.append(a); a.click(); a.remove(); setTimeout(() => URL.revokeObjectURL(a.href), 1000);
}
const flagged = score => score >= state.threshold;

/* ------------------------------------------------------------------ tabs and threshold */
function showTab(id) {
  if (!PAGES[id]) id = "detect";
  $$(".nav button").forEach(b => b.setAttribute("aria-selected", String(b.dataset.t === id)));
  $$(".pane").forEach(p => p.classList.toggle("on", p.id === id));
  $("#page-title").textContent = PAGES[id][0];
  $("#page-sub").textContent = PAGES[id][1];
  $("#thr-box").hidden = id === "review";
  if (location.hash !== "#" + id) history.replaceState(null, "", "#" + id);
  if (id === "eval") loadEval();
  if (id === "review") loadReview();
}
$$(".nav button").forEach(b => b.onclick = () => showTab(b.dataset.t));

function setThreshold(v, persist = true) {
  state.threshold = Math.min(1, Math.max(0, Number(v)));
  $("#thr").value = state.threshold;
  $("#thr-val").textContent = f2(state.threshold);
  $("#thr-reset").hidden = Math.abs(state.threshold - state.defaultThr) < 0.005;
  if (persist) store.set("rasm.threshold", String(state.threshold));
  Object.values(state.updaters).forEach(fn => typeof fn === "function" && fn());
}
$("#thr").oninput = e => setThreshold(e.target.value);
$("#thr-reset").onclick = () => setThreshold(state.defaultThr);

/* ------------------------------------------------------------------ shared pieces */
function gauge(score, thr) {
  const svg = sv("svg", { viewBox: "0 0 200 122", class: "gauge", role: "img" });
  const d = "M 20 100 A 80 80 0 0 1 180 100";
  svg.append(sv("path", { d, class: "g-track", pathLength: 100 }));
  const fill = sv("path", { d, class: "g-fill", pathLength: 100 });
  const tick = sv("line", { class: "g-tick" });
  svg.append(fill, tick, sv("text", { x: 100, y: 96, class: "g-num" }, f2(score)), sv("text", { x: 100, y: 116, class: "g-cap" }, "risk score"));
  svg.update = t => {
    const a = Math.PI * (1 - t);
    tick.setAttribute("x1", 100 + 66 * Math.cos(a)); tick.setAttribute("y1", 100 - 66 * Math.sin(a));
    tick.setAttribute("x2", 100 + 94 * Math.cos(a)); tick.setAttribute("y2", 100 - 94 * Math.sin(a));
    fill.setAttribute("stroke-dasharray", Math.max(score * 100, 0.01) + " 100");
    fill.setAttribute("class", "g-fill " + (score >= t ? "bad" : "ok"));
    svg.setAttribute("aria-label", "Risk score " + f2(score) + ", threshold " + f2(t));
  };
  svg.update(thr);
  return svg;
}

function section(title, note) {
  const s = el("div", "sec"); const h = el("h3", "", title);
  if (note) h.append(el("small", "", note));
  s.append(h); return s;
}

function signalRows(signals) {
  const wrap = el("div");
  Object.entries(signals).forEach(([k, s]) => {
    const [label, offText] = SIGNALS[k] || [k, "n/a"];
    const off = s.value === null;
    const row = el("div", "sig" + (off ? " off" : ""));
    const track = el("div", "sig-track"); const bar = el("i", !off && s.value >= 0.5 ? "hot" : "");
    bar.style.width = off ? "0%" : (s.value * 100) + "%"; track.append(bar);
    const w = el("span", "w", off ? offText : "weight " + pct(s.weight));
    const name = el("span", "", label); if (!off) name.append(el("span", "v hint", "  " + f2(s.value)));
    row.append(name, track, w); wrap.append(row);
  });
  return wrap;
}

function findingsList(list) {
  const wrap = el("div");
  list.slice().sort((a, b) => a.line - b.line).forEach(f => {
    const r = el("div", "finding");
    r.append(el("span", "ln", "line " + f.line), el("span", "tool", f.tool + " " + f.severity),
      el("span", "msg", (f.rule ? f.rule + ": " : "") + f.message + (f.cwe ? " (" + f.cwe + ")" : "")));
    wrap.append(r);
  });
  return wrap;
}

function channelBars(contrib) {
  const wrap = el("div");
  Object.entries(contrib).forEach(([ch, v]) => {
    const r = el("div", "bar"); const t = el("div", "bar-track"); const i = el("i"); i.style.width = (v * 100) + "%"; t.append(i);
    r.append(el("span", "", CHANNELS[ch] || ch), t, el("span", "", pct(v))); wrap.append(r);
  });
  return wrap;
}

function evidenceCards(list) {
  const wrap = el("div");
  list.forEach((e, i) => {
    const k = el("div", "case");
    k.append(el("h4", "", (i ? "Related case " : "Best matching case ") + e.pair_id + (e.cwe ? " (" + e.cwe + ")" : "")));
    if (e.description) k.append(el("p", "", e.description));
    if (e.solution) k.append(el("p", "", "Historical fix: " + e.solution));
    const d = el("pre", "diff");
    e.removed.forEach(l => d.append(el("div", "rm", "- " + l)));
    e.added.forEach(l => d.append(el("div", "ad", "+ " + l)));
    if (e.removed.length + e.added.length) k.append(d);
    wrap.append(k);
  });
  return wrap;
}

function diffView(rows) {
  const pre = el("pre", "diff");
  if (!rows.some(r => r.t !== " ")) { pre.append(el("div", "gap", "The two versions are identical.")); return pre; }
  const keep = rows.map(() => false);
  rows.forEach((r, i) => { if (r.t !== " ") for (let k = Math.max(0, i - 2); k <= Math.min(rows.length - 1, i + 2); k++) keep[k] = true; });
  let skipped = 0;
  const gap = () => { if (skipped) { pre.append(el("div", "gap", "… " + skipped + " unchanged line" + (skipped > 1 ? "s" : ""))); skipped = 0; } };
  rows.forEach((r, i) => {
    if (!keep[i]) { skipped++; return; }
    gap(); pre.append(el("div", r.t === "-" ? "rm" : r.t === "+" ? "ad" : "", r.t + " " + r.s));
  });
  gap(); return pre;
}

function resultChips(res) {
  const c = el("div", "chips");
  c.append(el("span", "chip", res.problem_type === "structure" ? "Structure-level issue" : "Statement-level issue"));
  if (res.static_tools && res.static_tools.length) c.append(el("span", "chip teal", res.static_tools.join(" + ")));
  if (res.callees && res.callees.length) c.append(el("span", "chip teal", res.callees.length + " called function" + (res.callees.length > 1 ? "s" : "") + " in prompt"));
  if (!res.llm_used) c.append(el("span", "chip", "Heuristic mode"));
  return c;
}

/* Analyst feedback (enhancement 6): queued for review, never written straight into the knowledge base. */
function feedbackForm(opts) {
  const box = el("div", "fb");
  box.append(el("h3", "", opts.title), el("p", "hint", "Goes to a reviewer first. It joins the knowledge base only after approval."));
  let label = opts.kind === "pair" ? null : "";
  if (opts.kind === "single") {
    const seg = el("div", "seg"); seg.setAttribute("role", "radiogroup");
    [["vulnerable", "It is vulnerable"], ["safe", "It is safe"]].forEach(([val, text]) => {
      const l = el("label"); const i = el("input"); i.type = "radio"; i.name = "fb-" + opts.id; i.value = val;
      i.onchange = () => { label = val; send.disabled = false; };
      l.append(i, el("span", "", text)); seg.append(l);
    });
    box.append(seg);
  }
  const grid = el("div", "grid");
  const cwe = el("input"); cwe.type = "text"; cwe.placeholder = "CWE-120"; cwe.maxLength = 40; cwe.setAttribute("aria-label", "CWE id");
  const note = el("input"); note.type = "text"; note.placeholder = "Short note for the reviewer"; note.maxLength = 1000; note.setAttribute("aria-label", "Note for the reviewer");
  grid.append(cwe, note); box.append(grid);
  const send = el("button", "btn small", "Send for review"); send.type = "button"; send.style.marginTop = "10px";
  send.disabled = opts.kind === "single";
  send.onclick = () => run(send, "Sending…", async () => {
    await api("/api/feedback", { ...opts.payload(), label: label || undefined, cwe: cwe.value, note: note.value });
    box.replaceChildren(el("h3", "", "Sent for review"), el("p", "hint", "Thank you. A reviewer will check it before it reaches the knowledge base."));
    if (state.health && state.health.review_enabled) refreshReviewBadge();
  });
  box.append(send);
  return box;
}

/* ------------------------------------------------------------------ Detect */
function renderDetect(res, code) {
  const out = $("#out"); out.replaceChildren();
  const panel = el("div", "panel");
  const v = el("div", "verdict");
  const g = gauge(res.risk_score, state.threshold);
  const info = el("div");
  const badge = el("span", "badge");
  const cweChip = el("span", "chip hot");
  const chips = resultChips(res); chips.prepend(cweChip);
  const why = el("p", "", res.explanation || "");
  const note = el("p", "hint");
  info.append(badge, chips, why, note);
  const conf = el("p", "hint", "Retrieval confidence " + pct(res.retrieval_confidence));
  info.append(conf);
  if (res.doubtful) info.append(el("p", "warnline", "Weak match with the knowledge base. Treat this result as doubtful."));
  v.append(g, info); panel.append(v);

  const sig = section("Why this score", "each signal runs from 0 (looks safe) to 1 (looks vulnerable)");
  sig.append(signalRows(res.signals)); panel.append(sig);
  if (res.suspicious_lines.length) { const s = section("Suspicious lines"); res.suspicious_lines.forEach(l => s.append(el("pre", "", l))); panel.append(s); }
  if (res.static_findings.length) { const s = section("Static analyzer findings", res.static_tools.join(", ")); s.append(findingsList(res.static_findings)); panel.append(s); }
  if (res.callees.length) { const s = section("Called functions added to the prompt"); const c = el("div", "chips"); res.callees.forEach(n => c.append(el("span", "chip", n))); s.append(c); panel.append(s); }
  if (Object.keys(res.channel_contribution).length) { const s = section("Retrieval channels that mattered", "weighted reciprocal rank fusion"); s.append(channelBars(res.channel_contribution)); panel.append(s); }
  if (res.evidence.length) { const s = section("Closest historical cases"); s.append(evidenceCards(res.evidence)); panel.append(s); }
  const fb = el("div", "sec");
  fb.append(feedbackForm({
    id: "d", kind: "single", title: "Is this verdict wrong?",
    payload: () => ({ kind: "single", code, language: "c", model_verdict: flagged(res.risk_score) ? "Vulnerable" : "Fixed/Safe", risk_score: res.risk_score }),
  }));
  panel.append(fb);
  out.append(panel);

  state.updaters.detect = () => {
    const hit = flagged(res.risk_score);
    badge.className = "badge " + (hit ? "bad" : "ok"); badge.textContent = hit ? "Vulnerable" : "Fixed / safe";
    g.update(state.threshold);
    const cwe = res.cwe || (res.evidence[0] && res.evidence[0].cwe) || "";
    cweChip.hidden = !(hit && cwe); cweChip.textContent = cwe;
    note.textContent = "Risk score " + f2(res.risk_score) + " is " + (hit ? "at or above" : "below") + " the threshold of " + f2(state.threshold) + ".";
  };
  state.updaters.detect();
}
$("#sample").onclick = $("#sample2").onclick = () => { $("#code").value = SAMPLE; $("#code").focus(); };
function analyze() {
  const code = $("#code").value;
  if (!code.trim()) return toast("Paste a function first.", "error");
  return run($("#go"), "Analyzing…", async () => {
    const res = await api("/api/detect", { code, context: $("#ctx").value, use_static: $("#use-static").checked && !$("#use-static").disabled });
    renderDetect(res, code);
  });
}
$("#go").onclick = analyze;
$("#code").addEventListener("keydown", e => { if ((e.ctrlKey || e.metaKey) && e.key === "Enter") analyze(); });

/* ------------------------------------------------------------------ Scan file */
function loadFileText(file) {
  if (file.size > ((state.health && state.health.scan_limits.max_bytes) || 400000)) return toast("That file is larger than the scan limit.", "error");
  const r = new FileReader();
  r.onload = () => { $("#scode").value = String(r.result); $("#file-name").textContent = file.name; $("#file-hint").textContent = Math.round(file.size / 1024 * 10) / 10 + " KB loaded"; };
  r.readAsText(file);
}
$("#pick").onclick = () => $("#file").click();
$("#file").onchange = e => e.target.files[0] && loadFileText(e.target.files[0]);
$("#scan-sample").onclick = () => { $("#scode").value = SAMPLE_FILE; $("#file-name").textContent = "example.c"; $("#file-hint").textContent = "Four functions, two of them risky"; };
const drop = $("#drop");
["dragenter", "dragover"].forEach(ev => drop.addEventListener(ev, e => { e.preventDefault(); drop.classList.add("over"); }));
["dragleave", "drop"].forEach(ev => drop.addEventListener(ev, e => { e.preventDefault(); drop.classList.remove("over"); }));
drop.addEventListener("drop", e => e.dataTransfer.files[0] && loadFileText(e.dataTransfer.files[0]));

function scanRow(f, i) {
  const row = el("details", "fn");
  const sum = el("summary");
  const nm = el("span", "nm", f.name); nm.append(el("small", "", "lines " + f.start_line + "–" + f.end_line + (f.cwe ? "  ·  " + f.cwe : "")));
  const mt = el("div", "mt"); const meter = el("div", "meter"); const bar = el("i"); const mark = el("u"); meter.append(bar, mark);
  const sc = el("div", "score"); const scv = el("span", "", f2(f.risk_score)); sc.append(scv, el("span", "", f.doubtful ? "weak match" : ""));
  mt.append(meter, sc);
  const tag = el("span", "badge tag");
  sum.append(el("span", "rank", String(i + 1)), nm, mt, tag); row.append(sum);

  const body = el("div", "body");
  if (f.explanation) body.append(el("p", "hint", f.explanation));
  body.append(resultChips({ ...f, llm_used: true, static_tools: [], callees: f.callees }));
  const s = section("Why this score"); s.append(signalRows(f.signals)); body.append(s);
  if (f.static_findings.length) { const x = section("Static analyzer findings"); x.append(findingsList(f.static_findings)); body.append(x); }
  if (f.callees.length) { const x = section("Called functions added to the prompt"); const c = el("div", "chips"); f.callees.forEach(n => c.append(el("span", "chip", n))); x.append(c); body.append(x); }
  if (f.best_case) { const x = section("Closest historical case"); x.append(el("p", "hint", f.best_case.pair_id + (f.best_case.cwe ? " (" + f.best_case.cwe + ")" : "") + ": " + f.best_case.description)); body.append(x); }
  const x = section("Code" + (f.truncated ? " (truncated)" : "")); x.append(el("pre", "", f.code));
  const open = el("button", "btn ghost small", "Open in Detect"); open.type = "button";
  open.onclick = () => { $("#code").value = f.code; showTab("detect"); analyze(); };
  x.append(open); body.append(x);
  row.append(body);

  const update = () => {
    const hit = flagged(f.risk_score);
    bar.style.width = (f.risk_score * 100) + "%"; bar.className = hit ? "hot" : "";
    mark.style.left = "calc(" + (state.threshold * 100) + "% - 1px)";
    tag.className = "badge tag " + (hit ? "bad" : "ok"); tag.textContent = hit ? "Flagged" : "Clear";
    row.dataset.hit = hit ? "1" : "";
  };
  return { row, update };
}

function renderScan(data) {
  const box = $("#sout"); box.replaceChildren();
  const fns = data.functions, st = data.stats;
  if (!fns.length) {
    const e = el("div", "empty"); e.append(el("h3", "", "No functions found"),
      el("p", "", "The scanner reads function definitions at file level. Methods written inside C++ class bodies are skipped."));
    box.append(e); delete state.updaters.scan; return;
  }
  const panel = el("div", "panel");
  const sum = el("div", "summary");
  const stat = (v, label) => { const d = el("div", "stat"); const b = el("b", "", v); d.append(b, el("span", "", label)); sum.append(d); return b; };
  const flagB = stat("0", "flagged at this threshold");
  stat(st.functions_scanned + " of " + st.functions_found, "functions scanned");
  stat(st.seconds + " s", "scan time");
  sum.append(el("div", "spacer"));
  const only = el("label", "opt"); const onlyBox = el("input"); onlyBox.type = "checkbox"; only.append(onlyBox, el("span", "", "Flagged only"));
  const csv = el("button", "btn ghost small", "Export CSV"); csv.type = "button";
  const json = el("button", "btn ghost small", "Export JSON"); json.type = "button";
  sum.append(only, csv, json); panel.append(sum);
  const tools = st.static_tools.length ? st.static_tools.join(" + ") : "no static analyzer";
  panel.append(el("p", "hint", "Ranked by risk score. Analyzers: " + tools + (st.llm_used ? ", LLM on." : ", LLM off.")));
  if (st.not_scanned) panel.append(el("p", "warnline", st.not_scanned + " more function" + (st.not_scanned > 1 ? "s were" : " was") + " not scanned because of the function limit or time budget. Raise “Max functions” to include them."));
  const list = el("div"); list.style.marginTop = "10px";
  const rows = fns.map(scanRow); rows.forEach(r => list.append(r.row)); panel.append(list); box.append(panel);

  const update = () => {
    rows.forEach(r => r.update());
    flagB.textContent = String(fns.filter(f => flagged(f.risk_score)).length);
    rows.forEach(r => { r.row.hidden = onlyBox.checked && !r.row.dataset.hit; });
  };
  onlyBox.onchange = update;
  csv.onclick = () => {
    const q = s => '"' + String(s ?? "").replace(/"/g, '""') + '"';
    const lines = [["rank", "function", "start_line", "end_line", "risk_score", "flagged_at_" + f2(state.threshold), "cwe", "static_findings", "called_functions"].join(",")];
    fns.forEach((f, i) => lines.push([i + 1, q(f.name), f.start_line, f.end_line, f.risk_score, flagged(f.risk_score), q(f.cwe), f.static_findings.length, q(f.callees.join(" "))].join(",")));
    download("rasm-vul-scan.csv", "text/csv", lines.join("\n"));
  };
  json.onclick = () => download("rasm-vul-scan.json", "application/json", JSON.stringify(data, null, 2));
  state.updaters.scan = update; update();
}
$("#sgo").onclick = e => {
  const code = $("#scode").value;
  if (!code.trim()) return toast("Choose or paste a file first.", "error");
  run(e.currentTarget, "Scanning…", async () => {
    $("#scan-hint").textContent = "Analyzing functions. Large files can take a minute.";
    try {
      renderScan(await api("/api/scan-file", {
        code, language: /\.(cc|cpp|cxx|hpp)$/i.test($("#file-name").textContent) ? "c++" : "c",
        use_llm: $("#s-llm").checked && !$("#s-llm").disabled, use_static: $("#s-static").checked && !$("#s-static").disabled,
        with_context: $("#s-ctx").checked, max_functions: Math.max(1, Math.min(100, parseInt($("#s-max").value, 10) || 25)),
      }));
    } finally { $("#scan-hint").textContent = ""; }
  });
};

/* ------------------------------------------------------------------ Patch check */
const ICONS = {
  ok: "M5 12.5l4.2 4.2L19 7M12 2.8a9.2 9.2 0 1 0 0 18.4 9.2 9.2 0 0 0 0-18.4z",
  bad: "M12 8v5m0 3.5h.01M10.3 3.9 2.6 17.2a2 2 0 0 0 1.7 3h15.4a2 2 0 0 0 1.7-3L13.7 3.9a2 2 0 0 0-3.4 0z",
};
function patchVerdict(r) {
  const ov = flagged(r.old.risk_score), nv = flagged(r.new.risk_score), drop = r.old.risk_score - r.new.risk_score;
  if (ov && !nv) return ["ok", "Fix looks correct", "The old version is flagged and the patched version is not."];
  if (ov && nv) return ["bad", "Still looks vulnerable", "Both versions are flagged. The risk score " + (drop > 0.02 ? "dropped by " + f2(drop) + ", so the patch may help but is not enough." : "barely changed, so the patch probably does not address the issue.")];
  if (nv) return ["bad", "The patch may introduce a problem", "The old version is not flagged but the patched version is."];
  return ["warn", "Neither version is flagged", "At this threshold the old version does not look vulnerable, so the fix cannot be confirmed. Lower the threshold to be more sensitive."];
}
function renderPatch(r, oldCode, newCode) {
  const box = $("#pout"); box.replaceChildren();
  const banner = el("div", "banner"); const svgI = sv("svg", { viewBox: "0 0 24 24", "aria-hidden": "true" }); const path = sv("path"); svgI.append(path);
  const txt = el("div"); const h = el("h3"); const p = el("p"); txt.append(h, p); banner.append(svgI, txt); box.append(banner);
  const panel = el("div", "panel"); panel.style.marginTop = "16px";
  const two = el("div", "two");
  const g1 = gauge(r.old.risk_score, state.threshold), g2 = gauge(r.new.risk_score, state.threshold);
  [["Before", g1, r.old], ["After", g2, r.new]].forEach(([title, g, res]) => {
    const side = el("div"); const sg = el("div", "sidegauge"); sg.append(el("h3", "", title), g); side.append(sg);
    side.append(resultChips(res)); const s = section("Signals"); s.append(signalRows(res.signals)); side.append(s);
    if (res.static_findings.length) { const x = section("Static analyzer findings"); x.append(findingsList(res.static_findings.slice(0, 5))); side.append(x); }
    two.append(side);
  });
  panel.append(two);
  const d = section("Changes"); d.append(diffView(r.diff)); panel.append(d);
  const fb = el("div", "sec");
  fb.append(feedbackForm({ id: "p", kind: "pair", title: "Confirm this fix", payload: () => ({ kind: "pair", old_code: oldCode, new_code: newCode, language: "c", model_verdict: patchVerdict(r)[1], risk_score: r.old.risk_score }) }));
  panel.append(fb); box.append(panel);
  state.updaters.patch = () => {
    const [tone, title, msg] = patchVerdict(r);
    banner.className = "banner " + tone; path.setAttribute("d", ICONS[tone === "ok" ? "ok" : "bad"]);
    h.textContent = title; p.textContent = msg; g1.update(state.threshold); g2.update(state.threshold);
  };
  state.updaters.patch();
}
$("#psample").onclick = () => { $("#oldc").value = SAMPLE; $("#newc").value = SAMPLE_FIXED; };
$("#pgo").onclick = e => {
  const oldCode = $("#oldc").value, newCode = $("#newc").value;
  if (!oldCode.trim() || !newCode.trim()) return toast("Paste both versions first.", "error");
  run(e.currentTarget, "Checking…", async () => renderPatch(await api("/api/patch-check", { old_code: oldCode, new_code: newCode, use_static: !$("#use-static").disabled && $("#use-static").checked }), oldCode, newCode));
};

/* ------------------------------------------------------------------ Evaluation */
function metricsAt(vs, fs, t) {
  const tp = vs.filter(s => s >= t).length, fn = vs.length - tp, fp = fs.filter(s => s >= t).length, tn = fs.length - fp;
  const p = tp / Math.max(tp + fp, 1), r = tp / Math.max(tp + fn, 1);
  const fb = (b) => (1 + b * b) * p * r / Math.max(b * b * p + r, 1e-12);
  const ok = vs.reduce((n, v, i) => n + (v >= t && fs[i] < t ? 1 : 0), 0);
  return { tp, fn, fp, tn, precision: p, recall: r, f1: fb(1), f2: fb(2), accuracy: (tp + tn) / Math.max(tp + fn + fp + tn, 1), pair_accuracy: ok / Math.max(vs.length, 1) };
}
function evalChart(vs, fs) {
  const W = 640, H = 300, L = 44, R = 16, T = 14, B = 34, X = t => L + t * (W - L - R), Y = v => T + (1 - v) * (H - T - B);
  const svg = sv("svg", { viewBox: "0 0 " + W + " " + H, class: "chart", role: "img", "aria-label": "Precision and recall as the threshold moves from 0 to 1" });
  [0, 0.25, 0.5, 0.75, 1].forEach(v => {
    svg.append(sv("line", { x1: L, x2: W - R, y1: Y(v), y2: Y(v), class: "grid" }), sv("text", { x: L - 8, y: Y(v) + 4, "text-anchor": "end" }, pct(v)),
      sv("line", { x1: X(v), x2: X(v), y1: T, y2: H - B, class: "grid" }), sv("text", { x: X(v), y: H - B + 17, "text-anchor": "middle" }, f2(v)));
  });
  svg.append(sv("text", { x: (L + W - R) / 2, y: H - 3, "text-anchor": "middle" }, "decision threshold"));
  const pts = []; for (let i = 0; i <= 100; i++) pts.push([i / 100, metricsAt(vs, fs, i / 100)]);
  const line = (key, cls) => svg.append(sv("path", { class: cls, d: pts.map(([t, m], i) => (i ? "L" : "M") + X(t).toFixed(1) + " " + Y(m[key]).toFixed(1)).join(" ") }));
  line("f2", "l-f"); line("precision", "l-p"); line("recall", "l-r");
  const mk = sv("line", { y1: T, y2: H - B, class: "mk" }), dp = sv("circle", { r: 5, fill: "#22d3ee", stroke: "#07111f", "stroke-width": 2 }), dr = sv("circle", { r: 5, fill: "#2dd4bf", stroke: "#07111f", "stroke-width": 2 });
  svg.append(mk, dp, dr);
  svg.update = t => {
    const m = metricsAt(vs, fs, t);
    mk.setAttribute("x1", X(t)); mk.setAttribute("x2", X(t));
    dp.setAttribute("cx", X(t)); dp.setAttribute("cy", Y(m.precision)); dr.setAttribute("cx", X(t)); dr.setAttribute("cy", Y(m.recall));
  };
  return svg;
}
async function loadEval() {
  const box = $("#eout");
  if (state.evalData) return;
  box.textContent = "Loading evaluation…";
  try {
    const r = await api("/api/eval"); box.replaceChildren();
    if (r.status !== "complete") {
      const card = el("div", "panel"); card.append(el("h3", "", "Evaluation not available"), el("p", "hint", r.message || "Evaluation has not been run on this deployment."));
      const c = el("div", "chips"); c.append(el("span", "chip", "Test dataset: " + (r.dataset_available ? "available" : "missing")), el("span", "chip", "Knowledge-base pairs: " + (r.knowledge_base_pairs ?? 0)));
      card.append(c); box.append(card); return;
    }
    state.evalData = r;
    const has = r.scores && r.scores.vulnerable && r.scores.vulnerable.length;
    const panel = el("div", "panel");
    panel.append(el("p", "hint", "Dataset " + (r.dataset || "unknown") + ": " + r.pairs + " pairs, " + r.samples + " functions. Evaluated " + (r.evaluated_at || "unknown").slice(0, 10) + (r.threshold != null ? " at threshold " + f2(r.threshold) : "") + "."));
    const grid = el("div", "metrics"); grid.style.marginTop = "12px";
    const defs = [["precision", "Precision", 1], ["recall", "Recall", 1], ["f1", "F1 score"], ["f2", "F2 score"], ["accuracy", "Accuracy"], ["pair_accuracy", "Pair accuracy"]];
    const cells = {};
    defs.forEach(([k, label, key]) => { const m = el("div", "metric" + (key ? " key" : "")); const b = el("b"); m.append(b, el("span", "", label)); grid.append(m); cells[k] = b; });
    panel.append(grid);
    const cmHost = el("div"); let chart = null;
    if (has) {
      const s = section("Precision and recall by threshold", "moves with the slider above");
      chart = evalChart(r.scores.vulnerable, r.scores.fixed); s.append(chart);
      const lg = el("div", "legend"); [["", "Precision"], ["r", "Recall"], ["f", "F2"]].forEach(([c, t]) => { const x = el("span"); x.append(el("i", c), t); lg.append(x); });
      s.append(lg); panel.append(s);
    } else {
      panel.append(el("p", "warnline", "These results were saved without per-sample scores, so the slider cannot move them. Re-run the evaluation to enable the threshold curve."));
    }
    const cm = section("Confusion matrix"); cm.append(cmHost); panel.append(cm); box.append(panel);
    const draw = (m, labels) => {
      const t = el("table"); const head = el("tr"); head.append(el("th", "", "Actual \\ predicted"), el("th", "", "Vulnerable"), el("th", "", "Fixed / safe")); t.append(head);
      [["Vulnerable", m.tp, m.fn], ["Fixed / safe", m.fp, m.tn]].forEach(([n, a, b]) => { const tr = el("tr"); tr.append(el("th", "", n), el("td", "", String(a)), el("td", "", String(b))); t.append(tr); });
      cmHost.replaceChildren(t);
    };
    state.updaters.eval = () => {
      let m;
      if (has) { m = metricsAt(r.scores.vulnerable, r.scores.fixed, state.threshold); chart.update(state.threshold); }
      else { const c = r.confusion_matrix.matrix; m = { ...r, tp: c[0][0], fn: c[0][1], fp: c[1][0], tn: c[1][1] }; }
      defs.forEach(([k]) => { cells[k].textContent = typeof m[k] === "number" ? pct1(m[k]) : "n/a"; });
      draw(m);
    };
    state.updaters.eval();
  } catch (e) { box.textContent = "Could not load evaluation results: " + e.message; }
}

/* ------------------------------------------------------------------ Review (admin) */
const adminHeaders = () => { const t = store.sget("rasm.admin"); return t ? { "X-Admin-Token": t } : {}; };
function badgeCount(n) { const b = $("#review-count"); b.hidden = !n; b.textContent = n || ""; }
async function refreshReviewBadge() {
  if (!state.health || !state.health.review_enabled || !store.sget("rasm.admin")) return;
  try { badgeCount((await api("/api/feedback?status=pending", undefined, adminHeaders())).counts.pending || 0); } catch { /* token may be wrong */ }
}
async function loadReview() {
  const box = $("#rout"); box.replaceChildren();
  if (!state.health || !state.health.review_enabled) {
    const p = el("div", "empty"); p.append(el("h3", "", "Review is switched off"),
      el("p", "", "Set the ADMIN_TOKEN environment variable on the server to let a reviewer approve analyst feedback. Anyone can still send feedback from the Detect and Patch check tabs.")); box.append(p); return;
  }
  if (!store.sget("rasm.admin")) {
    const p = el("div", "panel"); p.style.maxWidth = "460px";
    const lab = el("label", "field-label", "Reviewer token"); lab.htmlFor = "tok";
    const inp = el("input"); inp.type = "password"; inp.id = "tok"; inp.autocomplete = "off";
    const go = el("button", "btn", "Unlock review"); go.style.marginTop = "12px";
    go.onclick = () => { store.sset("rasm.admin", inp.value.trim()); loadReview(); };
    inp.onkeydown = e => { if (e.key === "Enter") go.click(); };
    p.append(lab, inp, go); box.append(p); return;
  }
  let data;
  try { data = await api("/api/feedback?status=pending", undefined, adminHeaders()); }
  catch (e) { if (e.status === 401) { store.sset("rasm.admin", null); toast("That token was not accepted.", "error"); return loadReview(); } box.textContent = e.message; return; }
  badgeCount(data.counts.pending || 0);
  const head = el("div", "summary");
  [[data.counts.pending || 0, "waiting for review"], [(data.counts.approved || 0) + (data.counts.approved_labelled || 0), "approved"], [data.counts.rejected || 0, "rejected"], [data.kb_pairs, "pairs in the knowledge base"]]
    .forEach(([v, l]) => { const d = el("div", "stat"); d.append(el("b", "", String(v)), el("span", "", l)); head.append(d); });
  head.append(el("div", "spacer")); const lock = el("button", "btn ghost small", "Lock"); lock.onclick = () => { store.sset("rasm.admin", null); badgeCount(0); loadReview(); }; head.append(lock);
  box.append(head);
  if (!data.items.length) { const e = el("div", "empty"); e.append(el("h3", "", "Nothing to review"), el("p", "", "New analyst feedback appears here.")); box.append(e); return; }
  data.items.forEach(it => box.append(reviewItem(it)));
}
function reviewItem(it) {
  const card = el("div", "rv"); const head = el("div", "rv-head");
  head.append(el("span", "chip teal", it.kind === "pair" ? "Confirmed fix" : "Single function"));
  if (it.kind === "single") head.append(el("span", "badge " + (it.label === "vulnerable" ? "bad" : "ok"), it.label === "vulnerable" ? "Analyst: vulnerable" : "Analyst: safe"));
  if (it.model_verdict) head.append(el("span", "chip", "Model said: " + it.model_verdict + (it.risk_score != null ? " (" + f2(it.risk_score) + ")" : "")));
  head.append(el("time", "", it.created_at.replace("T", " ").slice(0, 16) + " UTC")); card.append(head);
  if (it.note) card.append(el("p", "", it.note));
  if (it.kind === "pair") { const t = el("div", "two"); t.append(el("pre", "", it.old_code), el("pre", "", it.new_code)); card.append(t); } else card.append(el("pre", "", it.code));
  const acts = el("div", "rv-actions");
  const cwe = el("input"); cwe.type = "text"; cwe.value = it.cwe || ""; cwe.placeholder = "CWE"; cwe.style.width = "120px"; cwe.setAttribute("aria-label", "CWE id");
  let counter = null;
  if (it.kind === "single") {
    const w = el("div", "grow"); counter = el("textarea"); counter.rows = 3; counter.placeholder = it.label === "vulnerable" ? "Paste the FIXED version to add this to the knowledge base (optional)" : "Paste the VULNERABLE version to add this to the knowledge base (optional)"; w.append(counter); acts.append(w);
  }
  const ok = el("button", "btn small", "Approve"), no = el("button", "btn danger small", "Reject");
  acts.append(cwe, ok, no); card.append(acts);
  if (it.kind === "single") card.append(el("p", "hint", "Without a counterpart the example is kept as a labelled example only, because the knowledge base is built from vulnerable and fixed pairs."));
  ok.onclick = () => run(ok, "Approving…", async () => {
    const r = await api("/api/feedback/" + it.id + "/approve", { counterpart: counter ? counter.value : null, cwe: cwe.value }, adminHeaders());
    toast(r.item.status === "approved" ? "Added to the knowledge base (" + r.kb_pairs + " pairs now)." : "Kept as a labelled example."); loadReview();
  });
  no.onclick = () => run(no, "Rejecting…", async () => { await api("/api/feedback/" + it.id + "/reject", {}, adminHeaders()); toast("Rejected."); loadReview(); });
  return card;
}

/* ------------------------------------------------------------------ start-up */
function renderStatus(h) {
  const box = $("#status"); box.replaceChildren();
  if (!h) { box.append(el("div", "", "Server not reachable")); return; }
  const line = (label, value, on) => { const d = el("div"); const l = el("span"); if (on !== undefined) l.append(el("i", "dot" + (on ? " on" : ""))); l.append(label); d.append(l, el("b", "", value)); box.append(d); };
  line("Knowledge base", h.kb_pairs + " pairs"); line("Embedder", h.embedder);
  line("LLM", h.llm ? "on" : "off", h.llm);
  line("flawfinder", h.static_tools.flawfinder ? "found" : "missing", h.static_tools.flawfinder);
  line("cppcheck", h.static_tools.cppcheck ? "found" : "missing", h.static_tools.cppcheck);
}
function disableOpt(id, optId, note) { $(id).checked = false; $(id).disabled = true; $(optId).classList.add("off"); $(optId).title = note; }
async function init() {
  try { state.health = await api("/api/health"); } catch { state.health = null; }
  const h = state.health;
  renderStatus(h);
  if (h) {
    state.defaultThr = h.threshold;
    if (!h.static_tools.flawfinder && !h.static_tools.cppcheck) {
      disableOpt("#use-static", "#static-opt", "Install flawfinder or cppcheck on the server to enable this");
      disableOpt("#s-static", "#s-static-opt", "Install flawfinder or cppcheck on the server to enable this");
      $("#static-opt span").textContent = "Add flawfinder / cppcheck findings (not installed on this server)";
    }
    if (!h.llm) { disableOpt("#s-llm", "#s-llm-opt", "No LLM is configured on the server"); }
    $("#s-max").max = h.scan_limits.max_functions;
  }
  const saved = parseFloat(store.get("rasm.threshold"));
  setThreshold(Number.isFinite(saved) ? saved : state.defaultThr, false);
  showTab(location.hash.slice(1) || "detect");
  refreshReviewBadge();
}
window.addEventListener("hashchange", () => showTab(location.hash.slice(1)));
init();
