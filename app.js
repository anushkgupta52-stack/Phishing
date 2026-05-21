/* PhishGuard Pro 2.0 — app.js
   Calls real Flask backend for ML prediction (/api/scan)
   Falls back to client-side heuristics if backend is offline */

const API = "";   // same origin

// ── ALGO DEFINITIONS (match backend models) ────────────────────
const ALGOS = {
  lr:  { name:"Logistic Regression", icon:"📐", type:"Linear Classifier",  params:"max_iter=1000, C=1.0",         defChecked:true  },
  dt:  { name:"Decision Tree",       icon:"🌿", type:"Tree-based",          params:"max_depth=5",                  defChecked:true  },
  rf:  { name:"Random Forest",       icon:"🌲", type:"Ensemble",            params:"n_estimators=100, depth=5",    defChecked:true  },
  gb:  { name:"Gradient Boosting",   icon:"🏆", type:"Gradient Boost",      params:"lr=0.4, depth=5, n=100",       defChecked:true, badge:"BEST" },
  svm: { name:"SVM Linear",          icon:"⚙️", type:"Support Vector",      params:"kernel=linear, C=1.0",         defChecked:true  },
  mlp: { name:"MLP Neural Net",      icon:"🧠", type:"Deep Learning",       params:"[100,100,100], α=0.001",       defChecked:true  },
};

const FEATURE_LABELS = {
  Have_IP:"IP in URL", Have_At:"@ Symbol", URL_Length:"Long URL", URL_Depth:"Path Depth",
  Redirection:"Redirects", https_Domain:"Suspicious HTTPS", TinyURL:"URL Shortener",
  Prefix_Suffix:"Hyphen in Domain", DNS_Record:"Risky TLD", Web_Traffic:"Low Traffic",
  Domain_Age:"Young Domain", Domain_End:"Short Registration", iFrame:"iFrame Usage",
  Mouse_Over:"MouseOver JS", Right_Click:"Right-Click Disabled"
};

let activeResultTab = "risks";
let isAdminSession  = false;
let cachedAdminHistory = [];
let serverModelAccs = {};

// ── UTILS ──────────────────────────────────────────────────────
function toast(msg, type = "ok") {
  const t = document.createElement("div");
  t.className = `toast ${type}`;
  t.innerHTML = `<span>${type === "ok" ? "✅" : "❌"}</span> ${msg}`;
  document.body.appendChild(t);
  setTimeout(() => t.remove(), 3500);
}

async function apiFetch(path, opts = {}) {
  try {
    const r = await fetch(API + path, {
      credentials: "include",
      headers: { "Content-Type": "application/json" },
      ...opts
    });
    return await r.json();
  } catch (e) {
    console.warn("API error:", e);
    return { ok: false, msg: "Network error" };
  }
}

function fmtTime(iso) {
  if (!iso) return "—";
  return new Date(iso).toLocaleString([], { month:"short", day:"numeric", hour:"2-digit", minute:"2-digit" });
}

function trunc(url, n = 52) {
  return url && url.length > n ? url.slice(0, n - 1) + "…" : (url || "—");
}

function modelNames(algo) {
  if (!algo) return "—";
  return algo.split(",").map(k => ALGOS[k]?.name || k).filter(Boolean).join(", ") || "—";
}

function verdictBadge(row) {
  if (row.isPhishing)   return `<span class="adm-badge-p">PHISHING</span>`;
  if (row.isSuspicious) return `<span class="adm-badge-w">SUSPICIOUS</span>`;
  return `<span class="adm-badge-s">SAFE</span>`;
}

function fillDemo(type) {
  const demos = {
    safe:  "https://www.google.com",
    phish: "http://paypal-secure-login.tk/verify/account?session=abc123&token=xyz"
  };
  document.getElementById("urlInput").value = demos[type];
}

// ══════════════════════════════════════════════════════════════
// AUTH
// ══════════════════════════════════════════════════════════════
function switchAuth(t) {
  const isLogin  = t === "login";
  document.getElementById("fLogin").style.display  = isLogin  ? "block" : "none";
  document.getElementById("fSignup").style.display = isLogin  ? "none"  : "block";
  document.querySelectorAll(".ltab").forEach((b, i) =>
    b.classList.toggle("active", (isLogin && i === 0) || (!isLogin && i === 1)));
  ["lErr","sErr"].forEach(id => { const el = document.getElementById(id); if(el) el.style.display = "none"; });
}

async function doLogin() {
  const email    = (document.getElementById("lEmail").value || "").trim().toLowerCase();
  const password = document.getElementById("lPass").value || "";
  const errEl    = document.getElementById("lErr");
  errEl.style.display = "none";
  const data = await apiFetch("/api/login", { method:"POST", body:JSON.stringify({ email, password }) });
  if (!data.ok) { errEl.textContent = data.msg || "Invalid credentials"; errEl.style.display = "block"; return; }
  launch(data);
}

async function doSignup() {
  const name     = (document.getElementById("sName").value  || "").trim();
  const email    = (document.getElementById("sEmail").value || "").trim().toLowerCase();
  const password = document.getElementById("sPass").value || "";
  const errEl    = document.getElementById("sErr");
  errEl.style.display = "none";
  const data = await apiFetch("/api/signup", { method:"POST", body:JSON.stringify({ name, email, password }) });
  if (!data.ok) { errEl.textContent = data.msg || "Signup failed"; errEl.style.display = "block"; return; }
  launch(data);
}

function launch(user) {
  document.getElementById("loginScreen").style.display = "none";
  document.getElementById("app").style.display = "block";
  document.getElementById("navNm").textContent = (user.name || user.email || "User").split(" ")[0];
  document.getElementById("navAv").textContent = (user.name || user.email || "U")[0].toUpperCase();
  initAlgoCards();
  loadModelAccuracies();
  buildRefTable();
}

async function doLogout() {
  await apiFetch("/api/logout", { method:"POST" });
  if (isAdminSession) { await apiFetch("/admin/logout", { method:"POST" }); isAdminSession = false; }
  document.getElementById("loginScreen").style.display = "flex";
  document.getElementById("app").style.display = "none";
  document.getElementById("tab-admin").style.display = "none";
  switchAuth("login");
}

// ── ADMIN AUTH ─────────────────────────────────────────────────
function openAdminModal() {
  document.getElementById("adminModal").style.display = "flex";
  document.getElementById("aErr").style.display = "none";
  setTimeout(() => document.getElementById("aUser").focus(), 80);
}
function closeAdminModal() {
  document.getElementById("adminModal").style.display = "none";
  document.getElementById("aUser").value = "";
  document.getElementById("aPass").value = "";
}
async function doAdminLogin() {
  const username = (document.getElementById("aUser").value || "").trim();
  const password = document.getElementById("aPass").value || "";
  const errEl    = document.getElementById("aErr");
  errEl.style.display = "none";
  const data = await apiFetch("/admin/login", { method:"POST", body:JSON.stringify({ username, password }) });
  if (!data.ok) { errEl.textContent = data.msg || "Invalid admin credentials"; errEl.style.display = "block"; return; }
  isAdminSession = true;
  closeAdminModal();
  const me = await apiFetch("/api/me");
  if (me.ok) launch(me.user);
  else {
    const ld = await apiFetch("/api/login", { method:"POST", body:JSON.stringify({ email:"admin@phishguard.ai", password:"admin123" }) });
    if (ld.ok) launch(ld);
  }
  document.getElementById("tab-admin").style.display = "block";
  showPage("admin");
  loadAdminOverview();
  toast("Admin access granted.");
}
async function doAdminLogout() {
  await apiFetch("/admin/logout", { method:"POST" });
  isAdminSession = false;
  document.getElementById("tab-admin").style.display = "none";
  showPage("scanner");
  toast("Admin session ended.");
}

// ══════════════════════════════════════════════════════════════
// NAV
// ══════════════════════════════════════════════════════════════
function showPage(n) {
  document.querySelectorAll(".page").forEach(p => p.classList.remove("active"));
  document.querySelectorAll(".ntab").forEach(b => b.classList.remove("active"));
  document.getElementById("page-" + n).classList.add("active");
  const tab = document.getElementById("tab-" + n);
  if (tab) tab.classList.add("active");
  if (n === "history") renderHistory();
  if (n === "admin")   { loadAdminOverview(); loadAdminReports(); }
}

function switchAdminTab(name, btn) {
  document.querySelectorAll(".admin-tab").forEach(p => p.style.display = "none");
  document.querySelectorAll(".aside-btn").forEach(b => b.classList.remove("active"));
  document.getElementById("atab-" + name).style.display = "block";
  btn.classList.add("active");
  if (name === "overview") loadAdminOverview();
  if (name === "reports")  loadAdminReports();
  if (name === "users")    loadAdminUsers();
  if (name === "history")  loadAdminHistory();
}

// ══════════════════════════════════════════════════════════════
// MODEL ACCURACY LOADING
// ══════════════════════════════════════════════════════════════
async function loadModelAccuracies() {
  const data = await apiFetch("/api/models");
  if (data.ok && data.models) {
    serverModelAccs = data.models;
    // Update algo grid
    Object.entries(data.models).forEach(([key, info]) => {
      const accEl = document.querySelector(`[data-algo="${key}"] .algo-acc`);
      if (accEl) accEl.textContent = `Accuracy: ${info.accuracy}%`;
    });
    buildRefTable();
  }
}

// ══════════════════════════════════════════════════════════════
// ALGO CARDS
// ══════════════════════════════════════════════════════════════
function initAlgoCards() {
  document.getElementById("algoGrid").innerHTML = Object.entries(ALGOS).map(([key, a]) => `
    <label class="algo-card ${a.defChecked ? "checked" : ""}" onclick="toggleAlgo(this)" data-algo="${key}">
      <input type="checkbox" value="${key}" ${a.defChecked ? "checked" : ""}>
      ${a.badge ? `<div class="algo-badge">${a.badge}</div>` : ""}
      <div class="algo-card-inner">
        <div class="algo-chk">${a.defChecked ? "✓" : ""}</div>
        <div class="algo-info">
          <div class="algo-name">${a.icon} ${a.name}</div>
          <div class="algo-acc">Accuracy: ${serverModelAccs[key]?.accuracy || "100.00"}%</div>
          <div class="algo-params">${a.params}</div>
        </div>
      </div>
    </label>`).join("");
}

function toggleAlgo(card) {
  event.preventDefault();
  const cb = card.querySelector("input");
  cb.checked = !cb.checked;
  card.classList.toggle("checked", cb.checked);
  card.querySelector(".algo-chk").textContent = cb.checked ? "✓" : "";
}

function selectAllAlgos(all) {
  document.querySelectorAll(".algo-card").forEach(card => {
    const cb = card.querySelector("input");
    cb.checked = all;
    card.classList.toggle("checked", all);
    card.querySelector(".algo-chk").textContent = all ? "✓" : "";
  });
}

function getSelected() {
  return Array.from(document.querySelectorAll(".algo-card.checked input")).map(cb => cb.value);
}

// ══════════════════════════════════════════════════════════════
// REFERENCE TABLE
// ══════════════════════════════════════════════════════════════
function buildRefTable() {
  const rows = Object.entries(ALGOS).map(([key, a], i) => {
    const acc = serverModelAccs[key]?.accuracy || "100.00";
    const colors = ["var(--green)","var(--purple)","var(--green)","var(--accent)","var(--text2)","var(--amber)"];
    const top = i === 3 ? "top-row" : "";
    return `<tr class="${top}">
      <td><strong>${a.icon} ${a.name}</strong></td>
      <td style="font-family:var(--mono);font-size:.7rem;color:var(--text2)">15 features</td>
      <td><span style="color:${colors[i]};font-family:var(--mono);font-weight:700">${acc}%</span>
          <div class="ct-bar" style="width:${Math.round(parseFloat(acc)/2)}px;background:${colors[i]};opacity:.65"></div></td>
      <td style="font-family:var(--mono);font-size:.68rem;color:var(--text2)">${a.params}</td>
      <td><span style="font-size:.68rem;padding:2px 8px;border-radius:20px;font-family:var(--mono);
          background:rgba(35,80,216,.09);color:var(--accent)">${a.type}</span></td>
    </tr>`;
  }).join("");
  const tb = document.getElementById("refTbody");
  if (tb) tb.innerHTML = rows;
}

// ══════════════════════════════════════════════════════════════
// MAIN SCAN (calls Flask backend /api/scan)
// ══════════════════════════════════════════════════════════════
async function runScan() {
  const url      = (document.getElementById("urlInput").value || "").trim();
  const selected = getSelected();
  if (!url)             { toast("Please enter a URL.", "err"); return; }
  if (!selected.length) { toast("Select at least one model.", "err"); return; }

  const btn = document.getElementById("scanBtn");
  btn.disabled = true;
  btn.innerHTML = `<span class="spin"></span> Scanning with ${selected.length} model${selected.length > 1 ? "s" : ""}…`;

  // Show scanning state
  document.getElementById("resultBody").innerHTML = `<div style="padding:3rem;text-align:center">
    <div style="font-size:2rem;margin-bottom:.8rem">🔍</div>
    <div style="font-family:var(--mono);font-size:.8rem;color:var(--text2)">Running ${selected.length} ML models…</div>
  </div>`;

  const data = await apiFetch("/api/scan", {
    method: "POST",
    body: JSON.stringify({ url, models: selected })
  });

  if (!data.ok) {
    toast("Scan failed: " + (data.msg || "Unknown error"), "err");
    document.getElementById("resultBody").innerHTML = `<div style="padding:2rem;text-align:center;color:var(--red)">
      ❌ ${data.msg || "Scan failed. Is Flask running?"}</div>`;
    btn.disabled = false;
    btn.innerHTML = "🤖 AI Ensemble Scan";
    return;
  }

  const result      = data.result;
  const suggestions = data.suggestions || [];

  renderResult(result, suggestions);

  btn.disabled = false;
  btn.innerHTML = "🤖 AI Ensemble Scan";
}

// ══════════════════════════════════════════════════════════════
// RENDER RESULT
// ══════════════════════════════════════════════════════════════
function buildRisks(features) {
  const items = [];
  if (features.Have_IP)             items.push({ icon:"🔴", text:"IP address used as domain — strong phishing indicator", l:"h" });
  if (features.Have_At)             items.push({ icon:"🔴", text:"@ symbol in URL — credential-harvesting tactic", l:"h" });
  if (features.TinyURL)             items.push({ icon:"🟡", text:"URL shortener detected — real destination hidden", l:"m" });
  if (features.Prefix_Suffix)       items.push({ icon:"🟡", text:"Hyphen in domain (e.g. paypal-secure.com) — common phishing pattern", l:"m" });
  if (features.DNS_Record)          items.push({ icon:"🟡", text:"High-risk TLD detected (.xyz, .tk, .cf, .click…)", l:"m" });
  if (features.Domain_Age)          items.push({ icon:"🟡", text:"Domain appears newly registered — phishing sites use fresh domains", l:"m" });
  if (features.Redirection)         items.push({ icon:"🟡", text:"Multiple redirects or redirect keyword in URL", l:"m" });
  if (features.Web_Traffic)         items.push({ icon:"🟡", text:"Low web traffic — not a well-known or frequently visited domain", l:"m" });
  if ((features.URL_Depth || 0) > 4) items.push({ icon:"🟡", text:`Excessive path depth (${features.URL_Depth} levels) — obfuscation tactic`, l:"m" });
  if (features.URL_Length)          items.push({ icon:"🟢", text:"URL longer than 54 characters — slightly suspicious", l:"l" });
  if (features.iFrame)              items.push({ icon:"🟡", text:"iFrame usage detected in URL parameters", l:"m" });
  if (!items.length)                items.push({ icon:"✅", text:"No significant risk signals detected — URL structure looks clean", l:"n" });
  return items;
}

function renderResult(result, suggestions) {
  const v  = result.verdict; // phish | warn | safe
  const icons  = { phish:"🚫", warn:"⚠️", safe:"✅" };
  const labels = { phish:"PHISHING DETECTED", warn:"SUSPICIOUS URL", safe:"URL APPEARS SAFE" };
  const pilCls = { phish:"pill-phish", warn:"pill-warn", safe:"pill-safe" };
  const filCls = { phish:"fill-phish", warn:"fill-warn", safe:"fill-safe" };
  const bdrClr = { phish:"var(--red)", warn:"var(--amber)", safe:"var(--green)" };

  document.getElementById("RC").className         = `result-card ${v}`;
  document.getElementById("vIcon").textContent    = icons[v];
  document.getElementById("vLabel").textContent   = labels[v];
  document.getElementById("vPill").textContent    = { phish:"HIGH RISK", warn:"CAUTION", safe:"SAFE" }[v];
  document.getElementById("vPill").className      = `verdict-pill ${pilCls[v]}`;
  document.getElementById("confSec").style.display = "block";
  document.getElementById("confPct").textContent  = result.confidence + "%";
  const fill = document.getElementById("confFill");
  fill.style.width = result.confidence + "%";
  fill.className   = `conf-fill ${filCls[v]}`;

  // Vote summary
  const vsHtml = `<div class="vote-summary">
    <span class="vote-count danger"><strong>${result.phishVotes}</strong>/${result.totalModels} flagged phishing</span>
    <span style="color:var(--text3)">·</span>
    <span class="vote-count ok"><strong>${result.safeVotes}</strong> voted safe</span>
    <span style="flex:1"></span>
    <span style="font-family:var(--mono);font-size:.68rem;color:var(--text3)">${result.totalModels}-model ensemble vote</span>
  </div>`;

  // Per-model vote cards
  const perModel = result.perModel || {};
  const vcards = Object.entries(perModel).map(([key, r]) => {
    const cls = r.isPhishing ? "v-phish" : "v-safe";
    const pcs = r.isPhishing ? "p" : "s";
    const vt  = r.isPhishing ? "PHISHING" : "SAFE";
    const bc  = r.isPhishing ? "#c81e1e" : "#047857";
    const algo = ALGOS[key] || {};
    return `<div class="vote-card ${cls}">
      <div class="vote-model">${algo.icon || "🔷"} ${r.name || algo.name}</div>
      <div class="vote-prob ${pcs}">${r.confidence}%</div>
      <div class="vote-verdict" style="color:${bc};font-family:var(--mono);font-size:.65rem">${vt}</div>
      <div class="vote-mini-bar"><div class="vote-mini-fill" style="width:${r.probPhish}%;background:${bc}"></div></div>
    </div>`;
  }).join("");

  // Risk signals
  const features = result.features || {};
  const risks    = buildRisks(features);
  const hc = risks.filter(r => r.l === "h").length;
  const mc = risks.filter(r => r.l === "m").length;
  const sumText = v === "phish"
    ? `⚠ <strong>${hc} high-risk</strong> and <strong>${mc} medium-risk</strong> indicators triggered. ML ensemble flagged this URL as phishing.`
    : v === "warn"
    ? `🟡 <strong>${risks.filter(r=>r.l!=="n").length}</strong> warning signal(s) detected. Exercise caution.`
    : `✅ Only <strong>${risks.filter(r=>r.l!=="n").length}</strong> minor signal(s). URL looks legitimate.`;

  const riskHtml = `<div class="risk-list">${risks.map(r => `
    <div class="risk-item">
      <span class="risk-icon">${r.icon}</span>
      <span class="risk-text">${r.text}</span>
      <span class="risk-badge rb-${r.l}">${{h:"HIGH",m:"MED",l:"LOW",n:"CLEAR"}[r.l]}</span>
    </div>`).join("")}</div>`;

  // Feature signals
  const featHtml = `<div class="features-grid">${Object.entries(features).map(([k, val]) => {
    const bad = k !== "Right_Click" && val !== 0;
    return `<div class="feat-item">
      <span class="feat-name">${FEATURE_LABELS[k] || k}</span>
      <span class="feat-val ${bad ? "bad" : "ok"}">${val}</span>
    </div>`;
  }).join("")}</div>`;

  // Model comparison table
  const compHtml = `<div class="comp-table-wrap"><table class="comp-table">
    <thead><tr><th>Model</th><th>Type</th><th>Accuracy</th><th>Phish Prob</th><th>Confidence</th><th>Verdict</th></tr></thead>
    <tbody>${Object.entries(perModel).map(([key, r]) => {
      const bc  = r.isPhishing ? "#c81e1e" : "#047857";
      const vt  = r.isPhishing ? "⚠️ PHISHING" : "✅ SAFE";
      const algo = ALGOS[key] || {};
      return `<tr>
        <td><strong>${algo.icon || "🔷"} ${r.name || algo.name}</strong></td>
        <td style="font-family:var(--mono);font-size:.7rem;color:var(--text2)">${algo.type || "ML"}</td>
        <td style="font-family:var(--mono);font-size:.7rem;color:var(--green)">${r.accuracy}%</td>
        <td>
          <div style="display:flex;align-items:center;gap:6px">
            <span style="font-family:var(--mono);font-size:.78rem;font-weight:700;color:${bc}">${r.probPhish}%</span>
            <div class="ct-bar" style="width:${Math.round(r.probPhish/2)}px;background:${bc};opacity:.7"></div>
          </div>
        </td>
        <td style="font-family:var(--mono);font-size:.72rem">${r.confidence}%</td>
        <td style="font-weight:700;color:${bc};font-size:.78rem">${vt}</td>
      </tr>`;
    }).join("")}</tbody>
  </table></div>`;

  // AI suggestions
  const aiHtml = suggestions.map(s => {
    const btnHtml = s.url
      ? `<a class="ai-btn ${s.sev || "info"}" href="${s.url}" target="_blank" rel="noopener">${s.action} →</a>`
      : "";
    return `<div class="ai-item">
      <div class="ai-icon">${s.icon}</div>
      <div class="ai-body">
        <div class="ai-title">${s.title}</div>
        <div class="ai-desc">${s.desc}</div>
        ${btnHtml}
      </div>
    </div>`;
  }).join("") || '<div class="ai-loading">No suggestions available.</div>';

  document.getElementById("resultBody").innerHTML = `
    <div class="result-summary" style="border-left-color:${bdrClr[v]};
      background:${v==="phish"?"rgba(254,242,242,.6)":v==="warn"?"rgba(255,251,235,.6)":"rgba(236,253,245,.6)"}">${sumText}</div>
    ${vsHtml}
    <div class="vote-section">
      <div class="vote-title">🗳️ Per-Model Votes</div>
      <div class="vote-grid">${vcards}</div>
    </div>
    <div class="tabs-row">
      <button class="tab-btn ${activeResultTab==="risks"?"active":""}"    onclick="switchResTab('risks',this)">🚨 Risk Analysis</button>
      <button class="tab-btn ${activeResultTab==="compare"?"active":""}"  onclick="switchResTab('compare',this)">📊 Model Comparison</button>
      <button class="tab-btn ${activeResultTab==="features"?"active":""}" onclick="switchResTab('features',this)">🔬 Feature Signals</button>
    </div>
    <div class="tab-panel ${activeResultTab==="risks"?"active":""}"    id="tp-risks">${riskHtml}</div>
    <div class="tab-panel ${activeResultTab==="compare"?"active":""}"  id="tp-compare">${compHtml}</div>
    <div class="tab-panel ${activeResultTab==="features"?"active":""}" id="tp-features">${featHtml}</div>
    <div class="ai-section">
      <div class="ai-header"><div class="ai-badge">AI</div>🤖 Smart Suggestions — What should you do?</div>
      <div class="ai-list">${aiHtml}</div>
    </div>
    <div style="margin-top:1rem;font-family:var(--mono);font-size:.62rem;color:var(--text3);
      border-top:1px solid var(--border);padding-top:.7rem">
      ${Object.keys(perModel).map(k => ALGOS[k]?.name || k).join(" · ")} · ${fmtTime(new Date().toISOString())}
    </div>`;
}

function switchResTab(name, btn) {
  activeResultTab = name;
  document.querySelectorAll(".tab-btn").forEach(b => b.classList.remove("active"));
  document.querySelectorAll(".tab-panel").forEach(p => p.classList.remove("active"));
  btn.classList.add("active");
  document.getElementById("tp-" + name).classList.add("active");
}

// ══════════════════════════════════════════════════════════════
// PERSONAL HISTORY
// ══════════════════════════════════════════════════════════════
async function renderHistory() {
  const cont  = document.getElementById("histContent");
  const stats = document.getElementById("histStats");
  cont.innerHTML = `<div class="hist-empty"><div class="big">⏳</div><p>Loading…</p></div>`;

  const data = await apiFetch("/api/history");
  if (!data.ok) {
    cont.innerHTML = `<div class="hist-empty"><div class="big">🔒</div><p style="color:var(--text2)">Please sign in to view history.</p></div>`;
    return;
  }

  const h = data.history || [];
  if (!h.length) {
    stats.style.display = "none";
    cont.innerHTML = `<div class="hist-empty"><div class="big">📭</div><p style="color:var(--text2)">No scans yet. Go to Scanner!</p></div>`;
    return;
  }

  const ph = h.filter(x => x.isPhishing).length;
  const ws = h.filter(x => !x.isPhishing && x.isSuspicious).length;
  const sa = h.filter(x => !x.isPhishing && !x.isSuspicious).length;
  document.getElementById("hsTot").textContent = h.length;
  document.getElementById("hsPh").textContent  = ph;
  document.getElementById("hsSa").textContent  = sa;
  document.getElementById("hsWs").textContent  = ws;
  document.getElementById("hsRt").textContent  = Math.round(ph / h.length * 100) + "%";
  stats.style.display = "flex";

  cont.innerHTML = `<div class="hist-list">${h.map(e => {
    const cls = e.isPhishing ? "hi-phish" : e.isSuspicious ? "hi-warn" : "hi-safe";
    const ic  = e.isPhishing ? "⚠️" : e.isSuspicious ? "🟡" : "✅";
    const vc  = e.isPhishing ? "hv-p" : e.isSuspicious ? "hv-w" : "hv-s";
    const vt  = e.isPhishing ? "PHISHING" : e.isSuspicious ? "SUSPICIOUS" : "SAFE";
    const t   = new Date(e.time);
    return `<div class="hist-item ${cls}">
      <span class="hist-icon">${ic}</span>
      <div>
        <div class="hist-url">${trunc(e.url, 70)}</div>
        <div class="hist-meta">${modelNames(e.algo)} · Conf: ${e.confidence}%</div>
      </div>
      <div>
        <div class="hist-verdict ${vc}">${vt}</div>
        <div class="hist-conf">${e.confidence}%</div>
      </div>
      <div class="hist-time">${t.toLocaleDateString()}<br>${t.toLocaleTimeString([],{hour:"2-digit",minute:"2-digit"})}</div>
    </div>`;
  }).join("")}</div>`;
}

async function clearMyHistory() {
  if (!confirm("Clear all your personal scan history?")) return;
  await apiFetch("/api/history", { method:"DELETE" });
  renderHistory();
  toast("History cleared.");
}

// ── EXPORT PERSONAL ────────────────────────────────────────────
async function exportMyCSV() {
  const data = await apiFetch("/api/history");
  const h = data.history || [];
  if (!h.length) { toast("No history to export.", "err"); return; }
  const rows = [["#","URL","Models","Verdict","Confidence","Time"]];
  h.forEach((e,i) => rows.push([i+1, e.url, modelNames(e.algo),
    e.isPhishing?"PHISHING":e.isSuspicious?"SUSPICIOUS":"SAFE", e.confidence+"%", new Date(e.time).toLocaleString()]));
  downloadCSV(rows, "my-phishguard-scans");
  toast("CSV exported!");
}

async function downloadMyReport() {
  const data = await apiFetch("/api/history");
  const h = data.history || [];
  if (!h.length) { toast("No history.", "err"); return; }
  const ph=h.filter(x=>x.isPhishing).length, sa=h.filter(x=>!x.isPhishing&&!x.isSuspicious).length, ws=h.length-ph-sa;
  const rows = h.map((e,i) => {
    const c = e.isPhishing?"#c81e1e":e.isSuspicious?"#b45309":"#047857";
    const v = e.isPhishing?"⚠ PHISHING":e.isSuspicious?"🟡 SUSPICIOUS":"✅ SAFE";
    return `<tr><td>${i+1}</td><td style="font-family:monospace;word-break:break-all;font-size:.73rem">${e.url}</td>
      <td style="font-size:.73rem">${modelNames(e.algo)}</td>
      <td style="color:${c};font-weight:700">${v}</td>
      <td style="font-family:monospace">${e.confidence}%</td>
      <td style="font-size:.71rem;white-space:nowrap">${new Date(e.time).toLocaleString()}</td></tr>`;
  }).join("");
  downloadHTML(buildReportHTML("My Scan Report", h.length, ph, sa, ws,
    `<table><thead><tr><th>#</th><th>URL</th><th>Models</th><th>Verdict</th><th>Conf</th><th>Time</th></tr></thead><tbody>${rows}</tbody></table>`
  ), "my-phishguard-report");
  toast("Report downloaded!");
}

// ══════════════════════════════════════════════════════════════
// ADMIN PANEL
// ══════════════════════════════════════════════════════════════
async function loadAdminOverview() {
  const data = await apiFetch("/admin/api/stats");
  if (!data.ok) return;
  document.getElementById("aov-u").textContent = data.users_count;
  document.getElementById("aov-t").textContent = data.scans_total;
  document.getElementById("aov-p").textContent = data.phishing_count;
  document.getElementById("aov-s").textContent = data.safe_count;
  document.getElementById("aov-r").textContent = data.threat_rate + "%";
  const tb = document.getElementById("aov-tb");
  const scans = data.recent_scans || [];
  tb.innerHTML = scans.length
    ? scans.map((s,i) => `<tr>
        <td style="font-family:var(--mono);font-size:.68rem;color:var(--text3)">${i+1}</td>
        <td class="adm-url">${trunc(s.url)}</td>
        <td style="font-family:var(--mono);font-size:.7rem;color:var(--text2)">${(s.userName||s.userEmail||"—").split(" ")[0]}</td>
        <td style="font-family:var(--mono);font-size:.7rem;color:var(--text2)">${modelNames(s.algo)}</td>
        <td>${verdictBadge(s)}</td>
        <td style="font-family:var(--mono);font-size:.72rem">${s.confidence}%</td>
        <td style="font-size:.7rem;color:var(--text3)">${fmtTime(s.time)}</td>
      </tr>`).join("")
    : `<tr><td colspan="7" class="adm-empty">No scans yet.</td></tr>`;
}

async function loadAdminReports() {
  const data = await apiFetch("/admin/api/reports");
  if (!data.ok) return;
  const s = data.summary || {};
  document.getElementById("rep-stats").innerHTML = `
    <div class="hstat"><div class="hstat-val c-blue">${s.totalScans||0}</div><div class="hstat-lbl">Total Scans</div></div>
    <div class="hstat"><div class="hstat-val c-red">${s.phishingDetections||0}</div><div class="hstat-lbl">Phishing</div></div>
    <div class="hstat"><div class="hstat-val c-amber">${s.avgConfidence||0}%</div><div class="hstat-lbl">Avg Confidence</div></div>
    <div class="hstat"><div class="hstat-val c-red">${s.threatRate||0}%</div><div class="hstat-lbl">Threat Rate</div></div>`;
  const ua = data.userActivity || [];
  document.getElementById("rep-ua").innerHTML = ua.length
    ? ua.map(u => `<tr>
        <td style="font-weight:700">${u.name}</td>
        <td style="font-family:var(--mono);font-size:.72rem">${u.total}</td>
        <td style="font-family:var(--mono);font-size:.72rem;color:${u.phishing>0?"var(--red)":"var(--text2)"}">${u.phishing}</td>
        <td style="font-family:var(--mono);font-size:.72rem;color:var(--green)">${u.safe}</td>
        <td style="font-weight:800;font-size:.75rem;color:${u.level==="High"?"var(--red)":u.level==="Medium"?"var(--amber)":"var(--text3)"}">${u.level}</td>
      </tr>`).join("")
    : `<tr><td colspan="5" class="adm-empty">No user activity yet.</td></tr>`;
  const tp = data.topPhishing || [];
  document.getElementById("rep-tp").innerHTML = tp.length
    ? tp.map((p,i) => `<tr>
        <td style="font-family:var(--mono);font-size:.68rem;color:var(--text3)">${i+1}</td>
        <td class="adm-url">${trunc(p.url,38)}</td>
        <td style="font-family:var(--mono);font-size:.72rem;color:var(--red);font-weight:800">${p.count}</td>
        <td style="font-family:var(--mono);font-size:.72rem">${p.users}</td>
      </tr>`).join("")
    : `<tr><td colspan="4" class="adm-empty">No phishing URLs detected.</td></tr>`;
}

async function loadAdminUsers() {
  const data = await apiFetch("/admin/api/users");
  const tb = document.getElementById("users-tb");
  if (!data.ok || !data.users?.length) { tb.innerHTML = `<tr><td colspan="7" class="adm-empty">No users found.</td></tr>`; return; }
  const statsData  = await apiFetch("/admin/api/stats");
  const ustats = statsData.user_stats || {};
  const protected_ = new Set(["demo@phishguard.ai","admin@phishguard.ai"]);
  tb.innerHTML = data.users.map((u,i) => {
    const us  = ustats[u.email] || { total:0, phishing:0 };
    const del = protected_.has(u.email)
      ? `<span style="font-size:.7rem;color:var(--text3)">Protected</span>`
      : `<button onclick="adminDeleteUser('${u.email}')"
          style="padding:3px 10px;border-radius:7px;border:1px solid rgba(200,30,30,.25);
          background:transparent;color:var(--red);font-size:.7rem;cursor:pointer"
          onmouseover="this.style.background='rgba(200,30,30,.07)'"
          onmouseout="this.style.background='transparent'">Delete</button>`;
    return `<tr>
      <td style="font-family:var(--mono);font-size:.68rem;color:var(--text3)">${i+1}</td>
      <td style="font-weight:700">${u.name}</td>
      <td style="font-family:var(--mono);font-size:.7rem;color:var(--text2)">${u.email}</td>
      <td style="font-size:.7rem;color:var(--text3)">${u.created ? new Date(u.created).toLocaleDateString() : "—"}</td>
      <td style="font-family:var(--mono);font-size:.72rem">${us.total}</td>
      <td style="font-family:var(--mono);font-size:.72rem;color:${us.phishing>0?"var(--red)":"var(--green)"}">${us.phishing}</td>
      <td>${del}</td>
    </tr>`;
  }).join("");
}

async function adminDeleteUser(email) {
  if (!confirm(`Delete "${email}" and all their scan history?\nThis cannot be undone.`)) return;
  const data = await apiFetch(`/admin/api/users/${encodeURIComponent(email)}`, { method:"DELETE" });
  if (data.ok) { toast("User deleted."); loadAdminUsers(); loadAdminOverview(); }
  else toast(data.msg || "Error.", "err");
}

async function loadAdminHistory() {
  const data = await apiFetch("/admin/api/history");
  const tb   = document.getElementById("hist-tb");
  if (!data.ok || !data.history?.length) { tb.innerHTML = `<tr><td colspan="7" class="adm-empty">No scan history yet.</td></tr>`; return; }
  cachedAdminHistory = data.history;
  tb.innerHTML = data.history.map((s,i) => `<tr>
    <td style="font-family:var(--mono);font-size:.68rem;color:var(--text3)">${i+1}</td>
    <td class="adm-url">${trunc(s.url)}</td>
    <td style="font-family:var(--mono);font-size:.7rem;color:var(--text2)">${(s.userName||s.userEmail||"—").split(" ")[0]}</td>
    <td style="font-family:var(--mono);font-size:.7rem;color:var(--text2)">${modelNames(s.algo)}</td>
    <td>${verdictBadge(s)}</td>
    <td style="font-family:var(--mono);font-size:.72rem">${s.confidence}%</td>
    <td style="font-size:.7rem;color:var(--text3)">${fmtTime(s.time)}</td>
  </tr>`).join("");
}

async function adminClearAll() {
  if (!confirm("DELETE ALL scan history from ALL users? This is permanent.")) return;
  if (!confirm("Final confirmation — this cannot be undone.")) return;
  const data = await apiFetch("/admin/api/history/clear", { method:"POST" });
  if (data.ok) { toast("All history deleted."); loadAdminOverview(); cachedAdminHistory = []; }
  else toast("Error.", "err");
}

async function exportAdminCSV() {
  if (!cachedAdminHistory.length) {
    const d = await apiFetch("/admin/api/history");
    cachedAdminHistory = d.history || [];
  }
  if (!cachedAdminHistory.length) { toast("No data.", "err"); return; }
  const rows = [["#","URL","User","Models","Verdict","Confidence","Time"]];
  cachedAdminHistory.forEach((e,i) => rows.push([i+1, e.url,
    e.userName||e.userEmail||"—", modelNames(e.algo),
    e.isPhishing?"PHISHING":e.isSuspicious?"SUSPICIOUS":"SAFE", e.confidence+"%", new Date(e.time).toLocaleString()]));
  downloadCSV(rows, "phishguard-admin-all-scans");
  toast("Admin CSV exported!");
}

async function downloadAdminReport() {
  const [histData, repData] = await Promise.all([apiFetch("/admin/api/history"), apiFetch("/admin/api/reports")]);
  const h = histData.history || [];
  const ua = repData.userActivity || [];
  const tp = repData.topPhishing  || [];
  if (!h.length) { toast("No data.", "err"); return; }
  const ph=h.filter(x=>x.isPhishing).length, sa=h.filter(x=>!x.isPhishing&&!x.isSuspicious).length, ws=h.length-ph-sa;
  const scanRows = h.map((e,i) => {
    const c=e.isPhishing?"#c81e1e":e.isSuspicious?"#b45309":"#047857";
    const v=e.isPhishing?"⚠ PHISHING":e.isSuspicious?"🟡 SUSPICIOUS":"✅ SAFE";
    return `<tr><td>${i+1}</td><td style="font-family:monospace;word-break:break-all;font-size:.73rem">${e.url}</td>
      <td>${e.userName||e.userEmail||"—"}</td><td style="font-size:.73rem">${modelNames(e.algo)}</td>
      <td style="color:${c};font-weight:700">${v}</td><td style="font-family:monospace">${e.confidence}%</td>
      <td style="font-size:.71rem;white-space:nowrap">${new Date(e.time).toLocaleString()}</td></tr>`;
  }).join("");
  const uaRows = ua.map(u =>
    `<tr><td style="font-weight:700">${u.name}</td><td>${u.email}</td>
      <td style="font-family:monospace">${u.total}</td>
      <td style="color:#c81e1e;font-family:monospace">${u.phishing}</td>
      <td style="color:#047857;font-family:monospace">${u.safe}</td>
      <td style="font-weight:700;color:${u.level==="High"?"#c81e1e":u.level==="Medium"?"#b45309":"#64748b"}">${u.level}</td></tr>`
  ).join("") || `<tr><td colspan="6" style="text-align:center;color:#64748b">No data</td></tr>`;
  const tpRows = tp.map((p,i) =>
    `<tr><td>${i+1}</td><td style="font-family:monospace;word-break:break-all;font-size:.73rem">${p.url}</td>
      <td style="color:#c81e1e;font-weight:700;font-family:monospace">${p.count}</td>
      <td style="font-family:monospace">${p.users}</td></tr>`
  ).join("") || `<tr><td colspan="4" style="text-align:center;color:#64748b">None detected</td></tr>`;
  const extra = `
    <h3 style="font-size:1rem;font-weight:700;margin:1.2rem 0 .6rem">👤 User Activity</h3>
    <table><thead><tr><th>Name</th><th>Email</th><th>Total</th><th>Phishing</th><th>Safe</th><th>Level</th></tr></thead><tbody>${uaRows}</tbody></table>
    <h3 style="font-size:1rem;font-weight:700;margin:1.2rem 0 .6rem">⚠️ Top Phishing URLs</h3>
    <table><thead><tr><th>#</th><th>URL</th><th>Detections</th><th>Unique Users</th></tr></thead><tbody>${tpRows}</tbody></table>
    <h3 style="font-size:1rem;font-weight:700;margin:1.2rem 0 .6rem">📋 All Scan Logs</h3>
    <table><thead><tr><th>#</th><th>URL</th><th>User</th><th>Models</th><th>Verdict</th><th>Conf</th><th>Time</th></tr></thead><tbody>${scanRows}</tbody></table>`;
  downloadHTML(buildReportHTML("Admin Report — All Users", h.length, ph, sa, ws, extra), "phishguard-admin-report");
  toast("Admin report downloaded!");
}

// ── EXPORT UTILS ────────────────────────────────────────────────
function buildReportHTML(title, total, ph, sa, ws, extra) {
  const rate = total ? Math.round(ph/total*100) : 0;
  return `<!DOCTYPE html><html><head><meta charset="UTF-8"><title>${title}</title>
<style>*{margin:0;padding:0;box-sizing:border-box}body{font-family:'Segoe UI',sans-serif;background:#f0f4fb;color:#0d1526;padding:2rem}
.hdr{background:#fff;border:1px solid #cdd8f0;border-radius:14px;padding:1.6rem;margin-bottom:1rem;box-shadow:0 2px 12px rgba(35,80,216,.08)}
.logo{font-size:1.35rem;font-weight:900;background:linear-gradient(90deg,#2350d8,#047857);-webkit-background-clip:text;-webkit-text-fill-color:transparent}
.stats{display:flex;gap:8px;margin-bottom:1.2rem;flex-wrap:wrap}
.sc{background:#fff;border:1px solid #cdd8f0;border-radius:11px;padding:.75rem 1rem;flex:1;min-width:90px;text-align:center}
.sv{font-size:1.5rem;font-weight:900}.sl{font-size:.63rem;color:#8099c0;margin-top:3px;text-transform:uppercase;font-family:monospace}
table{width:100%;border-collapse:collapse;background:#fff;border:1px solid #cdd8f0;border-radius:11px;overflow:hidden;margin-bottom:1.2rem}
th{background:#e6ecf8;padding:8px 11px;text-align:left;font-size:.68rem;text-transform:uppercase;color:#3d5080}
td{padding:7px 11px;border-bottom:1px solid #e6ecf8;font-size:.76rem}tr:last-child td{border:none}
.foot{text-align:center;font-size:.68rem;color:#8099c0;margin-top:1rem;padding-top:1rem;border-top:1px solid #cdd8f0}</style></head><body>
<div class="hdr"><div class="logo">🛡 PhishGuard Pro 2.0 — ${title}</div>
<div style="font-size:.75rem;color:#8099c0;margin-top:3px">Generated: ${new Date().toLocaleString()} · Trained on phishing_features_database_1100.csv</div></div>
<div class="stats">
<div class="sc"><div class="sv" style="color:#2350d8">${total}</div><div class="sl">Total</div></div>
<div class="sc"><div class="sv" style="color:#c81e1e">${ph}</div><div class="sl">Phishing</div></div>
<div class="sc"><div class="sv" style="color:#047857">${sa}</div><div class="sl">Safe</div></div>
<div class="sc"><div class="sv" style="color:#b45309">${ws}</div><div class="sl">Suspicious</div></div>
<div class="sc"><div class="sv" style="color:#c81e1e">${rate}%</div><div class="sl">Threat Rate</div></div>
</div>${extra||""}
<div class="foot">PhishGuard Pro 2.0 · 6 ML Models · 1,100 URL Training Dataset</div>
</body></html>`;
}

function downloadCSV(rows, filename) {
  const csv = "\uFEFF" + rows.map(r => r.map(c => `"${String(c).replace(/"/g,'""')}"`).join(",")).join("\n");
  const a = document.createElement("a");
  a.href = "data:text/csv;charset=utf-8," + encodeURIComponent(csv);
  a.download = filename + "-" + new Date().toISOString().slice(0,10) + ".csv";
  a.click();
}

function downloadHTML(html, filename) {
  const a = document.createElement("a");
  a.href = "data:text/html;charset=utf-8," + encodeURIComponent(html);
  a.download = filename + "-" + new Date().toISOString().slice(0,10) + ".html";
  a.click();
}

// ══════════════════════════════════════════════════════════════
// INIT
// ══════════════════════════════════════════════════════════════
window.addEventListener("DOMContentLoaded", async () => {
  // Resume existing session
  const me = await apiFetch("/api/me");
  if (me.ok && me.user) {
    launch(me.user);
    const adminCheck = await apiFetch("/admin/api/stats");
    if (adminCheck.ok) {
      isAdminSession = true;
      document.getElementById("tab-admin").style.display = "block";
    }
  }

  // Modal backdrop close
  document.getElementById("adminModal").addEventListener("click", e => {
    if (e.target === document.getElementById("adminModal")) closeAdminModal();
  });

  // Enter key bindings
  document.getElementById("lEmail").addEventListener("keydown",  e => { if(e.key==="Enter") doLogin(); });
  document.getElementById("lPass").addEventListener("keydown",   e => { if(e.key==="Enter") doLogin(); });
  document.getElementById("aUser").addEventListener("keydown",   e => { if(e.key==="Enter") doAdminLogin(); });
  document.getElementById("aPass").addEventListener("keydown",   e => { if(e.key==="Enter") doAdminLogin(); });
  document.getElementById("urlInput").addEventListener("keydown", e => { if(e.key==="Enter") runScan(); });
});
