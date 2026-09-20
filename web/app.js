"use strict";
const $ = id => document.getElementById(id);
const tokenStore = {
  get: () => { try { return sessionStorage.getItem("ph_token"); } catch { return null; } },
  set: v => { try { sessionStorage.setItem("ph_token", v); } catch { /* private mode */ } },
  clear: () => { try { sessionStorage.removeItem("ph_token"); } catch { /* ignore */ } },
};

// Build DOM without innerHTML: every string from the server (including attacker-chosen domains and lure text)
// only ever reaches the page through textContent, and there is no inline script or style (see the CSP).
function h(tag, props = {}, ...kids) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(props)) {
    if (k === "class") el.className = v;
    else if (k === "on") for (const [ev, fn] of Object.entries(v)) el.addEventListener(ev, fn);
    else el.setAttribute(k, v);
  }
  el.append(...kids.flat().filter(k => k !== null && k !== undefined));
  return el;
}

let token = tokenStore.get();
let ws;

async function api(path, opts = {}) {
  const headers = { ...(opts.headers || {}), Authorization: "Bearer " + token };
  if (opts.body) headers["Content-Type"] = "application/json";
  const res = await fetch(path, { ...opts, headers });
  if (res.status === 401) { logout(); throw new Error("unauthorized"); }
  if (!res.ok) throw new Error((await res.json().catch(() => ({}))).detail || res.statusText);
  return res;
}

function logout() {
  tokenStore.clear(); token = null;
  if (ws) ws.close();
  $("app").hidden = true; $("login").hidden = false; $("conn").textContent = "not connected";
}

let pendingSimulateDomain = null;

function renderHit(d, prepend = true) {
  const justSimulated = d.domain === pendingSimulateDomain;
  const el = h("div", { class: "hit" + (d.score >= 70 ? " high" : "") + (justSimulated ? " simulated" : ""),
                        on: { click: () => investigate(d.domain) } },
    h("div", { class: "top" }, h("span", { class: "domain" }, d.domain), h("span", { class: "score" }, d.score + "/100")),
    h("ul", { class: "reasons" }, (d.reasons || []).map(r => h("li", {}, r))));
  const feed = $("feed");
  if (prepend) feed.prepend(el); else feed.append(el);
  while (feed.children.length > 60) feed.lastChild.remove();
  if (justSimulated) {
    pendingSimulateDomain = null;
    el.scrollIntoView({ behavior: "smooth", block: "nearest" });
  }
}

const AGENT_LABEL = { agent_builder: "Agent Builder analyst", gemini: "Gemini analyst" };

function renderInvestigation(inv) {
  const box = $("investigation");
  box.className = "panel";
  box.replaceChildren(
    h("div", { class: "top" }, h("span", { class: "domain" }, inv.domain), h("span", { class: "verdict v-" + inv.verdict }, inv.verdict)),
    h("p", {}, inv.summary),
    inv.domain_age_days != null ? h("p", { class: "dim" }, `Registered ${inv.domain_age_days.toFixed(1)} days ago (RDAP)`) : null,
    inv.corroboration.length ? h("ul", { class: "reasons" }, inv.corroboration.map(c => h("li", {}, c))) : null,
    inv.agent_summary ? h("div", { class: "lure" }, h("b", {}, AGENT_LABEL[inv.agent_source] || "Analyst"), h("div", {}, inv.agent_summary)) : null,
    ...inv.lures.map(l => h("div", { class: "lure" }, h("b", {}, `[${l.language || "?"}] ${l.type || ""}`), " " + l.snippet)),
    inv.lookalikes.length ? h("div", { class: "lure" }, h("b", {}, "Similar flagged domains: "), inv.lookalikes.map(x => x.domain).join(", ")) : null,
    (inv.defensive_suggestions || []).length ? h("div", { class: "lure" },
      h("b", {}, "Worth registering defensively"),
      h("div", { class: "chips" }, inv.defensive_suggestions.map(s => h("span", { class: "chip" }, s)))) : null,
    h("ol", { class: "trace" }, inv.trace.map(t => h("li", {}, h("b", {}, t.tool), " - " + t.result))),
    h("a", { href: "#", on: { click: async e => { e.preventDefault(); const r = await api("/api/report/" + encodeURIComponent(inv.domain)); alert(await r.text()); } } }, "view abuse report"));
}

function renderCampaigns(campaigns) {
  $("campaigns").replaceChildren(...campaigns.length ? campaigns.map(c => h("div", { class: "hit" },
    h("div", { class: "top" }, h("span", { class: "domain" }, `${c.brand} via ${c.issuer || "?"}`), h("span", { class: "score" }, c.domains + " domains")),
    h("div", { class: "dim" }, `.${c.tld || "?"} - peak score ${c.top_score} - last seen ${new Date(c.last_seen).toLocaleTimeString()}`)))
    : [h("span", { class: "dim" }, "no clusters yet (needs 2+ related domains in the last 24h)")]);
}

async function investigate(domain) {
  $("investigation").textContent = "Investigating " + domain + " ...";
  try {
    const res = await api("/api/investigate", { method: "POST", body: JSON.stringify({ domain }) });
    renderInvestigation(await res.json());
    loadActions(); loadCampaigns();
  } catch (e) { $("investigation").textContent = "Investigation failed: " + e.message; }
}

async function decide(id, verb) {
  try { await api(`/api/actions/${id}/${verb}`, { method: "POST" }); } catch (e) { alert(e.message); }
  loadActions();
}

const STATUS_BADGE = { pending_approval: "s-pending", executed: "s-executed", failed: "s-failed", rejected: "s-failed" };

async function loadActions() {
  const { actions, auto } = await (await api("/api/actions")).json();
  $("auto-note").textContent = auto ? "unattended actions ON (policy-gated)" : "unattended actions off - a person approves everything";
  $("actions").replaceChildren(...actions.slice(0, 30).map(a => h("div", { class: "action " + a.status },
    h("div", {}, h("span", { class: "domain" }, a.domain), h("div", { class: "dim" },
      `${a.kind} - `, h("span", { class: "status-badge " + (STATUS_BADGE[a.status] || "") }, a.status), ` - ${a.source}`)),
    a.status === "pending_approval" ? h("div", { class: "btns" },
      h("button", { on: { click: () => decide(a.id, "approve") } }, "Approve"),
      h("button", { class: "danger", on: { click: () => decide(a.id, "reject") } }, "Reject")) : null)));
}

async function loadVolume() {
  const { buckets } = await (await api("/api/volume")).json();
  const max = Math.max(1, ...buckets.map(b => b.flagged));
  // heights via the CSSOM (allowed by the CSP), not a style attribute
  const bars = buckets.map((b, i) => {
    const s = h("span", { title: `${b.bucket}: ${b.flagged}`, class: i === buckets.length - 1 ? "now" : "" });
    s.style.height = Math.round(100 * b.flagged / max) + "%";
    return s;
  });
  $("volume").replaceChildren(bars.length ? h("div", { class: "bars" }, bars) : h("span", { class: "dim" }, "no data yet"));
}

async function loadCampaigns() {
  const { campaigns } = await (await api("/api/campaigns")).json();
  renderCampaigns(campaigns);
}

async function loadBenchmark() {
  const r = await (await api("/api/benchmark")).json();
  $("benchmark").className = "panel";
  $("benchmark").replaceChildren(
    h("div", { class: "top" },
      h("span", {}, `${r.recall_pct}% recall`, h("span", { class: "dim" }, ` on ${r.in_scope} in-scope phishing URLs`)),
      h("span", { class: r.false_positives ? "score" : "dim" }, `${r.false_positives}/${r.known_good_tested} false positives`)),
    h("div", { class: "dim" }, `snapshot: ${r.snapshot}, ${r.total_urls} live URLs, ${r.configured_brands} configured brands`),
    r.false_positive_examples.length ? h("div", { class: "chips" },
      r.false_positive_examples.map(d => h("span", { class: "chip", title: "flagged, but actually legitimate" }, d))) : null,
  );
}

function stats(s) { $("seen").textContent = s.seen; $("flagged").textContent = s.flagged; }

function connect() {
  ws = new WebSocket((location.protocol === "https:" ? "wss://" : "ws://") + location.host + "/ws");
  ws.onopen = () => { ws.send(token); $("conn").textContent = "live"; };   // token in the first message, never the URL
  ws.onclose = () => { $("conn").textContent = "disconnected"; if (token) setTimeout(connect, 3000); };
  ws.onmessage = e => {
    const m = JSON.parse(e.data);
    if (m.type === "hit") { stats(m.stats); renderHit(m); }
    else if (m.type === "investigation") { renderInvestigation(m); loadActions(); loadCampaigns(); }
    else if (m.type === "actions") loadActions();
  };
}

async function simulate(live) {
  const btn = $(live ? "simulate-live" : "simulate");
  const label = live ? "Simulate a live attack" : "Simulate an attack";
  btn.disabled = true; btn.textContent = live ? "Fetching a real attack..." : "Simulating...";
  try {
    const { domain, source } = await (await api(`/api/simulate?live=${live}`, { method: "POST" })).json();
    pendingSimulateDomain = domain;
    btn.textContent = live ? `Pulled ${domain} (${source})` : `Simulated ${domain}`;
    // Jump straight to investigating it, so the result is the investigation panel filling in with real
    // evidence, not just a pulsing row somewhere in a feed that keeps scrolling in demo mode.
    await investigate(domain);
  } catch (e) {
    btn.textContent = e.message.toLowerCase().includes("demo") ? "Only available in demo mode" : label;
  } finally {
    setTimeout(() => { btn.disabled = false; btn.textContent = label; }, 4000);
  }
}

async function start() {
  try {
    const d = await (await api("/api/hits")).json();
    stats(d.stats);
    d.hits.reverse().forEach(x => renderHit(x, true));
    $("login").hidden = true; $("app").hidden = false; $("simulate").hidden = false; $("simulate-live").hidden = false;
    connect(); loadActions(); loadVolume(); loadCampaigns(); loadBenchmark();
    setInterval(loadVolume, 60000); setInterval(loadCampaigns, 60000);
  } catch { $("login-error").textContent = "Token rejected or server unreachable."; $("login").hidden = false; }
}

$("simulate").addEventListener("click", () => simulate(false));
$("simulate-live").addEventListener("click", () => simulate(true));

let loginMode = "login";
function setLoginMode(mode) {
  loginMode = mode;
  $("tab-login").classList.toggle("active", mode === "login");
  $("tab-token").classList.toggle("active", mode === "token");
  $("login-fields").hidden = mode !== "login";
  $("token-fields").hidden = mode !== "token";
}
$("tab-login").addEventListener("click", () => setLoginMode("login"));
$("tab-token").addEventListener("click", () => setLoginMode("token"));
setLoginMode("login");

async function tradeLoginForToken(username, password) {
  const res = await fetch("/api/auth/login", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ username, password }),
  });
  const body = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(body.detail || "login failed");
  return body.token;
}

$("login").addEventListener("submit", async e => {
  e.preventDefault();
  $("login-error").textContent = "";
  try {
    if (loginMode === "token") {
      token = $("token").value.trim(); $("token").value = "";
    } else {
      token = await tradeLoginForToken($("username").value.trim(), $("password").value);
      $("password").value = "";
    }
    tokenStore.set(token);
    start();
  } catch (err) {
    $("login-error").textContent = err.message;
  }
});
if (token) start(); else $("login").hidden = false;
