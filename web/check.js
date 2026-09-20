"use strict";
const $ = id => document.getElementById(id);

// Same no-innerHTML approach as the dashboard: every string reaching the page goes through textContent only.
function h(tag, props = {}, ...kids) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(props)) {
    if (k === "class") el.className = v;
    else el.setAttribute(k, v);
  }
  el.append(...kids.flat().filter(k => k !== null && k !== undefined));
  return el;
}

// Accepts a bare domain or a full pasted URL/link, either way we just need the hostname.
function extractHost(raw) {
  const trimmed = raw.trim();
  try {
    return new URL(trimmed).hostname;
  } catch {
    try {
      return new URL("https://" + trimmed).hostname;
    } catch {
      return trimmed;
    }
  }
}

function renderResult(data) {
  const box = $("check-result");
  box.hidden = false;
  box.className = "panel" + (data.verdict === "suspicious" ? " suspicious-result" : "");
  box.replaceChildren(
    h("div", { class: "top" },
      h("span", { class: "domain" }, data.domain),
      h("span", { class: "verdict v-" + (data.verdict === "suspicious" ? "confirmed" : "benign") }, data.verdict)),
    data.brand ? h("p", {}, `This looks like it's trying to impersonate ${data.brand}.`) : h("p", {}, "No brand impersonation detected."),
    data.reasons.length ? h("ul", { class: "reasons" }, data.reasons.map(r => h("li", {}, r))) : null,
    h("p", { class: "dim small" }, "This is an instant automated check, not a guarantee. When in doubt, don't enter your password."));
}

function renderError(message) {
  const box = $("check-result");
  box.hidden = false;
  box.className = "panel dim";
  box.replaceChildren(h("p", {}, message));
}

$("check-form").addEventListener("submit", async e => {
  e.preventDefault();
  const host = extractHost($("check-input").value);
  if (!host) return;
  try {
    const res = await fetch("/api/check?domain=" + encodeURIComponent(host));
    if (res.status === 429) { renderError("Too many checks in a short time, wait a moment and try again."); return; }
    if (!res.ok) { renderError("That doesn't look like a valid domain."); return; }
    renderResult(await res.json());
  } catch {
    renderError("Couldn't reach the server, try again in a moment.");
  }
});
