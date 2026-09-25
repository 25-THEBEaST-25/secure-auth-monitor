"use strict";

// Token is kept in memory only (not localStorage), so it's gone on reload
// and can't be read later by anything else on the origin.
let token = null;
let me = null;
let oldestEventId = null;
let refreshTimer = null;

const $ = (id) => document.getElementById(id);

const BAD_EVENTS = new Set(["ip_blocked", "account_locked", "login_blocked_ip", "login_locked_account"]);
const WARN_EVENTS = new Set(["login_failed", "login_disabled_account"]);

class ApiError extends Error {
  constructor(status, message) {
    super(message);
    this.status = status;
  }
}

async function api(method, path, body) {
  const headers = {};
  if (token) headers.Authorization = `Bearer ${token}`;
  if (body !== undefined) headers["Content-Type"] = "application/json";
  const res = await fetch(path, {
    method,
    headers,
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  if (res.status === 401 && token) {
    signOut("Session expired. Sign in again.");
    throw new ApiError(401, "Session expired");
  }
  if (!res.ok) {
    let message = `${res.status} ${res.statusText}`;
    try {
      const data = await res.json();
      if (typeof data.detail === "string") message = data.detail;
      else if (Array.isArray(data.detail)) message = data.detail.map((d) => d.msg).join("; ");
    } catch (_) { /* non-JSON error body */ }
    throw new ApiError(res.status, message);
  }
  return res.status === 204 ? null : res.json();
}

// Every value from the API goes through textContent, never innerHTML:
// usernames in events are whatever an attacker typed into the login form.
function el(tag, text, className) {
  const node = document.createElement(tag);
  if (text !== undefined && text !== null) node.textContent = String(text);
  if (className) node.className = className;
  return node;
}

function row(cells) {
  const tr = document.createElement("tr");
  for (const cell of cells) tr.append(cell instanceof Node ? cell : el("td", cell ?? ""));
  return tr;
}

function button(label, className, onClick) {
  const b = el("button", label, className);
  b.type = "button";
  b.addEventListener("click", onClick);
  return b;
}

function actions(...buttons) {
  const td = el("td", null, "actions");
  td.append(...buttons);
  return td;
}

function showError(message) {
  $("app-error").textContent = message || "";
}

async function run(action) {
  showError("");
  try {
    await action();
  } catch (err) {
    if (err.status !== 401) showError(err.message);
  }
}

function fmtTime(value) {
  return new Date(value).toLocaleString();
}

async function loadStats() {
  const s = await api("GET", "/api/admin/stats?hours=24");
  const c = s.event_counts;
  const cards = [
    ["Failed logins (24h)", c.login_failed || 0, (c.login_failed || 0) > 0 ? "warn" : ""],
    ["Successful logins (24h)", c.login_success || 0, ""],
    ["Blocks triggered (24h)", (c.ip_blocked || 0) + (c.account_locked || 0), (c.ip_blocked || c.account_locked) ? "bad" : ""],
    ["Active blocks", s.active_blocks, s.active_blocks ? "bad" : ""],
    ["Users", `${s.users}`, ""],
  ];
  const box = $("stats");
  box.replaceChildren(...cards.map(([label, n, cls]) => {
    const div = el("div", null, `stat ${cls}`);
    div.append(el("div", n, "n"), el("div", label, "label"));
    return div;
  }));
  if (s.top_failed_ips.length) {
    const div = el("div", null, "stat");
    div.append(el("div", "Top failing IPs (24h)", "label"));
    for (const [ip, n] of s.top_failed_ips) div.append(el("div", `${ip} — ${n}`));
    box.append(div);
  }
}

async function loadBlocks() {
  const blocks = await api("GET", "/api/admin/blocks");
  const body = $("blocks");
  if (!blocks.length) {
    body.replaceChildren(row([el("td", "No active blocks", "muted")]));
    return;
  }
  body.replaceChildren(...blocks.map((b) => {
    const until = b.permanent ? "permanent" : new Date(b.blocked_until * 1000).toLocaleTimeString();
    const lift = button("Lift", "secondary", () => run(async () => {
      const path = b.kind === "ip" ? "ip-bans" : "account-locks";
      await api("DELETE", `/api/admin/${path}/${encodeURIComponent(b.key)}`);
      await refresh();
    }));
    return row([b.kind, el("td", b.key, "wrap"), until, actions(lift)]);
  }));
}

async function loadUsers() {
  const users = await api("GET", "/api/admin/users");
  $("users").replaceChildren(...users.map((u) => {
    const status = el("td");
    status.append(el("span", u.is_disabled ? "disabled" : "active", `tag ${u.is_disabled ? "bad" : "ok"}`));
    const cell = u.id === me.id
      ? el("td", "you", "actions muted")
      : actions(
          button(u.is_disabled ? "Enable" : "Disable", u.is_disabled ? "secondary" : "danger", () => run(async () => {
            await api("PATCH", `/api/admin/users/${u.id}`, { is_disabled: !u.is_disabled });
            await refresh();
          })),
          button(u.role === "admin" ? "Make user" : "Make admin", "secondary", () => run(async () => {
            await api("PATCH", `/api/admin/users/${u.id}`, { role: u.role === "admin" ? "user" : "admin" });
            await refresh();
          })),
          button("Unlock", "secondary", () => run(async () => {
            await api("POST", `/api/admin/users/${u.id}/unlock`);
            await refresh();
          })),
        );
    return row([el("td", u.username, "wrap"), u.role, status, cell]);
  }));
}

function eventFilterQuery() {
  const form = new FormData($("event-filter"));
  const params = new URLSearchParams({ limit: "50" });
  for (const key of ["event", "username", "ip"]) {
    const value = String(form.get(key) || "").trim();
    if (value) params.set(key, value);
  }
  return params;
}

function eventRow(e) {
  const tag = el("td");
  const cls = BAD_EVENTS.has(e.event) ? "bad" : WARN_EVENTS.has(e.event) ? "warn" : "ok";
  tag.append(el("span", e.event, `tag ${cls}`));
  return row([fmtTime(e.created_at), tag, el("td", e.username, "wrap"), e.ip, el("td", e.detail, "wrap")]);
}

async function loadEvents(append = false) {
  const params = eventFilterQuery();
  if (append && oldestEventId) params.set("before_id", String(oldestEventId));
  const events = await api("GET", `/api/admin/events?${params}`);
  const rows = events.map(eventRow);
  if (append) $("events").append(...rows);
  else $("events").replaceChildren(...rows);
  if (events.length) oldestEventId = events[events.length - 1].id;
  $("more").hidden = events.length < 50;
}

async function refresh() {
  await Promise.all([loadStats(), loadBlocks(), loadUsers(), loadEvents()]);
}

function signOut(message) {
  token = null;
  me = null;
  clearInterval(refreshTimer);
  $("app-view").hidden = true;
  $("session").hidden = true;
  $("login-view").hidden = false;
  $("login-error").textContent = message || "";
}

$("login-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const form = new FormData(event.target);
  $("login-error").textContent = "";
  try {
    const res = await api("POST", "/api/login", {
      username: form.get("username"),
      password: form.get("password"),
    });
    token = res.access_token;
    me = await api("GET", "/api/me");
    if (me.role !== "admin") {
      signOut("This dashboard is for admins only.");
      return;
    }
    event.target.reset();
    $("whoami").textContent = `Signed in as ${me.username}`;
    $("login-view").hidden = true;
    $("session").hidden = false;
    $("app-view").hidden = false;
    await run(refresh);
    refreshTimer = setInterval(() => run(refresh), 15000);
  } catch (err) {
    token = null;
    $("login-error").textContent = err.message;
  }
});

$("logout").addEventListener("click", async () => {
  try { await api("POST", "/api/logout"); } catch (_) { /* signing out anyway */ }
  signOut();
});

$("ban-form").addEventListener("submit", (event) => {
  event.preventDefault();
  const ip = String(new FormData(event.target).get("ip")).trim();
  run(async () => {
    await api("POST", "/api/admin/ip-bans", { ip });
    event.target.reset();
    await refresh();
  });
});

$("user-form").addEventListener("submit", (event) => {
  event.preventDefault();
  const form = new FormData(event.target);
  run(async () => {
    await api("POST", "/api/admin/users", {
      username: form.get("username"),
      password: form.get("password"),
      role: form.get("role"),
    });
    event.target.reset();
    await refresh();
  });
});

$("event-filter").addEventListener("submit", (event) => {
  event.preventDefault();
  run(() => loadEvents(false));
});

$("more").addEventListener("click", () => run(() => loadEvents(true)));
