// Warden Hub management UI.
// Vanilla ES module: no external libraries, no CDN, no framework. Every
// action calls the existing JSON API; the UI is management-only and never
// reveals credentials, runs SQL, or executes remote commands.
"use strict";

const $ = (id) => document.getElementById(id);

const banner = $("banner");

function showBanner(message, kind) {
  banner.hidden = false;
  banner.className = "banner " + (kind || "error");
  banner.textContent = message;
}

function clearBanner() {
  banner.hidden = true;
  banner.textContent = "";
}

// apiError decodes the stable server error envelope. Falls back to a
// generic message when the body is not the expected shape.
class ApiError extends Error {
  constructor(code, message, status) {
    super(message);
    this.code = code;
    this.status = status;
  }
}

async function api(path, options) {
  const opts = options || {};
  const headers = Object.assign({}, opts.headers);
  if (opts.json !== undefined) {
    headers["Content-Type"] = "application/json";
  }
  const resp = await fetch(path, {
    method: opts.method || "GET",
    headers,
    body: opts.json !== undefined ? JSON.stringify(opts.json) : undefined,
  });
  if (resp.status === 204) return null;
  const text = await resp.text();
  let body = null;
  if (text) {
    try { body = JSON.parse(text); } catch { body = null; }
  }
  if (!resp.ok) {
    if (body && typeof body === "object" && body.code) {
      throw new ApiError(body.code, body.message || text, resp.status);
    }
    throw new ApiError("http_" + resp.status, "Request failed with status " + resp.status, resp.status);
  }
  return body;
}

function esc(value) {
  if (value === null || value === undefined) return "";
  return String(value)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

function badge(present) {
  return present ? '<span class="badge yes">set</span>' : '<span class="badge">unset</span>';
}

// ---- Modal -------------------------------------------------------------

let modalResolver = null;

function openModal(title, bodyEl, onClose) {
  $("modal-title").textContent = title;
  $("modal-body").replaceChildren(bodyEl);
  $("modal-backdrop").hidden = false;
  modalResolver = onClose || null;
}

function closeModal() {
  $("modal-backdrop").hidden = true;
  $("modal-body").replaceChildren();
  if (modalResolver) {
    const resolve = modalResolver;
    modalResolver = null;
    resolve();
  }
}

$("modal-close").addEventListener("click", closeModal);
$("modal-backdrop").addEventListener("click", (e) => {
  if (e.target === $("modal-backdrop")) closeModal();
});

function field(labelText, name, value, opts) {
  opts = opts || {};
  const type = opts.type || "text";
  const note = opts.note ? `<span class="field-note">${escNote(opts.note)}</span>` : "";
  const input = `<input id="f-${name}" name="${name}" type="${type}" ${opts.required ? "required" : ""} value="${escAttr(value === undefined ? "" : value)}">`;
  return `<div class="form-row"><label for="f-${name}">${escNote(labelText)}</label>${input}${note}</div>`;
}

function escNote(s) { return s.replace(/&/g, "&amp;").replace(/</g, "&lt;"); }
function escAttr(s) { return escNote(String(s)).replace(/"/g, "&quot;"); }

function textarea(labelText, name, value, rows, note) {
  const noteEl = note ? `<span class="field-note">${escNote(note)}</span>` : "";
  return `<div class="form-row"><label for="f-${name}">${escNote(labelText)}</label>` +
    `<textarea id="f-${name}" name="${name}" rows="${rows}">${escAttr(value === undefined ? "" : value)}</textarea>${noteEl}</div>`;
}

// formError renders the API error into the active form and reports whether
// the error was a validation/conflict error worth keeping the form open.
function formError(err) {
  const box = document.getElementById("form-error");
  if (box) box.textContent = err.message || String(err);
  return err instanceof ApiError && (err.code === "validation_error" || err.code === "conflict" || err.code === "invalid_request");
}

// ---- SSH connections ----------------------------------------------------

async function refreshSsh() {
  let rows;
  try {
    rows = await api("/api/v1/ssh-connections");
  } catch (err) {
    showBanner("Failed to load SSH connections: " + err.message);
    return;
  }
  const tbody = $("ssh-rows");
  tbody.replaceChildren();
  $("ssh-empty").hidden = rows.length > 0;
  for (const c of rows) {
    const tr = document.createElement("tr");
    const auth = [];
    if (c.has_password) auth.push(badge(true));
    if (c.has_private_key) auth.push(badge(true));
    tr.innerHTML =
      "<td class=\"monospace\">" + esc(c.name) + "</td>" +
      "<td>" + esc(c.host) + "</td>" +
      "<td>" + esc(c.port) + "</td>" +
      "<td>" + esc(c.username) + "</td>" +
      "<td>" + (auth.length ? auth.join(" ") : badge(false)) + "</td>" +
      "<td>" + (c.proxy_host ? esc(c.proxy_host) + ":" + esc(c.proxy_port) : "—") + "</td>" +
      "<td class=\"monospace\">" + esc(c.jump_connection_ids) + "</td>" +
      "<td class=\"monospace\">" + esc(c.default_dir || "—") + "</td>" +
      "<td>" +
        '<button class="btn" data-action="edit-ssh" data-id="' + c.id + '">Edit</button> ' +
        '<button class="btn btn-danger" data-action="delete-ssh" data-id="' + c.id + '">Delete</button>' +
      "</td>";
    tbody.appendChild(tr);
  }
  clearBanner();
}

function sshFormValues() {
  const get = (n) => document.querySelector('#ssh-form [name="' + n + '"]').value;
  const val = (n) => { const v = get(n); return v === "" ? null : v; };
  return {
    name: get("name"),
    host: get("host"),
    port: parseInt(get("port"), 10),
    username: get("username"),
    password: val("password"),
    private_key: val("private_key"),
    private_key_passphrase: val("private_key_passphrase"),
    proxy_host: get("proxy_host"),
    proxy_port: parseInt(get("proxy_port") || "0", 10),
    proxy_username: get("proxy_username"),
    proxy_password: val("proxy_password"),
    jump_connection_ids: get("jump_connection_ids") || "[]",
    default_dir: get("default_dir"),
  };
}

function openSshForm(existing) {
  const editing = !!existing;
  const v = existing || { name: "", host: "", port: 22, username: "", proxy_host: "", proxy_port: 0, proxy_username: "", jump_connection_ids: "[]", default_dir: "" };
  const body = document.createElement("div");
  body.innerHTML = `
    <form id="ssh-form" class="form" novalidate>
      ${field("Name", "name", v.name, { required: true })}
      ${field("Host", "host", v.host, { required: true })}
      ${field("Port", "port", v.port, { required: true, type: "number" })}
      ${field("Username", "username", v.username, { required: true })}
      ${field("Password (leave blank to keep)", "password", "", { type: "password", note: editing ? "Leave blank to keep the stored value." : "Optional; key auth also supported." })}
      ${textarea("Private key (PEM)", "private_key", "", 3, editing ? "Leave blank to keep the stored key." : "Optional OpenSSH private key text.")}
      ${field("Private key passphrase", "private_key_passphrase", "", { type: "password", note: "Optional." })}
      ${field("Proxy host", "proxy_host", v.proxy_host)}
      ${field("Proxy port", "proxy_port", v.proxy_port || 0, { type: "number" })}
      ${field("Proxy username", "proxy_username", v.proxy_username)}
      ${field("Proxy password", "proxy_password", "", { type: "password", note: "Optional." })}
      ${field("Jump connection IDs", "jump_connection_ids", v.jump_connection_ids, { note: "JSON array of SSH connection IDs, e.g. [12, 4]. Logical validation happens at transport time." })}
      ${field("Default directory", "default_dir", v.default_dir, { note: "Optional remote working directory for xssh." })}
      <p id="form-error" class="form-error"></p>
      <div class="form-actions">
        <button type="button" class="btn" data-act="cancel">Cancel</button>
        <button type="submit" class="btn btn-primary">${editing ? "Save" : "Create"}</button>
      </div>
    </form>`;
  openModal(editing ? "Edit SSH connection" : "New SSH connection", body);
  body.querySelector('[data-act="cancel"]').addEventListener("click", closeModal);
  body.querySelector("#ssh-form").addEventListener("submit", async (e) => {
    e.preventDefault();
    const payload = sshFormValues();
    try {
      if (editing) {
        await api("/api/v1/ssh-connections/" + existing.id, { method: "PUT", json: payload });
      } else {
        await api("/api/v1/ssh-connections", { method: "POST", json: payload });
      }
      closeModal();
      await refreshSsh();
      showBanner(editing ? "SSH connection saved." : "SSH connection created.", "ok");
    } catch (err) {
      formError(err);
    }
  });
}

$("ssh-create").addEventListener("click", () => openSshForm(null));

// ---- DB connections -----------------------------------------------------------

async function refreshDb() {
  let rows;
  try {
    rows = await api("/api/v1/db-connections");
  } catch (err) {
    showBanner("Failed to load DB connections: " + err.message);
    return;
  }
  const tbody = $("db-rows");
  tbody.replaceChildren();
  $("db-empty").hidden = rows.length > 0;
  for (const c of rows) {
    const tr = document.createElement("tr");
    tr.innerHTML =
      "<td class=\"monospace\">" + esc(c.name) + "</td>" +
      "<td>" + esc(c.host) + "</td>" +
      "<td>" + esc(c.port) + "</td>" +
      "<td>" + esc(c.username) + "</td>" +
      "<td class=\"monospace\">" + esc(c.database) + "</td>" +
      "<td>" + (c.ssh_connection_id ? "ssh #" + c.ssh_connection_id : "direct") + "</td>" +
      "<td>" +
        '<button class="btn" data-action="edit-db" data-id="' + c.id + '">Edit</button> ' +
        '<button class="btn btn-danger" data-action="delete-db" data-id="' + c.id + '">Delete</button>' +
      "</td>";
    tbody.appendChild(tr);
  }
  clearBanner();
}

function dbFormValues() {
  const get = (n) => document.querySelector('#db-form [name="' + n + '"]').value;
  const pwd = get("password");
  return {
    name: get("name"),
    host: get("host"),
    port: parseInt(get("port"), 10),
    username: get("username"),
    password: pwd === "" ? null : pwd,
    database: get("database"),
    ssh_connection_id: parseInt(get("ssh_connection_id") || "0", 10),
  };
}

function openDbForm(existing) {
  const editing = !!existing;
  const title = editing ? "Edit DB connection " : "Add DB connection";
  const v = existing || { name: "", host: "", port: 3306, username: "", database: "", ssh_connection_id: 0 };
  const body = document.createElement("div");
  body.innerHTML = `
    <form id="db-form" class="form" novalidate>
      ${field("Name", "name", v.name, { required: true })}
      ${field("Host", "host", v.host, { required: true })}
      ${field("Port", "port", v.port, { required: true, type: "number" })}
      ${field("Username", "username", v.username, { required: true })}
      ${field("Password (leave blank to keep)", "password", "", { type: "password" })}
      ${field("Database", "database", v.database, { required: true })}
      ${field("SSH connection ID (0 = direct)", "ssh_connection_id", v.ssh_connection_id || 0, { type: "number" })}
      <p id="form-error" class="form-error"></p>
      <div class="form-actions">
        <button type="button" class="btn" data-act="cancel">Cancel</button>
        <button type="submit" class="btn btn-primary">${editing ? "Save" : "Create"}</button>
      </div>
    </form>`;
  openModal(title, body);
  body.querySelector('[data-act="cancel"]').addEventListener("click", closeModal);
  body.querySelector("#db-form").addEventListener("submit", async (e) => {
    e.preventDefault();
    const payload = dbFormValues();
    try {
      if (editing) {
        await api("/api/v1/db-connections/" + existing.id, { method: "PUT", json: payload });
      } else {
        await api("/api/v1/db-connections", { method: "POST", json: payload });
      }
      closeModal();
      await refreshDb();
      showBanner(editing ? "DB connection saved." : "DB connection created.", "ok");
    } catch (err) {
      formError(err);
    }
  });
}

$("db-create").addEventListener("click", () => openDbForm(null));

// ---- Delete flow with dependents warning ------------------------------------

async function confirmDelete(kind, id, name) {
  const dependents = await api("/api/v1/" + kind + "-connections/" + id + "/dependents");
  const ssh = dependents.ssh || [];
  const db = dependents.db || [];
  const body = document.createElement("div");
  let depHtml = "";
  if (ssh.length === 0 && db.length === 0) {
    depHtml = '<p class="muted">No other profiles reference this connection.</p>';
  } else {
    depHtml = '<p class="warning">The following profiles reference this connection. Their stored routes are left unchanged and may become logically invalid:</p><ul class="dependents">';
    for (const d of ssh) depHtml += "<li>" + esc(d.name) + " (ssh)</li>";
    for (const d of db) depHtml += "<li>" + esc(d.name) + " (db)</li>";
    depHtml += "</ul>";
  }
  body.innerHTML = `
    <p>Delete ${kind === "ssh" ? "SSH connection" : "DB connection"} <span class="monospace">${esc(name)}</span> (#${esc(id)})?</p>
    ${depHtml}
    <p id="form-error" class="form-error"></p>
    <div class="form-actions">
      <button type="button" class="btn" data-act="cancel">Cancel</button>
      <button type="button" class="btn btn-danger" data-act="confirm">Delete</button>
    </div>`;
  openModal("Delete " + (kind === "ssh" ? "SSH connection" : "DB connection"), body);
  body.querySelector('[data-act="cancel"]').addEventListener("click", closeModal);
  body.querySelector('[data-act="confirm"]').addEventListener("click", async () => {
    try {
      await api("/api/v1/" + kind + "-connections/" + id, { method: "DELETE" });
      closeModal();
      if (kind === "ssh") await refreshSsh(); else await refreshDb();
      showBanner("Connection deleted.", "ok");
    } catch (err) {
      formError(err);
    }
  });
}

$("ssh-rows").addEventListener("click", (e) => {
  const btn = e.target.closest("[data-action]");
  if (!btn) return;
  const id = btn.dataset.id;
  if (btn.dataset.action === "edit-ssh") {
    const row = sshRow(id);
    if (row) openSshForm(row);
  } else if (btn.dataset.action === "delete-ssh") {
    confirmDelete("ssh", id, rowName("ssh", id));
  }
});

$("db-rows").addEventListener("click", (e) => {
  const btn = e.target.closest("[data-action]");
  if (!btn) return;
  const id = btn.dataset.id;
  if (btn.dataset.action === "edit-db") {
    const row = dbRow(id);
    if (row) openDbForm(row);
  } else if (btn.dataset.action === "delete-db") {
    confirmDelete("db", id, rowName("db", id));
  }
});

// Cache last fetched rows for edit prefill.
let sshCache = [];
let dbCache = [];

function sshRow(id) { return sshCache.find((r) => String(r.id) === String(id)); }
function dbRow(id) { return dbCache.find((r) => String(r.id) === String(id)); }

// rowName resolves a profile name for the delete confirmation dialog.
function rowName(kind, id) {
  const row = kind === "ssh" ? sshRow(id) : dbRow(id);
  return row ? row.name : "#" + id;
}

async function refreshSshCache() {
  try {
    sshCache = await api("/api/v1/ssh-connections");
  } catch { sshCache = []; }
}

async function refreshDbCache() {
  try {
    dbCache = await api("/api/v1/db-connections");
  } catch { dbCache = []; }
}

// ---- Projects & reports ------------------------------------------------------

async function refreshProjects() {
  let projects;
  try {
    projects = await api("/api/v1/projects");
  } catch (err) {
    showBanner("Failed to load projects: " + err.message);
    return;
  }
  $("projects-empty").hidden = projects.length > 0;
  const list = $("project-list");
  list.replaceChildren();
  for (const p of projects) {
    const div = document.createElement("div");
    div.className = "project";
    div.innerHTML =
      '<div class="project-name"><h3 class="monospace">' + esc(p.name) + "</h3>" +
      '<button class="btn" data-project="' + escAttr(p.name) + '" data-action="load-reports">Reports</button>' +
      '<button class="btn btn-primary" data-project="' + escAttr(p.name) + '" data-action="new-report">Add report</button></div>' +
      '<div data-reports></div>';
    list.appendChild(div);
  }
  clearBanner();
}

$("project-list").addEventListener("click", async (e) => {
  const btn = e.target.closest("[data-action]");
  if (!btn) return;
  const project = btn.dataset.project;
  if (btn.dataset.action === "load-reports") {
    await loadReports(btn, project);
  } else if (btn.dataset.action === "new-report") {
    openReportForm(project);
  }
});

async function loadReports(btn, project) {
  let reports;
  try {
    reports = await api("/api/v1/projects/" + encodeURIComponent(project) + "/reports");
  } catch (err) {
    showBanner("Failed to load reports: " + err.message);
    return;
  }
  const host = btn.closest(".project").querySelector("[data-reports]");
  host.replaceChildren();
  if (reports.length === 0) {
    host.appendChild(paragraph("No reports yet for this project."));
    return;
  }
  for (const r of reports) {
    const div = document.createElement("div");
    div.className = "report";
    div.innerHTML =
      '<div class="report-title">' + esc(r.title) + "</div>" +
      '<div class="report-meta">' + esc(r.agent_model) + " &middot; " + esc(new Date(r.created_at).toLocaleString()) + "</div>" +
      '<div class="report-summary">' + esc(r.summary) + "</div>";
    host.appendChild(div);
  }
}

function paragraph(text) {
  const p = document.createElement("p");
  p.className = "muted";
  p.textContent = text;
  return p;
}

function openReportForm(project) {
  const body = document.createElement("div");
  body.innerHTML = `
    <form id="report-form" class="form" novalidate>
      ${field("Project", "project", project, { required: true })}
      ${field("Title", "title", "", { required: true })}
      ${field("Agent model", "agent_model", "", { required: true, note: "Arbitrary caller-supplied name, e.g. gpt-5.4." })}
      ${textarea("Summary", "summary", "", 6, "1–16384 bytes. Like a git commit message.")}
      <p id="form-error" class="form-error"></p>
      <div class="form-actions">
        <button type="button" class="btn" data-act="cancel">Cancel</button>
        <button type="submit" class="btn btn-primary">Create report</button>
      </div>
    </form>`;
  openModal("Add report", body);
  body.querySelector('[data-act="cancel"]').addEventListener("click", closeModal);
  body.querySelector("#report-form").addEventListener("submit", async (e) => {
    e.preventDefault();
    const f = e.target;
    const payload = {
      project: f.project.value,
      title: f.title.value,
      summary: f.summary.value,
      agent_model: f.agent_model.value,
    };
    try {
      await api("/api/v1/reports", { method: "POST", json: payload });
      closeModal();
      await refreshProjects();
      showBanner("Report created.", "ok");
    } catch (err) {
      formError(err);
    }
  });
}

$("project-create").addEventListener("click", () => {
  const body = document.createElement("div");
  body.innerHTML = `
    <form id="project-form" class="form" novalidate>
      ${field("Project name", "name", "", { required: true, note: "1–100 chars of [A-Za-z0-9._-]." })}
      <p id="form-error" class="form-error"></p>
      <div class="form-actions">
        <button type="button" class="btn" data-act="cancel">Cancel</button>
        <button type="submit" class="btn btn-primary">Create</button>
      </div>
    </form>`;
  openModal("New project", body);
  body.querySelector('[data-act="cancel"]').addEventListener("click", closeModal);
  body.querySelector("#project-form").addEventListener("submit", async (e) => {
    e.preventDefault();
    try {
      await api("/api/v1/projects", { method: "POST", json: { name: e.target.name.value } });
      closeModal();
      await refreshProjects();
      showBanner("Project ready.", "ok");
    } catch (err) {
      formError(err);
    }
  });
});

// ---- bootstrap --------------------------------------------------------------

async function init() {
  await Promise.all([refreshSshCache(), refreshDbCache()]);
  await Promise.all([refreshSsh(), refreshDb(), refreshProjects()]);
}

init();
