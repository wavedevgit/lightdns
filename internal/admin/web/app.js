const $ = (selector, root = document) => root.querySelector(selector);
const $$ = (selector, root = document) => [...root.querySelectorAll(selector)];

const state = {
  session: null,
  config: null,
  configRevision: null,
  configDirty: false,
  dirtyKind: null,
  modalDirty: false,
  activeModalID: null,
  zones: [],
  selectedZone: null,
  records: [],
  users: [],
  audit: [],
  editingRecordID: null,
  editingUserID: null,
  resetUserID: null
};

const recordHelp = {
  A: ["192.0.2.10", "IPv4 address"],
  AAAA: ["2001:db8::10", "IPv6 address"],
  CNAME: ["target.example.com.", "Canonical target name"],
  MX: ["10 mail.example.com.", "Priority followed by the mail server name"],
  TXT: ["v=spf1 -all", "Text value; quotes are added automatically"],
  NS: ["ns1.example.com.", "Authoritative name server"],
  PTR: ["host.example.com.", "Reverse lookup target name"],
  SRV: ["10 5 443 service.example.com.", "Priority, weight, port, and target"],
  CAA: ['0 issue "letsencrypt.org"', "Flag, tag, and certificate authority value"]
};

let toastTimer;
let confirmResolver;

async function api(path, options = {}) {
  const headers = { ...(options.headers || {}) };
  if (options.body) headers["Content-Type"] = "application/json";
  if (options.method && !["GET", "HEAD"].includes(options.method)) headers["X-LightDNS-Request"] = "dashboard";

  const response = await fetch(path, { ...options, headers });
  const text = response.status === 204 ? "" : await response.text();
  let data = {};
  if (text) {
    try { data = JSON.parse(text); } catch { data = { error: text }; }
  }
  if (!response.ok) {
    if (response.status === 401) location.replace("/login");
    const error = new Error(data.error || `Request failed with status ${response.status}.`);
    error.status = response.status;
    error.code = data.code;
    throw error;
  }
  if (options.captureETag) state.configRevision = response.headers.get("ETag");
  return data;
}

function escapeHTML(value) {
  return String(value ?? "").replace(/[&<>'"]/g, (character) => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", "'": "&#39;", '"': "&quot;"
  })[character]);
}

function lines(value) {
  return value.split("\n").map((line) => line.trim()).filter(Boolean);
}

function formatNumber(value) {
  return Number(value || 0).toLocaleString();
}

function formatDate(value, includeTime = false) {
  if (!value) return "—";
  const options = includeTime
    ? { dateStyle: "medium", timeStyle: "short" }
    : { year: "numeric", month: "short", day: "numeric" };
  return new Intl.DateTimeFormat(undefined, options).format(new Date(value));
}

function notify(message) {
  const dialog = $("dialog[open]");
  if (dialog) {
    const form = $("form", dialog);
    if (form) {
      let error = $(".dialog-error", dialog);
      if (!error) {
        error = document.createElement("p");
        error.className = "dialog-error";
        error.setAttribute("role", "alert");
        form.prepend(error);
      }
      error.textContent = message;
      return;
    }
  }
  const toast = $("#toast");
  toast.textContent = message;
  toast.classList.add("show");
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => toast.classList.remove("show"), 3600);
}

async function withBusy(button, operation) {
  button.disabled = true;
  button.setAttribute("aria-busy", "true");
  try {
    return await operation();
  } catch (error) {
    notify(error.message);
    return null;
  } finally {
    button.disabled = false;
    button.removeAttribute("aria-busy");
  }
}

function setDirty(dirty, kind = "config") {
  state.configDirty = dirty;
  state.dirtyKind = dirty ? kind : null;
  $("#unsaved-bar > span").textContent = kind === "records" ? "DNS records have unsaved changes." : "Configuration has unsaved changes.";
  $("#unsaved-bar").hidden = !dirty;
  if (!dirty) $("#unsaved-bar").classList.remove("shake");
}

function shakeUnsavedBar() {
  const bar = $("#unsaved-bar");
  bar.classList.remove("shake");
  void bar.offsetWidth;
  bar.classList.add("shake");
}

function statusBadge(status) {
  return `<span class="status ${escapeHTML(status)}">${escapeHTML(status)}</span>`;
}

function showView(name, updateHistory = true) {
  const button = $(`[data-view="${CSS.escape(name)}"]`);
  const requestedView = $(`#view-${CSS.escape(name)}`);
  if (!requestedView || button?.hidden) name = "overview";
  const current = $(".view.active")?.id.replace("view-", "");
  if (state.configDirty && current && current !== name) {
    shakeUnsavedBar();
    if (!updateHistory) history.replaceState(null, "", `#${current}`);
    return;
  }
  const navView = name === "zone" ? "zones" : name;
  $$('[data-view]').forEach((item) => item.classList.toggle("active", item.dataset.view === navView));
  $$(".view").forEach((view) => view.classList.toggle("active", view.id === `view-${name}`));
  if (updateHistory) history.replaceState(null, "", `#${name}`);
  if (name === "audit" && !state.audit.length) loadAudit();
}

function confirmAction(title, message, actionLabel = "Confirm") {
  $("#confirm-title").textContent = title;
  $("#confirm-message").textContent = message;
  $("#confirm-action").textContent = actionLabel;
  $("#confirm-dialog").showModal();
  return new Promise((resolve) => { confirmResolver = resolve; });
}

function resolveConfirm(value) {
  $("#confirm-dialog").close();
  if (confirmResolver) confirmResolver(value);
  confirmResolver = null;
}

function closeDialog(id) {
  const dialog = document.getElementById(id);
  if (dialog?.open) dialog.close();
}

function formDialogState(dialog) {
  const controls = $$('input, textarea', dialog).filter((control) => !["button", "submit"].includes(control.type));
  return JSON.stringify(controls.map((control) => [control.id, control.type === "checkbox" ? control.checked : control.value]));
}

function openFormDialog(id) {
  const dialog = document.getElementById(id);
  dialog.dataset.initialState = formDialogState(dialog);
  state.activeModalID = id;
  state.modalDirty = false;
  dialog.showModal();
}

function restoreUnsavedBar() {
  const bar = $("#unsaved-bar");
  $("#toast").before(bar);
  bar.classList.remove("modal-unsaved", "shake");
  bar.hidden = !state.configDirty;
  $("#unsaved-bar > span").textContent = state.dirtyKind === "records" ? "DNS records have unsaved changes." : "Configuration has unsaved changes.";
}

function setModalDirty(dialog, dirty) {
  state.modalDirty = dirty;
  if (!dirty) {
    restoreUnsavedBar();
    return;
  }
  const bar = $("#unsaved-bar");
  $("#unsaved-bar > span").textContent = "This form has unsaved changes.";
  bar.classList.add("modal-unsaved");
  dialog.append(bar);
  bar.hidden = false;
}

function restoreFormDialog(dialog) {
  const values = JSON.parse(dialog.dataset.initialState || "[]");
  values.forEach(([id, value]) => {
    const control = document.getElementById(id);
    if (!control) return;
    if (control.type === "checkbox") control.checked = value;
    else control.value = value;
  });
  const dropdowns = [
    ["zone-owner-dropdown", "zone-owner", "data-zone-owner-value"],
    ["record-type-dropdown", "record-type", "data-record-dialog-type"],
    ["review-status-dropdown", "review-status", "data-review-status"],
    ["user-role-dropdown", "user-role", "data-new-user-role"]
  ];
  dropdowns.forEach(([dropdownID, inputID, attribute]) => {
    if (!dialog.contains(document.getElementById(dropdownID))) return;
    const value = document.getElementById(inputID).value;
    const option = document.querySelector(`[${attribute}="${CSS.escape(value)}"]`);
    if (option) $("summary > span:first-child", document.getElementById(dropdownID)).textContent = option.textContent;
  });
  setModalDirty(dialog, false);
}

function requestCloseDialog(id) {
  const dialog = document.getElementById(id);
  if (!dialog?.open) return;
  if (dialog.dataset.initialState !== formDialogState(dialog)) {
    setModalDirty(dialog, true);
    shakeUnsavedBar();
  } else {
    closeDialog(id);
  }
}

function setFormDropdownValue(dropdownID, inputID, value, label, dispatch = false) {
  const dropdown = document.getElementById(dropdownID);
  const input = document.getElementById(inputID);
  input.value = value;
  $("summary > span:first-child", dropdown).textContent = label;
  dropdown.open = false;
  if (dispatch) input.dispatchEvent(new Event("change", { bubbles: true }));
}

function secureRandomIndex(length) {
  const byte = new Uint8Array(1);
  const limit = Math.floor(256 / length) * length;
  do crypto.getRandomValues(byte); while (byte[0] >= limit);
  return byte[0] % length;
}

function generateTemporaryPassword(length = 20) {
  const sets = ["ABCDEFGHJKLMNPQRSTUVWXYZ", "abcdefghijkmnopqrstuvwxyz", "23456789", "!@#$%&*+-_=?"];
  const alphabet = sets.join("");
  const password = sets.map((set) => set[secureRandomIndex(set.length)]);
  while (password.length < length) password.push(alphabet[secureRandomIndex(alphabet.length)]);
  for (let index = password.length - 1; index > 0; index--) {
    const swap = secureRandomIndex(index + 1);
    [password[index], password[swap]] = [password[swap], password[index]];
  }
  return password.join("");
}

async function copyText(value) {
  try {
    await navigator.clipboard.writeText(value);
    return true;
  } catch {
    return false;
  }
}

function fillConfigForm(config) {
  $("#block-urls").value = (config.blocklists.urls || []).join("\n");
  $("#block-files").value = (config.blocklists.files || []).join("\n");
  $("#denylist").value = (config.blocking.denylist || []).join("\n");
  $("#allowlist").value = (config.blocking.allowlist || []).join("\n");
  $("#block-mode").value = config.blocking.mode;
  $("#block-mode-dropdown summary span").textContent = config.blocking.mode === "null" ? "Null address" : "NXDOMAIN";
  $("#block-refresh").value = config.blocklists.refresh;
  $("#block-ipv4").value = config.blocking.ipv4;
  $("#block-ipv6").value = config.blocking.ipv6;
  $("#block-bytes").value = config.blocklists.max_download_bytes;
  $("#upstream-list").value = (config.upstreams || []).join("\n");
  $("#timeout").value = config.timeout;
  $("#max-questions").value = config.max_questions;
  $("#dnssec").checked = config.dnssec;
  $("#dns-listen").value = config.listen;
  $("#http-listen").value = config.http_listen;
  const zoneLimits = config.zone_limits || { max_total_per_user: 25, max_active_per_user: 10, max_rejected_per_user: 10, appeal_email: "admin@local.invalid" };
  $("#zone-limit-total").value = zoneLimits.max_total_per_user;
  $("#zone-limit-active").value = zoneLimits.max_active_per_user;
  $("#zone-limit-rejected").value = zoneLimits.max_rejected_per_user;
  $("#zone-appeal-email").value = zoneLimits.appeal_email || "admin@local.invalid";
  $("#cache-entries").value = config.cache.entries;
  $("#cache-min").value = config.cache.min_ttl;
  $("#cache-max").value = config.cache.max_ttl;
  $("#tls-cert").value = config.tls.cert_file || "";
  $("#tls-key").value = config.tls.key_file || "";
  $("#dot-listen").value = config.tls.dot_listen || "";
  renderOverrides(config.records || []);
  setDirty(false);
}

function collectConfig() {
  const next = structuredClone(state.config);
  next.records = $$("#override-rows tr").map((row) => ({
    name: $('[data-field="name"]', row).value.trim(),
    type: $('[data-field="type"]', row).value,
    value: $('[data-field="value"]', row).value.trim(),
    ttl: Number($('[data-field="ttl"]', row).value)
  }));
  next.blocklists.urls = lines($("#block-urls").value);
  next.blocklists.files = lines($("#block-files").value);
  next.blocking.denylist = lines($("#denylist").value);
  next.blocking.allowlist = lines($("#allowlist").value);
  next.blocking.mode = $("#block-mode").value;
  next.blocklists.refresh = $("#block-refresh").value.trim();
  next.blocking.ipv4 = $("#block-ipv4").value.trim();
  next.blocking.ipv6 = $("#block-ipv6").value.trim();
  next.blocklists.max_download_bytes = Number($("#block-bytes").value);
  next.upstreams = lines($("#upstream-list").value);
  next.timeout = $("#timeout").value.trim();
  next.max_questions = Number($("#max-questions").value);
  next.dnssec = $("#dnssec").checked;
  next.listen = $("#dns-listen").value.trim();
  next.http_listen = $("#http-listen").value.trim();
  next.zone_limits = {
    max_total_per_user: Number($("#zone-limit-total").value),
    max_active_per_user: Number($("#zone-limit-active").value),
    max_rejected_per_user: Number($("#zone-limit-rejected").value),
    appeal_email: $("#zone-appeal-email").value.trim()
  };
  next.cache.entries = Number($("#cache-entries").value);
  next.cache.min_ttl = $("#cache-min").value.trim();
  next.cache.max_ttl = $("#cache-max").value.trim();
  next.tls = {
    cert_file: $("#tls-cert").value.trim(),
    key_file: $("#tls-key").value.trim(),
    dot_listen: $("#dot-listen").value.trim()
  };
  return next;
}

function addOverride(record = { name: "", type: "A", value: "", ttl: 300 }) {
  const row = $("#override-template").content.firstElementChild.cloneNode(true);
  Object.entries(record).forEach(([field, value]) => {
    const control = $(`[data-field="${field}"]`, row);
    if (control) control.value = value;
  });
  const typeInput = $('[data-field="type"]', row);
  const valueInput = $('[data-field="value"]', row);
  const typeDropdown = $(".record-type-dropdown", row);
  $("summary span", typeDropdown).textContent = typeInput.value;
  valueInput.placeholder = recordHelp[typeInput.value]?.[0] || "Record value";
  Object.keys(recordHelp).forEach((type) => {
    const button = document.createElement("button");
    button.type = "button";
    button.textContent = type;
    button.addEventListener("click", () => {
      typeInput.value = type;
      $("summary span", typeDropdown).textContent = type;
      valueInput.placeholder = recordHelp[type][0];
      typeDropdown.open = false;
      setDirty(true);
      filterOverrides();
    });
    $(".record-type-menu", typeDropdown).append(button);
  });
  $("[data-remove]", row).addEventListener("click", async () => {
    const approved = await confirmAction("Remove override?", `Remove ${$('[data-field="name"]', row).value || "this unsaved override"} from the configuration?`, "Remove");
    if (!approved) return;
    row.remove();
    setDirty(true);
    filterOverrides();
  });
  row.addEventListener("input", () => { setDirty(true); filterOverrides(); });
  row.addEventListener("change", () => { setDirty(true); filterOverrides(); });
  $("#override-rows").append(row);
}

function renderOverrides(records) {
  $("#override-rows").replaceChildren();
  records.forEach(addOverride);
  filterOverrides();
}

function filterOverrides() {
  const query = $("#override-search").value.trim().toLowerCase();
  const type = $("#override-type-filter").dataset.value || "";
  let visible = 0;
  const rows = $$("#override-rows tr");
  rows.forEach((row) => {
    const name = $('[data-field="name"]', row).value.toLowerCase();
    const value = $('[data-field="value"]', row).value.toLowerCase();
    const matches = (!query || name.includes(query) || value.includes(query)) && (!type || $('[data-field="type"]', row).value === type);
    row.hidden = !matches;
    if (matches) visible++;
  });
  $("#override-count").textContent = `${visible} of ${rows.length}`;
  $("#overrides-empty").hidden = visible > 0;
}

async function loadStats() {
  try {
    const stats = await api("/api/stats");
    $("#stat-queries").textContent = formatNumber(stats.queries);
    $("#stat-blocked").textContent = formatNumber(stats.blocked);
    $("#stat-local").textContent = formatNumber(stats.local_answers);
    $("#stat-cache").textContent = `${Number(stats.cache_rate || 0).toFixed(1)}%`;
    $("#stat-domains").textContent = formatNumber(stats.blocked_domains);
    $("#stat-misses").textContent = formatNumber(stats.cache_misses);
    $("#stat-errors").textContent = formatNumber(stats.upstream_errors);
    $("#stat-servfail").textContent = formatNumber(stats.servfail);
    $("#stats-time").textContent = `Updated ${new Date(stats.time).toLocaleTimeString()}`;
  } catch (error) {
    if (error.status !== 401) notify(error.message);
  }
}

function ownerName(ownerID) {
  if (ownerID === state.session.id) return state.session.username;
  return state.users.find((user) => user.id === ownerID)?.username || "Deleted user";
}

function recordSubdomain(name) {
  const apex = `${state.selectedZone.name}.`;
  if (name === apex) return "@";
  return name.endsWith(apex) ? name.slice(0, -apex.length).replace(/\.$/, "") : name;
}

function renderZoneList() {
  const query = $("#zone-search").value.trim().toLowerCase();
  const status = $("#zone-status-filter").dataset.value || "";
  const zones = state.zones.filter((zone) => (!query || zone.name.includes(query)) && (!status || zone.status === status));
  $("#zone-count").textContent = `${zones.length} of ${state.zones.length}`;
  const list = $("#zone-list");
  if (!zones.length) {
    list.innerHTML = '<tr><td colspan="4"><div class="empty-inline">No managed zones match this filter.</div></td></tr>';
    return;
  }
  list.innerHTML = zones.map((zone) => `<tr class="domain-row" data-zone-id="${escapeHTML(zone.id)}"><td><strong>${escapeHTML(zone.name)}</strong></td><td>${statusBadge(zone.status)}</td><td>${escapeHTML(ownerName(zone.owner_id))}</td><td>r${zone.revision}</td></tr>`).join("");
  $$("[data-zone-id]", list).forEach((button) => button.addEventListener("click", () => selectZone(button.dataset.zoneId)));
}

function recordRows() {
  return state.records.map(managedRecordRow).join("");
}

function managedRecordRow(record = null) {
  const type = record?.type || "A";
  return `<tr class="record-row" data-record-id="${escapeHTML(record?.id || "")}">
    <td><input data-field="name" aria-label="Record subdomain" placeholder="@ or www" value="${escapeHTML(record ? recordSubdomain(record.name) : "")}"></td>
    <td><details class="record-type-dropdown custom-dropdown"><summary aria-label="Record type"><span>${escapeHTML(type)}</span><span class="material-symbols-rounded dropdown-chevron" aria-hidden="true">expand_more</span></summary><div class="record-type-menu" role="listbox" aria-label="Choose record type"></div></details><input class="record-type-value" data-field="type" type="hidden" value="${escapeHTML(type)}"></td>
    <td><input data-field="value" aria-label="Record value" placeholder="${escapeHTML(recordHelp[type][0])}" value="${escapeHTML(record?.value || "")}"></td>
    <td><input data-field="ttl" aria-label="Record TTL" type="number" min="1" value="${record?.ttl || 300}"></td>
    <td><button class="remove-record" type="button" data-remove>Remove</button></td>
  </tr>`;
}

function setupManagedRecordRow(row) {
  const typeInput = $('[data-field="type"]', row);
  const valueInput = $('[data-field="value"]', row);
  const dropdown = $(".record-type-dropdown", row);
  Object.keys(recordHelp).forEach((type) => {
    const button = document.createElement("button");
    button.type = "button";
    button.textContent = type;
    button.addEventListener("click", () => {
      typeInput.value = type;
      $("summary span", dropdown).textContent = type;
      valueInput.placeholder = recordHelp[type][0];
      dropdown.open = false;
      filterManagedRecords();
      setDirty(true, "records");
    });
    $(".record-type-menu", dropdown).append(button);
  });
  $$('[data-field]', row).forEach((input) => {
    input.addEventListener("input", () => {
      filterManagedRecords();
      setDirty(true, "records");
    });
    input.addEventListener("change", () => setDirty(true, "records"));
    input.addEventListener("keydown", (event) => {
      if (event.key === "Enter") {
        event.preventDefault();
        setDirty(true, "records");
      }
    });
  });
  $("[data-remove]", row).addEventListener("click", async () => {
    if (row.dataset.recordId) {
      const record = state.records.find((item) => item.id === row.dataset.recordId);
      const approved = await confirmAction("Remove record?", `${record?.name || "This record"} will be removed when you save changes.`, "Remove");
      if (!approved) return;
    }
    row.remove();
    filterManagedRecords();
    setDirty(true, "records");
  });
}

function managedRecordInput(row) {
  return {
    name: $('[data-field="name"]', row).value.trim(),
    type: $('[data-field="type"]', row).value,
    value: $('[data-field="value"]', row).value.trim(),
    ttl: Number($('[data-field="ttl"]', row).value)
  };
}

function managedRecordChanged(record, input) {
  return recordSubdomain(record.name) !== input.name || record.type !== input.type || record.value !== input.value || record.ttl !== input.ttl;
}

async function saveManagedRecords() {
  const rows = $$("#managed-record-rows tr");
  const entries = rows.map((row) => ({ id: row.dataset.recordId, input: managedRecordInput(row) }));
  const invalid = entries.find(({ input }) => !input.name || !input.value || !Number.isInteger(input.ttl) || input.ttl < 1);
  if (invalid) throw new Error("Each DNS record needs a name, value, and positive whole-number TTL.");

  const existingIDs = new Set(entries.map(({ id }) => id).filter(Boolean));
  const deleted = state.records.filter((record) => !existingIDs.has(record.id));
  let revision = state.selectedZone.revision;
  try {
    for (const record of deleted) {
      await api(`/api/zones/${state.selectedZone.id}/records/${record.id}`, { method: "DELETE", headers: { "If-Match": String(revision) } });
      revision++;
    }
    for (const entry of entries) {
      const record = entry.id ? state.records.find((item) => item.id === entry.id) : null;
      if (record && !managedRecordChanged(record, entry.input)) continue;
      await api(`/api/zones/${state.selectedZone.id}/records${entry.id ? `/${entry.id}` : ""}`, {
        method: entry.id ? "PUT" : "POST",
        headers: { "If-Match": String(revision) },
        body: JSON.stringify(entry.input)
      });
      revision++;
    }
    setDirty(false);
    await refreshSelectedZone();
    notify("DNS record changes saved.");
  } catch (error) {
    setDirty(false);
    await refreshSelectedZone();
    if (error.status === 409) throw new Error("The zone changed elsewhere. Latest records loaded; review and retry.");
    throw error;
  }
}

function addManagedRecordRow() {
  const body = $("#managed-record-rows");
  body.insertAdjacentHTML("beforeend", managedRecordRow());
  const row = body.lastElementChild;
  setupManagedRecordRow(row);
  filterManagedRecords();
  setDirty(true, "records");
  $('[data-field="name"]', row).focus();
}

function filterManagedRecords() {
  const query = $("#managed-record-search").value.trim().toLowerCase();
  const type = $("#managed-record-type-filter").dataset.value || "";
  let visible = 0;
  const rows = $$("#managed-record-rows tr");
  rows.forEach((row) => {
    const name = $('[data-field="name"]', row).value.toLowerCase();
    const value = $('[data-field="value"]', row).value.toLowerCase();
    const matches = (!query || name.includes(query) || value.includes(query)) && (!type || $('[data-field="type"]', row).value === type);
    row.hidden = !matches;
    if (matches) visible++;
  });
  $("#managed-record-count").textContent = `${visible} of ${rows.length}`;
  $("#managed-records-empty").hidden = visible > 0;
}

function renderZoneDetail() {
  const detail = $("#zone-detail");
  const zone = state.selectedZone;
  if (!zone) {
    detail.innerHTML = '<div class="empty-panel"><h2>Select a zone</h2><p>Choose a zone to inspect its authority state and records.</p></div>';
    return;
  }
  const admin = state.session.role === "admin";
  const reviewButton = admin ? '<button type="button" class="secondary" id="review-zone">Review status</button>' : "";
  const technical = admin ? `<details class="zone-technical"><summary>Technical details<span class="material-symbols-rounded dropdown-chevron" aria-hidden="true">expand_more</span></summary><dl><div><dt>Zone ID</dt><dd class="mono">${escapeHTML(zone.id)}</dd></div><div><dt>Owner</dt><dd>${escapeHTML(ownerName(zone.owner_id))}</dd></div><div><dt>Revision</dt><dd>r${zone.revision}</dd></div><div><dt>Last updated</dt><dd>${escapeHTML(formatDate(zone.updated_at))}</dd></div></dl></details>` : "";
  const header = `<header class="zone-detail-header"><div class="zone-title"><h1>${escapeHTML(zone.name)}</h1>${statusBadge(zone.status)}</div><div class="detail-actions">${reviewButton}<button type="button" class="danger-button" id="delete-zone">Delete zone</button></div></header>${technical}`;
  if (zone.status !== "active") {
    const states = {
      pending: ["Awaiting approval", "This zone is in review. DNS records become available after an administrator approves it.", "schedule"],
      rejected: ["Zone rejected", zone.rejection_reason || "An administrator rejected this zone.", "cancel"],
      suspended: ["Zone suspended", zone.rejection_reason || "DNS records are unavailable while this zone is suspended.", "pause_circle"]
    };
    const [title, message, icon] = states[zone.status] || ["Zone unavailable", "This zone is not currently active.", "error"];
    const appeal = zone.status === "suspended" && zone.appeal_email ? `<p class="zone-appeal">To appeal, contact <a href="mailto:${escapeHTML(zone.appeal_email)}">${escapeHTML(zone.appeal_email)}</a>.</p>` : "";
    detail.innerHTML = `${header}<section class="zone-state-screen ${escapeHTML(zone.status)}"><span class="material-symbols-rounded zone-state-icon" aria-hidden="true">${icon}</span><h2>${escapeHTML(title)}</h2><p>${escapeHTML(message)}</p>${appeal}</section>`;
    $("#delete-zone").addEventListener("click", deleteSelectedZone);
    $("#review-zone")?.addEventListener("click", openReviewDialog);
    return;
  }
  detail.innerHTML = `${header}
    <h2 class="managed-records-title">DNS records</h2>
    <div class="records-toolbar"><input id="managed-record-search" type="search" placeholder="Search records" aria-label="Search records"><details id="managed-record-type-filter" class="filter-dropdown custom-dropdown" data-value=""><summary><span>All types</span><span class="material-symbols-rounded dropdown-chevron" aria-hidden="true">expand_more</span></summary><div class="filter-menu" role="listbox" aria-label="Filter by record type">${["", ...Object.keys(recordHelp)].map((type) => `<button type="button" data-managed-type="${type}">${type || "All types"}</button>`).join("")}</div></details><small id="managed-record-count">0 records</small><button type="button" id="add-managed-record">Add record</button></div>
    <div class="table-wrap"><table class="record-table editable-table"><colgroup><col class="record-name-column"><col class="record-type-column"><col class="record-value-column"><col class="record-ttl-column"><col class="record-action-column"></colgroup><thead><tr><th>Name</th><th>Type</th><th>Value</th><th>TTL</th><th aria-label="Action"></th></tr></thead><tbody id="managed-record-rows">${recordRows()}</tbody></table><p id="managed-records-empty" class="empty-state">No matching records.</p></div>`;
  $("#add-managed-record").addEventListener("click", addManagedRecordRow);
  $("#delete-zone").addEventListener("click", deleteSelectedZone);
  $("#review-zone")?.addEventListener("click", openReviewDialog);
  $$("#managed-record-rows .record-row", detail).forEach(setupManagedRecordRow);
  $("#managed-record-search").addEventListener("input", filterManagedRecords);
  $$('[data-managed-type]').forEach((button) => button.addEventListener("click", () => {
    const filter = $("#managed-record-type-filter");
    filter.dataset.value = button.dataset.managedType;
    $("summary span", filter).textContent = button.textContent;
    filter.open = false;
    filterManagedRecords();
  }));
  filterManagedRecords();
}

async function loadZones() {
  const result = await api("/api/zones");
  state.zones = result.zones || [];
  renderZoneList();
}

async function selectZone(zoneID, updateHistory = true) {
  try {
    const [zone, result] = await Promise.all([api(`/api/zones/${zoneID}`), api(`/api/zones/${zoneID}/records`)]);
    state.selectedZone = zone;
    state.records = result.records || [];
    renderZoneList();
    renderZoneDetail();
    showView("zone", false);
    if (updateHistory) history.replaceState(null, "", `#zone/${zoneID}`);
  } catch (error) {
    notify(error.message);
  }
}

async function refreshSelectedZone() {
  if (!state.selectedZone) return;
  const zoneID = state.selectedZone.id;
  const [zone, recordsResult, zonesResult] = await Promise.all([
    api(`/api/zones/${zoneID}`),
    api(`/api/zones/${zoneID}/records`),
    api("/api/zones")
  ]);
  state.selectedZone = zone;
  state.records = recordsResult.records || [];
  state.zones = zonesResult.zones || [];
  renderZoneList();
  renderZoneDetail();
}

function populateOwners() {
  const users = state.users.filter((user) => user.enabled);
  const menu = $("#zone-owner-options");
  menu.innerHTML = users.map((user) => `<button type="button" data-zone-owner-value="${escapeHTML(user.id)}">${escapeHTML(user.username)} · ${escapeHTML(user.role)}</button>`).join("");
  $$('[data-zone-owner-value]', menu).forEach((button) => button.addEventListener("click", () => {
    setFormDropdownValue("zone-owner-dropdown", "zone-owner", button.dataset.zoneOwnerValue, button.textContent, true);
  }));
  const selected = users.find((user) => user.id === $("#zone-owner").value) || users.find((user) => user.id === state.session.id) || users[0];
  if (selected) setFormDropdownValue("zone-owner-dropdown", "zone-owner", selected.id, `${selected.username} · ${selected.role}`);
}

function openRecordDialog(recordID = null) {
  const record = recordID ? state.records.find((item) => item.id === recordID) : null;
  state.editingRecordID = recordID;
  $("#record-dialog-title").textContent = record ? "Edit record" : "Add record";
  $("#record-name").value = record ? recordSubdomain(record.name) : "";
  $("#record-name-help").textContent = `Use @ for ${state.selectedZone.name}; other names are relative to this zone.`;
  setFormDropdownValue("record-type-dropdown", "record-type", record?.type || "A", record?.type || "A");
  $("#record-value").value = record?.value || "";
  $("#record-ttl").value = record?.ttl || 300;
  updateRecordHelp();
  openFormDialog("record-dialog");
  $("#record-name").focus();
}

function updateRecordHelp() {
  const [placeholder, help] = recordHelp[$("#record-type").value];
  $("#record-value").placeholder = placeholder;
  $("#record-value-help").textContent = help;
}

async function deleteRecord(recordID) {
  const record = state.records.find((item) => item.id === recordID);
  const approved = await confirmAction("Delete record?", `${record?.name || "This record"} will immediately be removed from the zone snapshot.`, "Delete record");
  if (!approved) return;
  try {
    await api(`/api/zones/${state.selectedZone.id}/records/${recordID}`, { method: "DELETE", headers: { "If-Match": String(state.selectedZone.revision) } });
    await refreshSelectedZone();
    notify("Record deleted and authority snapshot updated.");
  } catch (error) {
    if (error.status === 409) await refreshSelectedZone();
    notify(error.status === 409 ? "The zone changed elsewhere. Latest revision loaded; review and retry." : error.message);
  }
}

async function deleteSelectedZone() {
  const zone = state.selectedZone;
  const approved = await confirmAction("Delete managed zone?", `${zone.name} and all of its records will be permanently deleted.`, "Delete zone");
  if (!approved) return;
  try {
    await api(`/api/zones/${zone.id}`, { method: "DELETE" });
    state.selectedZone = null;
    state.records = [];
    await loadZones();
    showView("zones");
    notify("Managed zone deleted.");
  } catch (error) { notify(error.message); }
}

function openReviewDialog() {
  const status = state.selectedZone.status === "pending" ? "active" : state.selectedZone.status;
  const labels = { active: "Approve and activate", rejected: "Reject", suspended: "Suspend" };
  setFormDropdownValue("review-status-dropdown", "review-status", status, labels[status]);
  $("#review-reason").value = state.selectedZone.rejection_reason || "";
  updateReviewReason();
  openFormDialog("review-dialog");
}

function updateReviewReason() {
  const reasonRequired = $("#review-status").value !== "active";
  $("#review-reason").required = reasonRequired;
  $("#review-reason-label").firstChild.textContent = reasonRequired ? "Reason (required)" : "Reason";
}

function openUserDialog(userID = null) {
  const user = userID ? state.users.find((item) => item.id === userID) : null;
  state.editingUserID = user?.id || null;
  $("#user-form").reset();
  $("#user-dialog-title").textContent = user ? "Edit user" : "Create user";
  $("#user-submit").textContent = user ? "Save user" : "Create user";
  $("#user-submit").hidden = false;
  $("#user-name").value = user?.username || "";
  $("#user-email").value = user?.email || "";
  $("#user-password-label").hidden = Boolean(user);
  $("#user-password").required = !user;
  $("#user-must-change-label").hidden = Boolean(user);
  $("#user-must-change").checked = !user;
  const role = user?.role || "user";
  setFormDropdownValue("user-role-dropdown", "user-role", role, role === "admin" ? "Administrator" : "User");
  const editingSelf = user?.id === state.session.id;
  $("#user-role-dropdown").classList.toggle("disabled", editingSelf);
  $("#user-role-dropdown summary").setAttribute("aria-disabled", String(editingSelf));
  openFormDialog("user-dialog");
  $("#user-name").focus();
}

function renderUsers() {
  const body = $("#user-rows");
  body.innerHTML = state.users.map((user) => {
    const self = user.id === state.session.id;
    const search = `${user.username} ${user.email} ${user.id} ${user.role}`.toLowerCase();
    const roleLabel = user.role === "admin" ? "Administrator" : "User";
    return `<tr data-user-row data-search="${escapeHTML(search)}" data-role="${escapeHTML(user.role)}" data-banned="${!user.enabled}"><td class="user-identity"><div><strong>${escapeHTML(user.username)}</strong>${self ? '<span class="self-label">You</span>' : ""}</div><small title="${escapeHTML(user.id)}">${escapeHTML(user.email)}</small></td><td><details class="user-role-dropdown form-dropdown custom-dropdown${self ? " disabled" : ""}" data-user-role="${escapeHTML(user.id)}" data-value="${escapeHTML(user.role)}"><summary aria-label="Role for ${escapeHTML(user.username)}" aria-disabled="${self}"><span>${roleLabel}</span><span class="material-symbols-rounded dropdown-chevron" aria-hidden="true">expand_more</span></summary><div class="form-dropdown-menu" role="listbox"><button type="button" data-role-value="user">User</button><button type="button" data-role-value="admin">Administrator</button></div></details></td><td>${statusBadge(user.enabled ? "enabled" : "banned")}</td><td>${user.must_change_password ? statusBadge("change") : '<span class="password-current">Current</span>'}</td><td>${escapeHTML(formatDate(user.updated_at))}</td><td><div class="row-actions"><button class="secondary user-action" type="button" data-edit-user="${escapeHTML(user.id)}">Edit</button><button class="secondary user-action" type="button" data-reset-user="${escapeHTML(user.id)}">Reset password</button><button class="${user.enabled ? "warning-button" : "secondary"} user-action" type="button" data-toggle-user="${escapeHTML(user.id)}" data-enabled="${user.enabled}" ${self ? "disabled" : ""}>${user.enabled ? "Ban" : "Unban"}</button><button class="danger-button user-action" type="button" data-delete-user="${escapeHTML(user.id)}" ${self ? "disabled" : ""}>Delete</button></div></td></tr>`;
  }).join("");
  $$(".user-role-dropdown", body).forEach((dropdown) => {
    if (dropdown.classList.contains("disabled")) {
      dropdown.addEventListener("toggle", () => { dropdown.open = false; });
      return;
    }
    $$("[data-role-value]", dropdown).forEach((button) => button.addEventListener("click", () => {
      dropdown.open = false;
      updateUser(dropdown.dataset.userRole, { role: button.dataset.roleValue });
    }));
  });
  $$('[data-edit-user]', body).forEach((button) => button.addEventListener("click", () => openUserDialog(button.dataset.editUser)));
  $$("[data-toggle-user]", body).forEach((button) => button.addEventListener("click", () => toggleUser(button)));
  $$("[data-reset-user]", body).forEach((button) => button.addEventListener("click", () => openPasswordReset(button.dataset.resetUser)));
  $$("[data-delete-user]", body).forEach((button) => button.addEventListener("click", () => deleteUser(button.dataset.deleteUser)));
  filterUsers();
  populateOwners();
}

function filterUsers() {
  const query = $("#user-search").value.trim().toLowerCase();
  const filter = $("#user-filter").dataset.value || "";
  let visible = 0;
  const rows = $$("[data-user-row]");
  rows.forEach((row) => {
    const matchesFilter = !filter || (filter === "banned" ? row.dataset.banned === "true" : row.dataset.role === filter);
    const matches = (!query || row.dataset.search.includes(query)) && matchesFilter;
    row.hidden = !matches;
    if (matches) visible++;
  });
  $("#user-count").textContent = `${visible} of ${rows.length}`;
  $("#users-empty").hidden = visible > 0;
}

async function loadUsers() {
  const result = await api("/api/users");
  state.users = result.users || [];
  renderUsers();
  renderZoneList();
  renderZoneDetail();
  if (state.audit.length) renderAudit();
}

async function updateUser(userID, patch, message = "User access updated.") {
  try {
    await api(`/api/users/${userID}`, { method: "PATCH", body: JSON.stringify(patch) });
    await loadUsers();
    notify(message);
  } catch (error) {
    await loadUsers();
    notify(error.message);
  }
}

async function toggleUser(button) {
  const user = state.users.find((item) => item.id === button.dataset.toggleUser);
  const enabled = button.dataset.enabled !== "true";
  if (!enabled) {
    const approved = await confirmAction("Ban user?", `${user.username} will be signed out immediately and blocked from the control plane.`, "Ban user");
    if (!approved) return;
  }
  await updateUser(user.id, { enabled }, enabled ? "User unbanned." : "User banned.");
}

async function deleteUser(userID) {
  const user = state.users.find((item) => item.id === userID);
  const approved = await confirmAction("Delete user?", `${user.username} will be permanently removed from user management. This cannot be undone.`, "Delete user");
  if (!approved) return;
  try {
    await api(`/api/users/${userID}`, { method: "DELETE" });
    await loadUsers();
    notify("User deleted.");
  } catch (error) {
    notify(error.message);
  }
}

function openPasswordReset(userID) {
  const user = state.users.find((item) => item.id === userID);
  state.resetUserID = userID;
  $("#password-reset-user").textContent = `Set a temporary password for ${user.username}. Existing sessions will be revoked.`;
  $("#password-reset-form").reset();
  $("#reset-must-change").checked = true;
  openFormDialog("password-reset-dialog");
}

function relativeDate(value) {
  const seconds = Math.round((new Date(value).getTime() - Date.now()) / 1000);
  const formatter = new Intl.RelativeTimeFormat(undefined, { numeric: "auto" });
  if (Math.abs(seconds) < 60) return formatter.format(seconds, "second");
  const minutes = Math.round(seconds / 60);
  if (Math.abs(minutes) < 60) return formatter.format(minutes, "minute");
  const hours = Math.round(minutes / 60);
  if (Math.abs(hours) < 24) return formatter.format(hours, "hour");
  const days = Math.round(hours / 24);
  if (Math.abs(days) < 30) return formatter.format(days, "day");
  return formatDate(value);
}

function auditPresentation(event) {
  const details = event.details || {};
  const zone = state.zones.find((item) => item.id === (details.zone_id || event.target_id));
  const user = state.users.find((item) => item.id === event.target_id);
  const resource = event.target_type === "zone"
    ? (zone?.name || details.name || "Managed zone")
    : event.target_type === "user"
      ? (user?.username || "User account")
      : event.target_type === "record"
        ? (details.name ? `${details.name} ${details.type || "record"}` : zone?.name || "DNS record")
        : "Resolver settings";
  const presentations = {
    "user.create": ["User created", `A ${details.role || "user"} account was added.`, "success"],
    "user.update": [details.enabled === false ? "User banned" : details.enabled === true ? "User unbanned" : details.username || details.email ? "User details updated" : "User role changed", details.role ? `Role changed to ${details.role}.` : details.enabled === false ? "Control-plane access was revoked." : details.enabled === true ? "Control-plane access was restored." : "The username or email address changed.", details.enabled === false ? "danger" : details.enabled === true ? "success" : "info"],
    "user.delete": ["User deleted", "The account was removed from user management.", "danger"],
    "user.password_reset": ["Password reset", details.must_change_password ? "A temporary password was issued and must be changed at sign-in." : "The account password was reset.", "warning"],
    "user.password_change": ["Password changed", "The user changed their own password.", "info"],
    "zone.create": ["Zone requested", `${details.name || "A managed zone"} was submitted for approval.`, "info"],
    "zone.review": [details.status === "active" ? "Zone approved" : details.status === "rejected" ? "Zone rejected" : "Zone suspended", details.reason || (details.status === "active" ? "Authoritative DNS management was enabled." : "The zone review state changed."), details.status === "active" ? "success" : details.status === "rejected" ? "danger" : "warning"],
    "zone.delete": ["Zone deleted", "The managed zone and its records were removed.", "danger"],
    "record.create": ["DNS record added", `${details.type || "Record"} ${details.name || "entry"} was added.`, "success"],
    "record.update": ["DNS record updated", "The record value or configuration changed.", "info"],
    "record.delete": ["DNS record removed", "The record was removed from the authoritative zone.", "danger"],
    "settings.update": ["Resolver settings updated", details.revision ? `Configuration revision ${details.revision} was applied.` : "Resolver configuration was changed.", "info"]
  };
  const icons = {
    user: "person",
    zone: "language",
    record: "dns",
    settings: "settings"
  };
  if (presentations[event.action]) return { title: presentations[event.action][0], summary: presentations[event.action][1], tone: presentations[event.action][2], resource, icon: icons[event.target_type] || icons.settings };
  const title = event.action.replace(/[._-]+/g, " ").replace(/^./, (character) => character.toUpperCase());
  return { title, summary: "A control-plane change was recorded.", tone: "info", resource, icon: icons[event.target_type] || icons.settings };
}

function auditDay(value) {
  const date = new Date(value);
  const today = new Date();
  const yesterday = new Date();
  yesterday.setDate(today.getDate() - 1);
  if (date.toDateString() === today.toDateString()) return "Today";
  if (date.toDateString() === yesterday.toDateString()) return "Yesterday";
  return new Intl.DateTimeFormat(undefined, { month: "long", day: "numeric", year: "numeric" }).format(date);
}

function auditActorControl(event) {
  const user = state.users.find((item) => item.id === event.actor_id);
  if (!user) return `<span>${event.actor_id ? "Former user" : "System"}</span>`;
  const self = user.id === state.session.id;
  return `<details class="audit-actor-dropdown custom-dropdown" data-audit-actor="${escapeHTML(user.id)}"><summary aria-label="Actions for ${escapeHTML(user.username)}"><span>${escapeHTML(user.username)}</span><span class="material-symbols-rounded dropdown-chevron" aria-hidden="true">expand_more</span></summary><div class="form-dropdown-menu audit-actor-menu" role="menu"><button type="button" role="menuitem" class="${user.enabled ? "audit-ban-action" : ""}" data-audit-toggle-user="${escapeHTML(user.id)}" data-enabled="${user.enabled}" ${self ? "disabled" : ""}>${user.enabled ? "Ban user" : "Unban user"}</button><button type="button" role="menuitem" class="audit-delete-action" data-audit-delete-user="${escapeHTML(user.id)}" ${self ? "disabled" : ""}>Delete user</button></div></details>`;
}

function renderAudit() {
  const list = $("#audit-list");
  if (!state.audit.length) {
    list.innerHTML = '<div class="empty-inline">No audit events have been recorded.</div>';
    $("#audit-count").textContent = "0 events";
    $("#load-more-audit").hidden = true;
    return;
  }
  const groups = new Map();
  state.audit.forEach((event) => {
    const day = auditDay(event.created_at);
    if (!groups.has(day)) groups.set(day, []);
    groups.get(day).push(event);
  });
  list.innerHTML = [...groups].map(([day, events]) => `<section class="audit-day" data-audit-group><h2>${escapeHTML(day)}</h2>${events.map((event) => {
    const details = JSON.stringify(event.details || {});
    const actor = state.users.find((user) => user.id === event.actor_id)?.username || (event.actor_id ? "Former user" : "System");
    const presentation = auditPresentation(event);
    const searchable = `${actor} ${event.action} ${presentation.title} ${presentation.summary} ${presentation.resource} ${details}`.toLowerCase();
    return `<article class="audit-event" data-audit-event data-search="${escapeHTML(searchable)}"><span class="audit-icon ${presentation.tone}" aria-hidden="true"><span class="material-symbols-rounded">${presentation.icon}</span></span><div class="audit-content"><div class="audit-title"><strong>${escapeHTML(presentation.title)}</strong><span class="audit-resource" title="${escapeHTML(presentation.resource)}">${escapeHTML(presentation.resource)}</span></div><p>${escapeHTML(presentation.summary)}</p><div class="audit-meta">${auditActorControl(event)}<span aria-hidden="true">·</span><time datetime="${escapeHTML(event.created_at)}" title="${escapeHTML(formatDate(event.created_at, true))}">${escapeHTML(relativeDate(event.created_at))}</time></div></div></article>`;
  }).join("")}</section>`).join("");
  $$('[data-audit-toggle-user]', list).forEach((button) => button.addEventListener("click", () => {
    button.closest("details").open = false;
    toggleUser({ dataset: { toggleUser: button.dataset.auditToggleUser, enabled: button.dataset.enabled } });
  }));
  $$('[data-audit-delete-user]', list).forEach((button) => button.addEventListener("click", () => {
    button.closest("details").open = false;
    deleteUser(button.dataset.auditDeleteUser);
  }));
  filterAudit();
  $("#load-more-audit").hidden = state.audit.length % 50 !== 0;
}

function filterAudit() {
  const query = $("#audit-search").value.trim().toLowerCase();
  let visible = 0;
  const events = $$("[data-audit-event]");
  events.forEach((event) => {
    const matches = !query || event.dataset.search.includes(query);
    event.hidden = !matches;
    if (matches) visible++;
  });
  $$('[data-audit-group]').forEach((group) => { group.hidden = !$$('[data-audit-event]:not([hidden])', group).length; });
  $("#audit-count").textContent = `${visible} event${visible === 1 ? "" : "s"}`;
}

async function loadAudit(append = false) {
  const button = append ? $("#load-more-audit") : $("#refresh-audit");
  await withBusy(button, async () => {
    const before = append && state.audit.length ? `&before=${state.audit.at(-1).id}` : "";
    const result = await api(`/api/audit?limit=50${before}`);
    state.audit = append ? [...state.audit, ...(result.events || [])] : (result.events || []);
    renderAudit();
  });
}

async function boot() {
  state.session = await api("/api/session");
  if (state.session.must_change_password) {
    location.replace("/change-password");
    return;
  }
  const admin = state.session.role === "admin";
  $$('[data-admin-only]').forEach((element) => { element.hidden = !admin; });
  const tasks = [loadZones(), loadStats()];
  if (admin) {
    tasks.push(loadUsers());
    tasks.push(api("/api/settings", { captureETag: true }).then((config) => {
      state.config = config;
      fillConfigForm(config);
    }));
  }
  await Promise.all(tasks);

  const requested = location.hash.slice(1) || "overview";
  if (requested.startsWith("zone/")) await selectZone(requested.slice(5), false);
  else showView(requested, false);
  $("#boot-state").hidden = true;
  $("#app").hidden = false;
}

$$('[data-view]').forEach((button) => button.addEventListener("click", () => {
  showView(button.dataset.view);
}));

$$('[data-go]').forEach((button) => button.addEventListener("click", () => showView(button.dataset.go)));
$(".brand").addEventListener("click", (event) => { event.preventDefault(); showView("overview"); });
window.addEventListener("hashchange", () => {
  const requested = location.hash.slice(1) || "overview";
  if (requested.startsWith("zone/")) selectZone(requested.slice(5), false);
  else showView(requested, false);
});

$$('[data-close]').forEach((button) => button.addEventListener("click", () => requestCloseDialog(button.dataset.close)));
$$('dialog').forEach((dialog) => {
  if (dialog.id !== "confirm-dialog") {
    dialog.addEventListener("click", (event) => { if (event.target === dialog) requestCloseDialog(dialog.id); });
    dialog.addEventListener("cancel", (event) => { event.preventDefault(); requestCloseDialog(dialog.id); });
    const form = $("form", dialog);
    ["input", "change"].forEach((eventName) => form?.addEventListener(eventName, () => {
      if (dialog.open) setModalDirty(dialog, dialog.dataset.initialState !== formDialogState(dialog));
    }));
  }
  dialog.addEventListener("close", () => {
    $(".dialog-error", dialog)?.remove();
    if (state.activeModalID === dialog.id) {
      state.activeModalID = null;
      state.modalDirty = false;
      restoreUnsavedBar();
    }
    delete dialog.dataset.initialState;
  });
});
$("#confirm-cancel").addEventListener("click", () => resolveConfirm(false));
$("#confirm-action").addEventListener("click", () => resolveConfirm(true));
$("#confirm-dialog").addEventListener("cancel", (event) => { event.preventDefault(); resolveConfirm(false); });
$$('[data-record-dialog-type]').forEach((button) => button.addEventListener("click", () => {
  setFormDropdownValue("record-type-dropdown", "record-type", button.dataset.recordDialogType, button.textContent, true);
}));
$$('[data-review-status]').forEach((button) => button.addEventListener("click", () => {
  setFormDropdownValue("review-status-dropdown", "review-status", button.dataset.reviewStatus, button.textContent, true);
}));
$$('[data-new-user-role]').forEach((button) => button.addEventListener("click", () => {
  if ($("#user-role-dropdown").classList.contains("disabled")) return;
  setFormDropdownValue("user-role-dropdown", "user-role", button.dataset.newUserRole, button.textContent, true);
}));
$("#user-role-dropdown").addEventListener("toggle", () => {
  if ($("#user-role-dropdown").classList.contains("disabled")) $("#user-role-dropdown").open = false;
});
$$('[data-generate-password]').forEach((button) => button.addEventListener("click", () => {
  const input = document.getElementById(button.dataset.generatePassword);
  input.value = generateTemporaryPassword();
  input.dispatchEvent(new Event("input", { bubbles: true }));
  input.focus();
}));
$$('[data-copy-password]').forEach((button) => button.addEventListener("click", async () => {
  const input = document.getElementById(button.dataset.copyPassword);
  if (!input.value) {
    input.setCustomValidity("Generate or enter a temporary password first.");
    input.reportValidity();
    input.setCustomValidity("");
    return;
  }
  if (await copyText(input.value)) {
    const label = $("span:last-child", button);
    label.textContent = "Copied";
    setTimeout(() => { if (label.isConnected) label.textContent = "Copy"; }, 1400);
  } else {
    notify("The temporary password could not be copied. Select it manually instead.");
  }
}));

$("#zone-search").addEventListener("input", renderZoneList);
$("#back-to-zones").addEventListener("click", () => showView("zones"));
$$('[data-zone-status]').forEach((button) => button.addEventListener("click", () => {
  const filter = $("#zone-status-filter");
  filter.dataset.value = button.dataset.zoneStatus;
  $("summary span", filter).textContent = button.textContent;
  filter.open = false;
  renderZoneList();
}));
$("#add-zone").addEventListener("click", () => {
  $("#zone-form").reset();
  populateOwners();
  openFormDialog("zone-dialog");
  $("#zone-name").focus();
});
$("#zone-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const button = $('button[type="submit"]', event.currentTarget);
  await withBusy(button, async () => {
    const body = { name: $("#zone-name").value.trim() };
    if (state.session.role === "admin") body.owner_id = $("#zone-owner").value;
    const zone = await api("/api/zones", { method: "POST", body: JSON.stringify(body) });
    closeDialog("zone-dialog");
    await loadZones();
    await selectZone(zone.id);
    notify(zone.status === "pending" ? "Zone created and queued for review." : "Zone created.");
  });
});

$("#record-type").addEventListener("change", updateRecordHelp);
$("#record-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const button = $('button[type="submit"]', event.currentTarget);
  await withBusy(button, async () => {
    const body = {
      name: $("#record-name").value.trim(),
      type: $("#record-type").value,
      value: $("#record-value").value.trim(),
      ttl: Number($("#record-ttl").value)
    };
    const suffix = state.editingRecordID ? `/${state.editingRecordID}` : "";
    try {
      await api(`/api/zones/${state.selectedZone.id}/records${suffix}`, {
        method: state.editingRecordID ? "PUT" : "POST",
        headers: { "If-Match": String(state.selectedZone.revision) },
        body: JSON.stringify(body)
      });
    } catch (error) {
      if (error.status === 409) {
        await refreshSelectedZone();
        throw new Error("The zone changed elsewhere. Latest revision loaded; review and retry.");
      }
      throw error;
    }
    closeDialog("record-dialog");
    await refreshSelectedZone();
    notify(state.editingRecordID ? "Record updated." : "Record added.");
  });
});

$("#review-status").addEventListener("change", updateReviewReason);
$("#review-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const button = $('button[type="submit"]', event.currentTarget);
  await withBusy(button, async () => {
    try {
      await api(`/api/zones/${state.selectedZone.id}/review`, {
        method: "POST",
        body: JSON.stringify({ status: $("#review-status").value, reason: $("#review-reason").value.trim(), revision: state.selectedZone.revision })
      });
    } catch (error) {
      if (error.status === 409) await refreshSelectedZone();
      throw error;
    }
    closeDialog("review-dialog");
    await refreshSelectedZone();
    notify("Zone state updated and authority reconciled.");
  });
});

$("#add-user").addEventListener("click", () => openUserDialog());
$("#user-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const button = $('button[type="submit"]', event.currentTarget);
  await withBusy(button, async () => {
    const username = $("#user-name").value.trim();
    const email = $("#user-email").value.trim();
    const role = $("#user-role").value;
    if (state.editingUserID) {
      const updated = await api(`/api/users/${state.editingUserID}`, { method: "PATCH", body: JSON.stringify({ username, email, role }) });
      if (updated.id === state.session.id) state.session = { ...state.session, ...updated };
      closeDialog("user-dialog");
      await loadUsers();
      notify("User details updated.");
      return;
    }
    const password = $("#user-password").value;
    const credentials = `LightDNS sign-in\nURL: ${location.origin}/login\nUsername: ${username}\nEmail: ${email}\nTemporary password: ${password}`;
    const copyPromise = copyText(credentials);
    await api("/api/users", { method: "POST", body: JSON.stringify({ username, email, password, role, must_change_password: $("#user-must-change").checked }) });
    const copied = await copyPromise;
    closeDialog("user-dialog");
    await loadUsers();
    notify(copied ? "User created. Sign-in details copied to the clipboard." : "User created, but the browser blocked clipboard access.");
  });
});
$("#password-reset-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const button = $('button[type="submit"]', event.currentTarget);
  await withBusy(button, async () => {
    await api(`/api/users/${state.resetUserID}/password-reset`, { method: "POST", body: JSON.stringify({ password: $("#reset-password").value, must_change_password: $("#reset-must-change").checked }) });
    closeDialog("password-reset-dialog");
    await loadUsers();
    notify("Password reset and existing sessions revoked.");
  });
});

$("#change-password").addEventListener("click", () => {
  $("#change-password-form").reset();
  openFormDialog("change-password-dialog");
  $("#current-password").focus();
});
$("#change-password-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  if ($("#new-password").value !== $("#confirm-password").value) {
    $("#confirm-password").setCustomValidity("Passwords do not match.");
    $("#confirm-password").reportValidity();
    return;
  }
  $("#confirm-password").setCustomValidity("");
  const button = $('button[type="submit"]', event.currentTarget);
  await withBusy(button, async () => {
    state.session = await api("/api/session/password", { method: "PUT", body: JSON.stringify({ current_password: $("#current-password").value, new_password: $("#new-password").value }) });
    closeDialog("change-password-dialog");
    notify("Password changed. Other sessions were revoked.");
  });
});
$("#confirm-password").addEventListener("input", () => $("#confirm-password").setCustomValidity(""));

$("#refresh-audit").addEventListener("click", () => loadAudit());
$("#load-more-audit").addEventListener("click", () => loadAudit(true));
$("#user-search").addEventListener("input", filterUsers);
$$('[data-user-filter]').forEach((button) => button.addEventListener("click", () => {
  const filter = $("#user-filter");
  filter.dataset.value = button.dataset.userFilter;
  $("summary span", filter).textContent = button.textContent;
  filter.open = false;
  filterUsers();
}));
$("#audit-search").addEventListener("input", filterAudit);

$("#add-override").addEventListener("click", () => { addOverride(); setDirty(true); filterOverrides(); $("#override-rows tr:last-child input").focus(); });
$("#override-search").addEventListener("input", filterOverrides);
$$('[data-override-type]').forEach((button) => button.addEventListener("click", () => {
  $("#override-type-filter").dataset.value = button.dataset.overrideType;
  $("#override-type-label").textContent = button.textContent;
  $("#override-type-filter").open = false;
  filterOverrides();
}));
$$('[data-block-mode]').forEach((button) => button.addEventListener("click", () => {
  $("#block-mode").value = button.dataset.blockMode;
  $("#block-mode-dropdown summary span").textContent = button.textContent;
  $("#block-mode-dropdown").open = false;
  $("#block-mode").dispatchEvent(new Event("input", { bubbles: true }));
}));
document.addEventListener("click", (event) => {
  $$(".custom-dropdown[open]").forEach((dropdown) => {
    if (!dropdown.contains(event.target)) dropdown.open = false;
  });
});
$$('.config-view input, .config-view select, .config-view textarea').forEach((control) => {
  control.addEventListener("input", () => setDirty(true));
  control.addEventListener("change", () => setDirty(true));
});
$("#save").addEventListener("click", async () => {
  if (state.activeModalID) {
    $("form", document.getElementById(state.activeModalID)).requestSubmit();
    return;
  }
  await withBusy($("#save"), async () => {
    if (state.dirtyKind === "records") {
      await saveManagedRecords();
      return;
    }
    const result = await api("/api/settings", { method: "PUT", headers: { "If-Match": state.configRevision }, body: JSON.stringify(collectConfig()) });
    state.config = await api("/api/settings", { captureETag: true });
    fillConfigForm(state.config);
    notify(result.restart_required ? "Saved. Restart LightDNS to apply listener changes." : "Configuration saved and applied live.");
  });
});
$("#reset-changes").addEventListener("click", () => {
  if (state.activeModalID) {
    restoreFormDialog(document.getElementById(state.activeModalID));
    return;
  }
  if (state.dirtyKind === "records") {
    renderZoneDetail();
    setDirty(false);
    notify("Unsaved DNS record changes reset.");
    return;
  }
  fillConfigForm(state.config);
  notify("Unsaved configuration reset.");
});
$("#reload-lists").addEventListener("click", () => withBusy($("#reload-lists"), async () => {
  const result = await api("/api/blocklists/reload", { method: "POST" });
  notify(`Reloaded ${formatNumber(result.blocked_domains)} blocked domains.`);
  await loadStats();
}));

$("#logout").addEventListener("click", async () => {
  try { await api("/api/session", { method: "DELETE" }); } finally { location.replace("/login"); }
});

window.addEventListener("beforeunload", (event) => {
  if (!state.configDirty && !state.modalDirty) return;
  event.preventDefault();
  event.returnValue = "";
});

boot().catch((error) => {
  $("#boot-state p").textContent = error.message;
  notify(error.message);
});
setInterval(loadStats, 5000);
