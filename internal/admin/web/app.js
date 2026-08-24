const $ = (selector) => document.querySelector(selector);
const $$ = (selector) => [...document.querySelectorAll(selector)];
let config = null;
let configRevision = null;
let toastTimer;
let pendingRemoval = null;
let configDirty = false;
let recordDraftDirty = false;

async function api(path, options = {}) {
  const { captureETag = false, ...fetchOptions } = options;
  const headers = { ...options.headers };
  if (options.body) headers["Content-Type"] = "application/json";
  if (options.method && options.method !== "GET") headers["X-LightDNS-Request"] = "dashboard";
  const response = await fetch(path, { ...fetchOptions, headers });
  const data = response.status === 204 ? {} : await response.json();
  if (!response.ok) {
    if (response.status === 401) location.replace("/login");
    throw new Error(data.error || `Request failed with status ${response.status}.`);
  }
  if (captureETag) configRevision = response.headers.get("ETag");
  return data;
}

function lines(value) {
  return value.split("\n").map((line) => line.trim()).filter(Boolean);
}

function initializeView() {
  const requestedView = location.hash.slice(1);
  const knownView = $$('[data-view]').some((item) => item.dataset.view === requestedView);
  showView(knownView ? requestedView : "overview", false);
}

function notify(message) {
  const toast = $("#toast");
  toast.textContent = message;
  toast.classList.add("show");
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => toast.classList.remove("show"), 3200);
}

function setDirty(dirty) {
  configDirty = dirty;
  updateUnsavedState();
}

function setDropdownValue(selector, value, label = value) {
  const dropdown = $(selector);
  dropdown.querySelector("summary span").textContent = label;
  dropdown.parentElement.querySelector("[data-dropdown-input]").value = value;
}

function updateUnsavedState() {
  const bar = $("#unsaved-bar");
  const dialog = $("dialog[open]");
  if (dialog && bar.parentElement !== dialog) dialog.append(bar);
  if (!dialog && bar.parentElement !== document.body) document.body.insertBefore(bar, $("#toast"));
  bar.hidden = !configDirty && !recordDraftDirty;
  $("#unsaved-message").textContent = recordDraftDirty ? "You have an unfinished DNS record." : "You have unsaved changes.";
}

function hasUnsavedChanges() {
  return configDirty || recordDraftDirty;
}

function shakeUnsavedChanges() {
  const bar = $("#unsaved-bar");
  bar.classList.remove("shake");
  void bar.offsetWidth;
  bar.classList.add("shake");
}

function addRecord(record = { name: "", type: "A", value: "", ttl: 300 }) {
  const row = $("#record-template").content.firstElementChild.cloneNode(true);
  Object.entries(record).forEach(([field, value]) => {
    const input = row.querySelector(`[data-field="${field}"]`);
    if (input) input.value = value;
  });
  const typeValue = row.querySelector('[data-field="type"]');
  const typeDropdown = row.querySelector(".record-type-dropdown");
  const typeMenu = typeDropdown.querySelector(".record-type-menu");
  typeDropdown.querySelector("summary span").textContent = typeValue.value;
  Object.keys(recordHelp).forEach((type) => {
    const button = document.createElement("button");
    button.type = "button";
    button.dataset.value = type;
    button.textContent = type;
    button.addEventListener("click", () => {
      typeValue.value = type;
      typeDropdown.querySelector("summary span").textContent = type;
      typeDropdown.open = false;
      updateEmptyRecords();
      setDirty(true);
    });
    typeMenu.append(button);
  });
  row.querySelector(".remove-record").addEventListener("click", () => {
    pendingRemoval = row;
    $("#remove-record-dialog").showModal();
    updateUnsavedState();
  });
  row.querySelectorAll("input, select").forEach((control) => control.addEventListener("input", updateEmptyRecords));
  $("#record-rows").append(row);
  updateEmptyRecords();
}

function updateEmptyRecords() {
  const query = $("#record-search").value.trim().toLowerCase();
  const type = $("#record-type-filter").dataset.value || "";
  const rows = $$(".record-row");
  let visible = 0;
  rows.forEach((row) => {
    const name = row.querySelector('[data-field="name"]').value.toLowerCase();
    const value = row.querySelector('[data-field="value"]').value.toLowerCase();
    const recordType = row.querySelector('[data-field="type"]').value;
    const matches = (!query || name.includes(query) || value.includes(query)) && (!type || recordType === type);
    row.hidden = !matches;
    if (matches) visible++;
  });
  $("#records-empty").hidden = visible > 0;
  $("#record-count").textContent = `${visible} of ${rows.length}`;
}

const recordHelp = {
  A: ["192.0.2.10", "IPv4 address, for example 192.0.2.10"],
  AAAA: ["2001:db8::10", "IPv6 address, for example 2001:db8::10"],
  CNAME: ["target.example.com.", "Canonical target name"],
  MX: ["10 mail.example.com.", "Priority followed by the mail server name"],
  TXT: ["v=spf1 -all", "Text value; quotes are added automatically"],
  NS: ["ns1.example.com.", "Authoritative name server"],
  PTR: ["host.example.com.", "Reverse lookup target name"],
  SRV: ["10 5 443 service.example.com.", "Priority, weight, port, and target"],
  CAA: ['0 issue "letsencrypt.org"', "Flag, tag, and certificate authority value"]
};

function updateRecordHelp() {
  const [placeholder, help] = recordHelp[$("#new-record-type").value];
  $("#new-record-type-dropdown summary span").textContent = $("#new-record-type").value;
  $("#new-record-value").placeholder = placeholder;
  $("#record-value-help").textContent = help;
}

function fillForm(cfg) {
  $("#record-rows").replaceChildren();
  (cfg.records || []).forEach(addRecord);
  updateEmptyRecords();
  $("#block-urls").value = (cfg.blocklists.urls || []).join("\n");
  $("#block-files").value = (cfg.blocklists.files || []).join("\n");
  $("#denylist").value = (cfg.blocking.denylist || []).join("\n");
  $("#allowlist").value = (cfg.blocking.allowlist || []).join("\n");
  $("#block-mode").value = cfg.blocking.mode;
  setDropdownValue("#block-mode-dropdown", cfg.blocking.mode, cfg.blocking.mode === "null" ? "Null address" : "NXDOMAIN");
  $("#block-refresh").value = cfg.blocklists.refresh;
  $("#block-ipv4").value = cfg.blocking.ipv4;
  $("#block-ipv6").value = cfg.blocking.ipv6;
  $("#block-bytes").value = cfg.blocklists.max_download_bytes;
  $("#upstream-list").value = (cfg.upstreams || []).join("\n");
  $("#timeout").value = cfg.timeout;
  $("#max-questions").value = cfg.max_questions;
  $("#dnssec").checked = cfg.dnssec;
  $("#dns-listen").value = cfg.listen;
  $("#http-listen").value = cfg.http_listen;
  $("#cache-entries").value = cfg.cache.entries;
  $("#cache-min").value = cfg.cache.min_ttl;
  $("#cache-max").value = cfg.cache.max_ttl;
  $("#tls-cert").value = cfg.tls.cert_file || "";
  $("#tls-key").value = cfg.tls.key_file || "";
  $("#dot-listen").value = cfg.tls.dot_listen || "";
  setDirty(false);
}

function collectForm() {
  const next = structuredClone(config);
  next.records = $$(".record-row").map((row) => ({
    name: row.querySelector('[data-field="name"]').value.trim(),
    type: row.querySelector('[data-field="type"]').value,
    value: row.querySelector('[data-field="value"]').value.trim(),
    ttl: Number(row.querySelector('[data-field="ttl"]').value)
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

async function loadConfig() {
  config = await api("/api/settings", { captureETag: true });
  fillForm(config);
  initializeView();
  await loadStats();
}

async function loadStats() {
  if ($("#app").hidden) return;
  try {
    const stats = await api("/api/stats");
    $("#stat-queries").textContent = stats.queries.toLocaleString();
    $("#stat-blocked").textContent = stats.blocked.toLocaleString();
    $("#stat-local").textContent = stats.local_answers.toLocaleString();
    $("#stat-cache").textContent = `${stats.cache_rate.toFixed(1)}%`;
    $("#stat-domains").textContent = stats.blocked_domains.toLocaleString();
    $("#stat-misses").textContent = stats.cache_misses.toLocaleString();
    $("#stat-errors").textContent = stats.upstream_errors.toLocaleString();
    $("#stat-servfail").textContent = stats.servfail.toLocaleString();
    $("#stats-time").textContent = `Updated ${new Date(stats.time).toLocaleTimeString()}`;
  } catch (error) {
    notify(error.message);
  }
}

$("#save").addEventListener("click", async () => {
  const button = $("#save");
  if (recordDraftDirty) {
    const form = $("#record-form");
    if (!form.reportValidity()) {
      shakeUnsavedChanges();
      return;
    }
    form.requestSubmit();
  }
  button.disabled = true;
  button.setAttribute("aria-busy", "true");
  try {
    const next = collectForm();
    const result = await api("/api/settings", { method: "PUT", headers: { "If-Match": configRevision }, body: JSON.stringify(next) });
    config = await api("/api/settings", { captureETag: true });
    setDirty(false);
    notify(result.restart_required ? "Saved. Restart LightDNS to apply listener changes." : "Saved and applied live.");
  } catch (error) {
    notify(error.message);
  } finally {
    button.disabled = false;
    button.removeAttribute("aria-busy");
  }
});

$("#reset-changes").addEventListener("click", () => {
  if (recordDraftDirty) {
    $("#record-form").reset();
    updateRecordHelp();
    recordDraftDirty = false;
    updateUnsavedState();
    notify("Record draft reset.");
    return;
  }
  fillForm(config);
  notify("Unsaved changes reset.");
});

$("#app").addEventListener("input", (event) => {
  if (event.target.id !== "record-search") setDirty(true);
});
$("#app").addEventListener("change", (event) => {
  if (event.target.id !== "record-search") setDirty(true);
});

$("#add-record").addEventListener("click", () => {
  recordDraftDirty = false;
  updateUnsavedState();
  $("#record-dialog").showModal();
  updateUnsavedState();
  $("#new-record-name").focus();
});

function closeRecordDialog() {
  recordDraftDirty = false;
  $("#record-dialog").close();
  updateUnsavedState();
}
$("#cancel-record").addEventListener("click", closeRecordDialog);
$("#cancel-record-footer").addEventListener("click", closeRecordDialog);
$("#cancel-remove-record").addEventListener("click", () => {
  pendingRemoval = null;
  $("#remove-record-dialog").close();
  updateUnsavedState();
});
$("#confirm-remove-record").addEventListener("click", () => {
  if (pendingRemoval) pendingRemoval.remove();
  pendingRemoval = null;
  $("#remove-record-dialog").close();
  updateEmptyRecords();
  setDirty(true);
});
$("#new-record-type").addEventListener("change", updateRecordHelp);
$("#record-form").addEventListener("input", () => {
  recordDraftDirty = true;
  updateUnsavedState();
});
$("#record-search").addEventListener("input", updateEmptyRecords);
$$('[data-record-type]').forEach((button) => button.addEventListener("click", () => {
  $("#record-type-filter").dataset.value = button.dataset.recordType;
  $("#record-type-label").textContent = button.textContent;
  $("#record-type-filter").open = false;
  updateEmptyRecords();
}));
$$('[data-dropdown-value]').forEach((button) => button.addEventListener("click", () => {
  const dropdown = button.closest(".custom-dropdown");
  const input = dropdown.parentElement.querySelector("[data-dropdown-input]");
  input.value = button.dataset.dropdownValue;
  dropdown.querySelector("summary span").textContent = button.textContent;
  dropdown.open = false;
  input.dispatchEvent(new Event("input", { bubbles: true }));
  input.dispatchEvent(new Event("change", { bubbles: true }));
}));
$("#record-form").addEventListener("submit", (event) => {
  event.preventDefault();
  addRecord({
    name: $("#new-record-name").value.trim(),
    type: $("#new-record-type").value,
    value: $("#new-record-value").value.trim(),
    ttl: Number($("#new-record-ttl").value)
  });
  recordDraftDirty = false;
  setDirty(true);
  event.currentTarget.reset();
  updateRecordHelp();
  closeRecordDialog();
  notify("Record added. Save changes to apply it.");
});

$("#reload-lists").addEventListener("click", async () => {
  const button = $("#reload-lists");
  button.disabled = true;
  try {
    const result = await api("/api/blocklists/reload", { method: "POST" });
    notify(`Reloaded ${result.blocked_domains.toLocaleString()} blocked domains.`);
    await loadStats();
  } catch (error) {
    notify(error.message);
  } finally {
    button.disabled = false;
  }
});

function showView(name, updateHistory = true) {
  $$('[data-view]').forEach((item) => item.classList.toggle("active", item.dataset.view === name));
  $$(".view").forEach((view) => view.classList.toggle("active", view.id === `view-${name}`));
  if (updateHistory) history.replaceState(null, "", `#${name}`);
}

$$('[data-view]').forEach((button) => button.addEventListener("click", () => {
  if (hasUnsavedChanges() && !button.classList.contains("active")) {
    shakeUnsavedChanges();
    return;
  }
  showView(button.dataset.view);
}));

$(".brand").addEventListener("click", (event) => {
  event.preventDefault();
  if (hasUnsavedChanges()) {
    shakeUnsavedChanges();
    return;
  }
  showView("overview");
});

document.addEventListener("click", (event) => {
  $$(".custom-dropdown[open]").forEach((dropdown) => {
    if (!dropdown.contains(event.target)) dropdown.open = false;
  });
});

$$('dialog').forEach((dialog) => {
  const dismiss = (event) => {
    if (event.type === "click" && event.target !== dialog) return;
    if (hasUnsavedChanges()) {
      event.preventDefault();
      shakeUnsavedChanges();
      return;
    }
    if (dialog === $("#remove-record-dialog")) pendingRemoval = null;
    dialog.close();
    updateUnsavedState();
  };
  dialog.addEventListener("click", dismiss);
  dialog.addEventListener("cancel", dismiss);
});

$("#logout").addEventListener("click", async () => {
  await api("/logout", { method: "POST" });
  location.replace("/login");
});

loadConfig().catch((error) => notify(error.message));
setInterval(loadStats, 5000);
