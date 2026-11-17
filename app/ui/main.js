// lethe UI. All crypto, storage and networking live in Rust; this file only renders.
// User-controlled strings are only ever set via textContent, never innerHTML.

const { invoke } = window.__TAURI__.core;
const { listen } = window.__TAURI__.event;

const $ = (id) => document.getElementById(id);
const state = { contacts: [], openId: null, messages: [] };

const STATUS = { invited: "waiting for them to use your link", joining: "connecting…", ready: "end-to-end encrypted", left: "left the conversation" };
const statusKey = (s) => String(s).toLowerCase();

// ---------- lock screen ----------
let isNew = false;

async function initLock() {
  isNew = !(await invoke("profile_exists"));
  $("pass2").hidden = !isNew;
  $("lock-hint").textContent = isNew ? "Choose a passphrase to create your encrypted profile." : "Enter your passphrase to unlock.";
  $("unlock-btn").textContent = isNew ? "Create profile" : "Unlock";
  $("pass").value = $("pass2").value = "";
  $("lock").hidden = false;
  $("app").hidden = true;
  $("pass").focus();
}

$("lock-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const pass = $("pass").value;
  $("lock-error").textContent = "";
  if (isNew) {
    if (pass.length < 8) return ($("lock-error").textContent = "Use at least 8 characters.");
    if (pass !== $("pass2").value) return ($("lock-error").textContent = "Passphrases don't match.");
  }
  $("unlock-btn").disabled = true;
  $("unlock-btn").textContent = "Unlocking…";
  try {
    await invoke("unlock", { passphrase: pass });
    $("pass").value = $("pass2").value = "";
    $("lock").hidden = true;
    $("app").hidden = false;
    await loadSettings();
    await refreshContacts();
    if (!settings.relay) openSettings();
  } catch (err) {
    $("lock-error").textContent = String(err);
  } finally {
    $("unlock-btn").disabled = false;
    $("unlock-btn").textContent = isNew ? "Create profile" : "Unlock";
  }
});

$("lock-btn").addEventListener("click", async () => {
  await invoke("lock");
  state.openId = null;
  showConversation(false);
  initLock();
});

// ---------- contacts ----------
async function refreshContacts() {
  state.contacts = await invoke("contacts");
  state.contacts.sort((a, b) => (b.lastItem?.ts ?? 0) - (a.lastItem?.ts ?? 0) || b.id - a.id);
  const list = $("contact-list");
  list.replaceChildren(
    ...state.contacts.map((c) => {
      const li = document.createElement("li");
      li.className = "contact" + (c.id === state.openId ? " active" : "");
      li.tabIndex = 0;
      const name = document.createElement("strong");
      name.textContent = c.name;
      const sub = document.createElement("span");
      sub.className = "fine";
      sub.textContent = c.lastItem ? c.lastItem.text.slice(0, 60) : STATUS[statusKey(c.status)];
      li.append(name, sub);
      li.addEventListener("click", () => openChat(c.id));
      li.addEventListener("keydown", (e) => e.key === "Enter" && openChat(c.id));
      return li;
    }),
  );
  if (state.openId != null) renderHeader();
}

function current() {
  return state.contacts.find((c) => c.id === state.openId);
}

async function openChat(id) {
  state.openId = id;
  state.messages = await invoke("messages", { contactId: id });
  await refreshContacts();
  renderMessages();
  showConversation(true);
  $("text").focus();
}

function showConversation(on) {
  $("conversation").hidden = !on;
  $("empty").hidden = on;
  document.body.classList.toggle("in-chat", on);
}

function renderHeader() {
  const c = current();
  if (!c) return showConversation(false);
  const s = statusKey(c.status);
  $("chat-name").textContent = c.name;
  $("chat-status").textContent = STATUS[s];
  $("show-link-btn").hidden = s !== "invited";
  const canSend = s === "ready" || s === "joining";
  $("text").disabled = !canSend;
  $("text").placeholder = canSend ? "Message" : STATUS[s];
}

function renderMessages() {
  const ol = $("messages");
  ol.replaceChildren(...state.messages.map(messageEl));
  ol.scrollTop = ol.scrollHeight;
}

function messageEl(m) {
  const li = document.createElement("li");
  li.className = "msg " + (statusKey(m.direction) === "sent" ? "out" : "in");
  li.dataset.id = m.id;
  const body = document.createElement("p");
  body.textContent = m.text;
  const meta = document.createElement("span");
  meta.className = "meta";
  const time = new Date(m.ts * 1000).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
  const st = statusKey(m.status);
  meta.textContent = time + (st === "pending" ? " · sending" : st === "failed" ? " · failed" : st === "sent" ? " · sent" : "");
  li.append(body, meta);
  return li;
}

// ---------- composer ----------
$("composer").addEventListener("submit", async (e) => {
  e.preventDefault();
  const text = $("text").value.trim();
  if (!text || state.openId == null) return;
  try {
    const item = await invoke("send_text", { contactId: state.openId, text });
    $("text").value = "";
    autoGrow();
    state.messages.push(item);
    renderMessages();
    refreshContacts();
  } catch (err) {
    toast(String(err));
  }
});

$("text").addEventListener("keydown", (e) => {
  if (e.key === "Enter" && !e.shiftKey) {
    e.preventDefault();
    $("composer").requestSubmit();
  }
});
$("text").addEventListener("input", autoGrow);
function autoGrow() {
  const t = $("text");
  t.style.height = "auto";
  t.style.height = Math.min(t.scrollHeight, 160) + "px";
}

$("back-btn").addEventListener("click", () => {
  state.openId = null;
  showConversation(false);
  refreshContacts();
});

$("rename-btn").addEventListener("click", async () => {
  const c = current();
  const alias = prompt("Name for this contact (only you see it):", c?.name ?? "");
  if (alias === null) return;
  await invoke("rename_contact", { contactId: state.openId, alias });
  refreshContacts();
});

$("delete-btn").addEventListener("click", async () => {
  const c = current();
  if (!c || !confirm(`Delete ${c.name}? They'll be told, and the conversation is erased from this device.`)) return;
  await invoke("delete_contact", { contactId: c.id });
  state.openId = null;
  showConversation(false);
  refreshContacts();
});

// ---------- invites ----------
function showInvite(inv) {
  $("qr").src = "data:image/svg+xml;base64," + btoa(inv.qrSvg);
  $("invite-link").value = inv.link;
  $("invite-dlg").showModal();
}

$("invite-btn").addEventListener("click", async () => {
  try {
    const inv = await invoke("create_invite", { alias: null });
    await refreshContacts();
    showInvite(inv);
  } catch (err) {
    toast(String(err));
    if (!settings.relay) openSettings();
  }
});

$("show-link-btn").addEventListener("click", async () => showInvite(await invoke("invite_link", { contactId: state.openId })));

$("copy-link").addEventListener("click", async () => {
  await navigator.clipboard.writeText($("invite-link").value);
  $("copy-link").textContent = "Copied";
  setTimeout(() => ($("copy-link").textContent = "Copy link"), 1500);
});

$("join-btn").addEventListener("click", () => {
  $("join-link").value = $("join-alias").value = $("join-error").textContent = "";
  $("join-dlg").showModal();
});

$("join-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  try {
    const id = await invoke("accept_invite", { link: $("join-link").value.trim(), alias: $("join-alias").value.trim() || null });
    $("join-dlg").close();
    await refreshContacts();
    openChat(id);
  } catch (err) {
    $("join-error").textContent = String(err);
  }
});

// ---------- settings ----------
let settings = {};
async function loadSettings() {
  settings = await invoke("get_settings");
}

function openSettings() {
  $("set-relay").value = settings.relay ?? "";
  $("set-name").value = settings.profileName ?? "";
  $("set-proxy").value = settings.socksProxy ?? "";
  $("settings-error").textContent = "";
  $("settings-dlg").showModal();
}
$("settings-btn").addEventListener("click", openSettings);

$("settings-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const next = { relay: $("set-relay").value, profileName: $("set-name").value, socksProxy: $("set-proxy").value };
  try {
    await invoke("set_settings", { settings: next });
    await loadSettings();
    $("settings-dlg").close();
  } catch (err) {
    $("settings-error").textContent = String(err);
  }
});

document.querySelectorAll("[data-close]").forEach((b) => b.addEventListener("click", () => b.closest("dialog").close()));

// ---------- events from Rust ----------
listen("lethe-event", async ({ payload: e }) => {
  switch (e.type) {
    case "message":
      if (e.contactId === state.openId) {
        state.messages.push(e.item);
        renderMessages();
      }
      refreshContacts();
      break;
    case "itemStatus": {
      const m = state.messages.find((x) => x.id === e.itemId);
      if (m) {
        m.status = e.status;
        renderMessages();
      }
      break;
    }
    case "contactConnected":
    case "contactLeft":
      refreshContacts();
      break;
    case "relayDisconnected":
      $("relay-status").textContent = `Relay ${e.relay.host} unreachable, retrying…`;
      break;
    case "relayConnected":
      $("relay-status").textContent = "";
      break;
    case "error":
      toast(e.message);
      break;
  }
});
listen("lethe-resync", () => state.openId != null ? openChat(state.openId) : refreshContacts());

function toast(text) {
  const t = document.createElement("div");
  t.className = "toast";
  t.textContent = text;
  document.body.append(t);
  setTimeout(() => t.remove(), 5000);
}

initLock();
