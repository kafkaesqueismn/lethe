// lethe UI. All crypto, storage and networking live in Rust; this file only renders.
// User-controlled strings are only ever set via textContent, never innerHTML.

const { invoke } = window.__TAURI__.core;
const { listen } = window.__TAURI__.event;

const $ = (id) => document.getElementById(id);
const el = (tag, cls, text) => {
  const e = document.createElement(tag);
  if (cls) e.className = cls;
  if (text != null) e.textContent = text;
  return e;
};
const icon = (name) => {
  const s = document.createElementNS("http://www.w3.org/2000/svg", "svg");
  const u = document.createElementNS("http://www.w3.org/2000/svg", "use");
  u.setAttribute("href", "#i-" + name);
  s.append(u);
  return s;
};

const state = { contacts: [], openId: null, messages: [], unread: new Map(), filter: "", unlocked: false };
let settings = {};
const key = (s) => String(s).toLowerCase();

const STATUS = {
  invited: "Waiting for them to use your invitation",
  joining: "Connecting…",
  ready: "End-to-end encrypted",
  left: "Left the conversation",
};

// ============ lock screen ============
let isNew = false;

async function showLock(reason) {
  isNew = !(await invoke("profile_exists"));
  $("pass2").hidden = !isNew;
  $("meter").hidden = !isNew;
  $("lock-hint").textContent = reason ?? (isNew ? "Choose a passphrase to create your profile" : "Enter your passphrase");
  $("unlock-btn").textContent = isNew ? "Create profile" : "Unlock";
  $("lock-fine").textContent = isNew
    ? "There is no account and no recovery. If you forget this passphrase, your conversations are gone for good."
    : "No account, phone number or email. Everything lives on this device, encrypted with your passphrase.";
  $("pass").value = $("pass2").value = "";
  $("pass").autocomplete = isNew ? "new-password" : "current-password";
  $("lock-error").textContent = "";
  updateMeter();
  $("app").hidden = true;
  $("lock").hidden = false;
  $("pass").focus();
}

function strength(p) {
  let s = Math.min(p.length, 20) / 20;
  const kinds = [/[a-z]/, /[A-Z]/, /\d/, /[^A-Za-z0-9]/].filter((r) => r.test(p)).length;
  s = s * 0.7 + (kinds / 4) * 0.3;
  if (p.length < 8) s = Math.min(s, 0.25);
  return s;
}
function updateMeter() {
  const s = strength($("pass").value);
  const bar = $("meter").firstElementChild;
  bar.style.width = Math.round(s * 100) + "%";
  bar.style.background = s < 0.4 ? "var(--danger)" : s < 0.7 ? "var(--warn)" : "var(--accent)";
}
$("pass").addEventListener("input", () => isNew && updateMeter());

$("reveal").addEventListener("click", () => {
  const show = $("pass").type === "password";
  for (const id of ["pass", "pass2"]) $(id).type = show ? "text" : "password";
  $("pass").focus();
});

function lockError(msg) {
  $("lock-error").textContent = msg;
  const card = $("lock-form");
  card.classList.remove("shake");
  void card.offsetWidth;
  card.classList.add("shake");
}

$("lock-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const pass = $("pass").value;
  $("lock-error").textContent = "";
  if (isNew) {
    if (pass.length < 8) return lockError("Use at least 8 characters.");
    if (pass !== $("pass2").value) return lockError("Passphrases don't match.");
  }
  const btn = $("unlock-btn");
  btn.disabled = true;
  btn.textContent = isNew ? "Creating…" : "Unlocking…";
  try {
    await invoke("unlock", { passphrase: pass });
    $("pass").value = $("pass2").value = "";
    for (const id of ["pass", "pass2"]) $(id).type = "password";
    state.unlocked = true;
    $("lock").hidden = true;
    $("app").hidden = false;
    await loadSettings();
    await refreshContacts();
    touch();
    if (!settings.relay) openSettings();
  } catch (err) {
    lockError(String(err).includes("passphrase") ? "Wrong passphrase." : String(err));
    $("pass").select();
  } finally {
    btn.disabled = false;
    btn.textContent = isNew ? "Create profile" : "Unlock";
  }
});

/** Lock: stop the agent (keys are dropped in Rust) and wipe everything from the DOM. */
async function lockNow(reason) {
  if (!state.unlocked) return;
  state.unlocked = false;
  document.querySelectorAll("dialog[open]").forEach((d) => d.close());
  try {
    await invoke("lock");
  } catch (_) {}
  Object.assign(state, { contacts: [], openId: null, messages: [], unread: new Map(), filter: "" });
  $("contact-list").replaceChildren();
  $("messages").replaceChildren();
  $("text").value = $("search").value = $("invite-link").textContent = "";
  $("qr").removeAttribute("src");
  $("toasts").replaceChildren();
  showConversation(false);
  showLock(reason);
}
$("lock-btn").addEventListener("click", () => lockNow());

// ---- auto-lock after inactivity ----
let lastActivity = Date.now();
const touch = () => (lastActivity = Date.now());
for (const ev of ["pointerdown", "pointermove", "keydown", "wheel", "touchstart"]) {
  window.addEventListener(ev, touch, { passive: true });
}
setInterval(() => {
  const mins = Number(settings.autoLockMinutes ?? 5);
  if (state.unlocked && mins > 0 && Date.now() - lastActivity > mins * 60_000) {
    lockNow("Locked after inactivity");
  }
}, 10_000);

// ============ contacts ============
function hue(id) {
  return (Number(id) * 137.508) % 360;
}
function initials(name) {
  const parts = name.replace(/^contact #/, "#").trim().split(/\s+/);
  return (parts.length > 1 ? parts[0][0] + parts[1][0] : name.slice(0, 2)).toUpperCase();
}
function avatarFor(c, node = el("div", "avatar")) {
  node.className = "avatar" + (key(c.status) === "invited" ? " pending" : "");
  node.style.setProperty("--h", hue(c.id));
  node.replaceChildren(key(c.status) === "invited" ? icon("link") : document.createTextNode(initials(c.name)));
  return node;
}
function shortTime(ts) {
  const d = new Date(ts * 1000);
  const now = new Date();
  if (d.toDateString() === now.toDateString()) return d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
  const diff = (now - d) / 86_400_000;
  if (diff < 6) return d.toLocaleDateString([], { weekday: "short" });
  return d.toLocaleDateString([], { day: "numeric", month: "short" });
}

async function refreshContacts() {
  if (!state.unlocked) return;
  state.contacts = await invoke("contacts");
  state.contacts.sort((a, b) => (b.lastItem?.ts ?? 0) - (a.lastItem?.ts ?? 0) || b.id - a.id);
  renderContacts();
  if (state.openId != null) renderHeader();
}

function renderContacts() {
  const q = state.filter.trim().toLowerCase();
  const shown = state.contacts.filter((c) => !q || c.name.toLowerCase().includes(q));
  const list = $("contact-list");
  if (!shown.length) {
    const msg = q ? "No matches." : "No conversations yet.\nCreate an invite to get started.";
    list.replaceChildren(el("li", "list-empty", msg));
    return;
  }
  list.replaceChildren(
    ...shown.map((c) => {
      const li = el("li", "contact" + (c.id === state.openId ? " active" : ""));
      li.tabIndex = 0;
      const s = key(c.status);
      const last = c.lastItem;
      let preview = STATUS[s];
      if (last && s !== "invited") preview = (key(last.direction) === "sent" ? "You: " : "") + last.text.replace(/\s+/g, " ");
      const unread = state.unread.get(c.id) ?? 0;
      li.append(
        avatarFor(c),
        el("span", "name", c.name),
        el("span", "time", last ? shortTime(last.ts) : ""),
        el("span", "preview" + (!last || s === "invited" ? " pending" : ""), preview),
        unread ? el("span", "badge", unread > 99 ? "99+" : String(unread)) : el("span"),
      );
      li.addEventListener("click", () => openChat(c.id));
      li.addEventListener("keydown", (e) => e.key === "Enter" && openChat(c.id));
      return li;
    }),
  );
}

$("search").addEventListener("input", (e) => {
  state.filter = e.target.value;
  renderContacts();
});

const current = () => state.contacts.find((c) => c.id === state.openId);

async function openChat(id) {
  state.openId = id;
  state.unread.delete(id);
  state.messages = await invoke("messages", { contactId: id });
  renderContacts();
  renderHeader();
  renderMessages();
  showConversation(true);
  if (!$("text").disabled) $("text").focus();
}

function showConversation(on) {
  $("conversation").hidden = !on;
  $("empty").hidden = on;
  document.body.classList.toggle("in-chat", on);
}

function renderHeader() {
  const c = current();
  if (!c) return showConversation(false);
  const s = key(c.status);
  avatarFor(c, $("chat-avatar"));
  $("chat-name").textContent = c.name;
  const st = $("chat-status");
  st.className = "status-line" + (s === "ready" ? " secure" : "");
  st.replaceChildren(...(s === "ready" ? [icon("lock")] : []), document.createTextNode(STATUS[s]));
  $("show-link-btn").hidden = s !== "invited";
  const canSend = s === "ready" || s === "joining";
  $("text").disabled = !canSend;
  $("text").placeholder = canSend ? "Message" : s === "invited" ? "Waiting for them to join…" : "This conversation has ended";
  updateSend();
}

// ============ messages ============
function dayLabel(ts) {
  const d = new Date(ts * 1000);
  const today = new Date();
  const yest = new Date(Date.now() - 86_400_000);
  if (d.toDateString() === today.toDateString()) return "Today";
  if (d.toDateString() === yest.toDateString()) return "Yesterday";
  return d.toLocaleDateString([], { weekday: "long", day: "numeric", month: "long" });
}

function renderMessages() {
  const ol = $("messages");
  const nodes = [];
  const c = current();
  const notice = el("li", "notice");
  notice.append(icon("shield"), document.createTextNode(
    key(c?.status) === "invited"
      ? "Share your invitation. Once they join, messages here are end-to-end encrypted."
      : "Messages are end-to-end encrypted. Relays only ever see padded ciphertext.",
  ));
  nodes.push(notice);
  let lastDay = null;
  state.messages.forEach((m, i) => {
    const day = new Date(m.ts * 1000).toDateString();
    if (day !== lastDay) {
      nodes.push(el("li", "day", dayLabel(m.ts)));
      lastDay = day;
    }
    const next = state.messages[i + 1];
    const tail = !next || key(next.direction) !== key(m.direction) || new Date(next.ts * 1000).toDateString() !== day || next.ts - m.ts > 300;
    nodes.push(messageEl(m, tail));
  });
  ol.replaceChildren(...nodes);
  ol.scrollTop = ol.scrollHeight;
}

function messageEl(m, tail) {
  const out = key(m.direction) === "sent";
  const st = key(m.status);
  const li = el("li", `msg ${out ? "out" : "in"}${tail ? " tail" : ""}${st === "failed" ? " failed" : ""}`);
  li.dataset.id = m.id;
  const meta = el("span", "meta", new Date(m.ts * 1000).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" }));
  if (out) meta.append(el("span", "tick", st === "pending" ? "···" : st === "failed" ? "!" : "✓"));
  const p = el("p", null, m.text);
  p.append(meta);
  li.append(p);
  if (st === "failed") li.title = "Not delivered";
  return li;
}

// ============ composer ============
function updateSend() {
  $("send-btn").disabled = $("text").disabled || !$("text").value.trim();
}
function autoGrow() {
  const t = $("text");
  t.style.height = "auto";
  t.style.height = Math.min(t.scrollHeight, 160) + "px";
  updateSend();
}
$("text").addEventListener("input", autoGrow);
$("text").addEventListener("keydown", (e) => {
  if (e.key === "Enter" && !e.shiftKey && !e.isComposing) {
    e.preventDefault();
    $("composer").requestSubmit();
  }
});

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
    toast(String(err), true);
  }
});

$("back-btn").addEventListener("click", () => {
  state.openId = null;
  showConversation(false);
  renderContacts();
});

// ============ rename / delete ============
$("rename-btn").addEventListener("click", () => {
  $("rename-input").value = current()?.name ?? "";
  $("rename-dlg").showModal();
  $("rename-input").select();
});
$("rename-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  await invoke("rename_contact", { contactId: state.openId, alias: $("rename-input").value.trim() || null });
  $("rename-dlg").close();
  refreshContacts();
});

function confirmDialog(title, text, ok = "Delete") {
  $("confirm-title").textContent = title;
  $("confirm-text").textContent = text;
  $("confirm-ok").textContent = ok;
  const dlg = $("confirm-dlg");
  dlg.returnValue = "";
  dlg.showModal();
  return new Promise((resolve) => {
    const form = $("confirm-form");
    const done = (v) => {
      form.removeEventListener("submit", onOk);
      dlg.removeEventListener("close", onClose);
      resolve(v);
    };
    const onOk = (e) => {
      e.preventDefault();
      dlg.close();
      done(true);
    };
    const onClose = () => done(false);
    form.addEventListener("submit", onOk);
    dlg.addEventListener("close", onClose);
  });
}

$("delete-btn").addEventListener("click", async () => {
  const c = current();
  if (!c) return;
  const ok = await confirmDialog(`Delete ${c.name}?`, "They'll be told you left, and the whole conversation is erased from this device. This can't be undone.");
  if (!ok) return;
  await invoke("delete_contact", { contactId: c.id });
  state.openId = null;
  showConversation(false);
  refreshContacts();
});

// ============ invites ============
function showInvite(inv) {
  $("qr").src = "data:image/svg+xml;base64," + btoa(inv.qrSvg);
  $("invite-link").textContent = inv.link;
  $("invite-dlg").showModal();
}

async function newInvite() {
  if (!settings.relay) {
    toast("Set your relay first.", true);
    return openSettings();
  }
  try {
    const inv = await invoke("create_invite", { alias: null });
    await refreshContacts();
    openChat(inv.contactId);
    showInvite(inv);
  } catch (err) {
    toast(String(err), true);
  }
}
$("invite-btn").addEventListener("click", newInvite);
$("empty-invite").addEventListener("click", newInvite);
$("show-link-btn").addEventListener("click", async () => showInvite(await invoke("invite_link", { contactId: state.openId })));

$("copy-link").addEventListener("click", async () => {
  await navigator.clipboard.writeText($("invite-link").textContent);
  const label = $("copy-link").querySelector("span");
  label.textContent = "Copied";
  setTimeout(() => (label.textContent = "Copy"), 1500);
});

function openJoin() {
  $("join-link").value = $("join-alias").value = $("join-error").textContent = "";
  $("join-dlg").showModal();
}
$("join-btn").addEventListener("click", openJoin);
$("empty-join").addEventListener("click", openJoin);

$("join-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  if (!settings.relay) {
    $("join-error").textContent = "Set your relay in Settings first.";
    return;
  }
  try {
    const id = await invoke("accept_invite", { link: $("join-link").value.trim(), alias: $("join-alias").value.trim() || null });
    $("join-dlg").close();
    await refreshContacts();
    openChat(id);
  } catch (err) {
    $("join-error").textContent = String(err).includes("invitation") ? "That doesn't look like a valid invitation link." : String(err);
  }
});

// ============ settings ============
async function loadSettings() {
  settings = await invoke("get_settings");
}

function openSettings() {
  $("set-relay").value = settings.relay ?? "";
  $("set-name").value = settings.profileName ?? "";
  $("set-proxy").value = settings.socksProxy ?? "";
  $("set-autolock").value = String(settings.autoLockMinutes ?? 5);
  $("settings-error").textContent = "";
  $("settings-dlg").showModal();
}
$("settings-btn").addEventListener("click", openSettings);

$("settings-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const next = {
    relay: $("set-relay").value,
    profileName: $("set-name").value,
    socksProxy: $("set-proxy").value,
    autoLockMinutes: Number($("set-autolock").value),
  };
  try {
    await invoke("set_settings", { settings: next });
    await loadSettings();
    $("settings-dlg").close();
    toast("Settings saved");
  } catch (err) {
    $("settings-error").textContent = String(err);
  }
});

document.querySelectorAll("[data-close]").forEach((b) => b.addEventListener("click", () => b.closest("dialog").close()));

// ============ events from Rust ============
listen("lethe-event", async ({ payload: e }) => {
  if (!state.unlocked) return;
  switch (e.type) {
    case "message":
      if (e.contactId === state.openId) {
        state.messages.push(e.item);
        renderMessages();
      } else {
        state.unread.set(e.contactId, (state.unread.get(e.contactId) ?? 0) + 1);
      }
      refreshContacts();
      break;
    case "itemStatus": {
      const m = state.messages.find((x) => x.id === e.itemId);
      if (m) {
        m.status = e.status;
        renderMessages();
      }
      if (key(e.status) === "sent" || key(e.status) === "failed") refreshContacts();
      break;
    }
    case "contactConnected": {
      await refreshContacts();
      const c = state.contacts.find((x) => x.id === e.contactId);
      if (c) toast(`${c.name} connected`);
      if (e.contactId === state.openId) renderMessages();
      break;
    }
    case "contactLeft":
      refreshContacts();
      break;
    case "relayDisconnected":
      $("relay-text").textContent = `Reconnecting to ${e.relay.host}…`;
      $("relay-status").hidden = false;
      break;
    case "relayConnected":
      $("relay-status").hidden = true;
      break;
    case "error":
      toast(e.message, true);
      break;
  }
});
listen("lethe-resync", () => (state.openId != null ? openChat(state.openId) : refreshContacts()));

function toast(text, bad = false) {
  const t = el("div", "toast" + (bad ? " bad" : ""), text);
  $("toasts").append(t);
  setTimeout(() => t.remove(), 4500);
}

showLock();
