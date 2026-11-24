// lethe UI. All crypto, storage and networking live in Rust; this file only renders.
// User-controlled strings are only ever set via textContent, never innerHTML.

const { invoke } = window.__TAURI__.core;
const { listen } = window.__TAURI__.event;
const appWindow = window.__TAURI__.window?.getCurrentWindow?.();

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
const key = (s) => String(s ?? "").toLowerCase();
const INVITE_RE = /lethe:\/\/inv#[A-Za-z0-9_-]+/;

const state = {
  contacts: [],
  openId: null,
  messages: [],
  filter: "",
  unlocked: false,
  drafts: new Map(),
  blobs: new Map(), // item id -> object URL for decrypted images
  invites: new Map(), // contact id -> {link, qrSvg} for pending invites shown in chat
};
let settings = {};

const STATUS = {
  invited: "Waiting for them to use your invite",
  joining: "Connecting…",
  ready: "End-to-end encrypted",
  left: "Left the conversation",
};
const TIMERS = { 300: "5 min", 3600: "1 hour", 86400: "1 day", 604800: "1 week" };

// ============ lock screen ============
let isNew = false;

async function showLock(reason) {
  isNew = !(await invoke("profile_exists"));
  $("pass2").hidden = !isNew;
  $("meter").hidden = !isNew;
  $("reset-btn").hidden = isNew;
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
    if (!settings.relay) openRelaySetup();
  } catch (err) {
    if (String(err) === "OLD_PROFILE") {
      lockError("This profile was made by an older test version and can't be opened. Start over to create a new one.");
      $("reset-btn").hidden = false;
    } else {
      lockError(String(err));
      $("pass").select();
    }
  } finally {
    btn.disabled = false;
    btn.textContent = isNew ? "Create profile" : "Unlock";
  }
});

$("reset-btn").addEventListener("click", async () => {
  const ok = await confirmDialog(
    "Start over?",
    "This permanently erases the profile on this device: every conversation, file and contact. There is no way to recover it.",
    [{ label: "Erase everything", cls: "danger" }],
  );
  if (!ok) return;
  try {
    await invoke("reset_profile");
    toast("Profile erased");
    showLock();
  } catch (err) {
    lockError(String(err));
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
  for (const url of state.blobs.values()) URL.revokeObjectURL(url);
  Object.assign(state, { contacts: [], openId: null, messages: [], filter: "", drafts: new Map(), blobs: new Map(), invites: new Map() });
  $("contact-list").replaceChildren();
  $("messages").replaceChildren();
  $("text").value = $("search").value = $("invite-link").textContent = "";
  $("qr").removeAttribute("src");
  $("toasts").replaceChildren();
  $("info").hidden = true;
  showConversation(false);
  setTitle(0);
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
  if (state.unlocked && mins > 0 && Date.now() - lastActivity > mins * 60_000) lockNow("Locked after inactivity");
}, 10_000);

// ============ contacts ============
const hue = (id) => (Number(id) * 137.508) % 360;
function initials(name) {
  const parts = name.replace(/^contact #/, "#").trim().split(/\s+/);
  return (parts.length > 1 ? parts[0][0] + parts[1][0] : name.slice(0, 2)).toUpperCase();
}
function avatarFor(c, node) {
  node = node ?? el("span", "avatar");
  const pending = key(c.status) === "invited";
  node.className = node.className.replace(/\bpending\b/g, "").trim() + (pending ? " pending" : "");
  if (!node.classList.contains("avatar")) node.classList.add("avatar");
  node.style.setProperty("--h", hue(c.id));
  node.replaceChildren(pending ? icon("link") : document.createTextNode(initials(c.name)));
  return node;
}
function shortTime(ts) {
  const d = new Date(ts * 1000);
  const now = new Date();
  if (d.toDateString() === now.toDateString()) return d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
  if ((now - d) / 86_400_000 < 6) return d.toLocaleDateString([], { weekday: "short" });
  return d.toLocaleDateString([], { day: "numeric", month: "short" });
}
function previewText(item) {
  if (!item) return "";
  if (item.system) return item.text;
  const a = item.attachment;
  const base = a ? (key(a.mime).startsWith("image/") ? "📷 Photo" : "📎 " + a.name) + (item.text ? " · " + item.text : "") : item.text;
  return base.replace(/\s+/g, " ");
}
function tickFor(status) {
  const s = key(status);
  if (s === "pending") return ["…", ""];
  if (s === "failed") return ["!", ""];
  if (s === "sent") return ["✓", ""];
  if (s === "delivered") return ["✓✓", ""];
  if (s === "read") return ["✓✓", "read"];
  return null;
}

async function refreshContacts() {
  if (!state.unlocked) return;
  state.contacts = await invoke("contacts");
  state.contacts.sort((a, b) => (b.lastItem?.ts ?? b.createdAt) - (a.lastItem?.ts ?? a.createdAt) || b.id - a.id);
  renderContacts();
  if (state.openId != null) renderHeader();
  setTitle(state.contacts.reduce((n, c) => n + (c.id === state.openId && document.hasFocus() ? 0 : c.unread), 0));
}

function renderContacts() {
  const q = state.filter.trim().toLowerCase();
  const shown = state.contacts.filter((c) => !q || c.name.toLowerCase().includes(q));
  const list = $("contact-list");
  if (!shown.length) {
    list.replaceChildren(el("li", "list-empty", q ? "No matches." : "No conversations yet.\nAdd a contact to get started."));
    return;
  }
  list.replaceChildren(
    ...shown.map((c) => {
      const li = el("li", "contact" + (c.id === state.openId ? " active" : ""));
      li.tabIndex = 0;
      const s = key(c.status);
      const last = c.lastItem;
      const unread = c.id === state.openId ? 0 : c.unread;
      const preview = el("span", "preview" + (!last || s === "invited" ? " pending" : unread ? " unread" : ""));
      if (last && s !== "invited") {
        const t = key(last.direction) === "sent" && !last.system ? tickFor(last.status) : null;
        if (t) preview.append(el("span", "tick " + t[1], t[0]));
        preview.append(document.createTextNode(previewText(last)));
      } else {
        preview.textContent = STATUS[s];
      }
      li.append(
        avatarFor(c),
        el("span", "name", c.name),
        el("span", "time", last ? shortTime(last.ts) : ""),
        preview,
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
  if (state.openId != null) state.drafts.set(state.openId, $("text").value);
  state.openId = id;
  state.messages = await invoke("messages", { contactId: id });
  $("text").value = state.drafts.get(id) ?? "";
  autoGrow();
  renderHeader();
  renderMessages();
  showConversation(true);
  if (!$("info").hidden) renderInfo();
  await markRead();
  if (!$("text").disabled) $("text").focus();
}

async function markRead() {
  const c = current();
  if (c && c.unread > 0 && document.hasFocus()) {
    try {
      await invoke("mark_read", { contactId: c.id });
    } catch (_) {}
  }
  await refreshContacts();
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
  const parts = [];
  if (s === "ready") parts.push(icon("lock"));
  parts.push(document.createTextNode(STATUS[s]));
  if (c.timer) parts.push(document.createTextNode(" · disappearing: " + (TIMERS[c.timer] ?? c.timer + "s")));
  st.replaceChildren(...parts);
  $("timer-btn").classList.toggle("on", !!c.timer);
  $("timer-btn").hidden = s !== "ready";
  const canSend = s === "ready" || s === "joining";
  $("text").disabled = !canSend;
  $("attach-btn").disabled = !canSend;
  $("text").placeholder = canSend ? "Message" : s === "invited" ? "Waiting for them to join…" : "This conversation has ended";
  updateSend();
}

// ============ messages ============
function dayLabel(ts) {
  const d = new Date(ts * 1000);
  if (d.toDateString() === new Date().toDateString()) return "Today";
  if (d.toDateString() === new Date(Date.now() - 86_400_000).toDateString()) return "Yesterday";
  return d.toLocaleDateString([], { weekday: "long", day: "numeric", month: "long" });
}

function renderMessages() {
  const ol = $("messages");
  const c = current();
  const nodes = [];
  if (key(c?.status) === "invited") {
    nodes.push(inviteCard(c));
  } else {
    const notice = el("li", "notice");
    notice.append(icon("shield"), document.createTextNode("Messages are end-to-end encrypted. Relays only ever see padded ciphertext."));
    nodes.push(notice);
  }
  let lastDay = null;
  state.messages.forEach((m, i) => {
    const day = new Date(m.ts * 1000).toDateString();
    if (day !== lastDay && !m.system) {
      nodes.push(el("li", "day", dayLabel(m.ts)));
      lastDay = day;
    }
    if (m.system) {
      const li = el("li", "sys");
      li.append(icon("hourglass"), document.createTextNode(m.text));
      nodes.push(li);
      return;
    }
    const next = state.messages[i + 1];
    const tail = !next || next.system || key(next.direction) !== key(m.direction) || next.ts - m.ts > 300;
    nodes.push(messageEl(m, tail));
  });
  ol.replaceChildren(...nodes);
  ol.scrollTop = ol.scrollHeight;
}

function inviteCard(c) {
  const li = el("li", "invite-card");
  const img = el("img");
  img.alt = "Invitation QR code";
  const title = el("strong", null, "Your invite is ready");
  const sub = el("p", "fine", "Show this QR code, or copy the link and send it to them. As soon as they use it, you're connected.");
  const row = el("div", "row");
  const copy = el("button", "btn");
  copy.type = "button";
  copy.append(icon("copy"), document.createTextNode("Copy link"));
  const msg = el("button", "btn");
  msg.type = "button";
  msg.append(icon("share"), document.createTextNode("Copy as message"));
  row.append(copy, msg);
  li.append(img, title, sub, row);
  const fill = (inv) => {
    img.src = "data:image/svg+xml;base64," + btoa(inv.qrSvg);
    copy.onclick = () => copyText(inv.link, "Link copied");
    msg.onclick = () => copyText(inviteMessage(inv.link), "Message copied");
  };
  const cached = state.invites.get(c.id);
  if (cached) fill(cached);
  else
    invoke("invite_link", { contactId: c.id })
      .then((inv) => {
        state.invites.set(c.id, inv);
        fill(inv);
      })
      .catch(() => {});
  return li;
}

const inviteMessage = (link) => `Let's talk privately on lethe (no account needed). Open the app, choose "Add contact" → "I have an invite", and paste this:\n${link}`;

function formatSize(n) {
  if (n < 1024) return n + " B";
  if (n < 1024 * 1024) return (n / 1024).toFixed(0) + " KB";
  return (n / 1024 / 1024).toFixed(1) + " MB";
}

function messageEl(m, tail) {
  const out = key(m.direction) === "sent";
  const st = key(m.status);
  const a = m.attachment;
  const isImage = a && key(a.mime).startsWith("image/") && key(a.state) === "ready";
  const li = el("li", `msg ${out ? "out" : "in"}${tail ? " tail" : ""}${st === "failed" ? " failed" : ""}${isImage ? " has-media" : ""}`);
  li.dataset.id = m.id;

  if (a) li.append(attachmentEl(m, out));

  const meta = el("span", "meta");
  if (m.expiresAt) {
    const exp = el("span", "exp");
    exp.title = "Disappears " + new Date(m.expiresAt * 1000).toLocaleString();
    exp.append(icon("hourglass"));
    meta.append(exp);
  }
  meta.append(document.createTextNode(new Date(m.ts * 1000).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })));
  if (out) {
    const t = tickFor(m.status);
    if (t) {
      const tick = el("span", "tick " + t[1], t[0]);
      tick.title = { pending: "Sending", sent: "Sent", delivered: "Delivered", read: "Read", failed: "Not delivered" }[st] ?? "";
      meta.append(tick);
    }
  }
  const p = el("p", null, m.text);
  p.append(meta);
  li.append(p);

  // hover actions
  const actions = el("div", "msg-actions");
  if (m.text) actions.append(actionBtn("copy", "Copy text", () => copyText(m.text, "Copied")));
  if (a && (key(a.state) === "ready" || out)) actions.append(actionBtn("download", "Save to Downloads", () => saveFile(m)));
  actions.append(actionBtn("trash", "Delete", () => deleteMessage(m), "danger"));
  li.append(actions);
  return li;
}

function actionBtn(name, title, fn, cls = "") {
  const b = el("button", cls);
  b.type = "button";
  b.title = title;
  b.setAttribute("aria-label", title);
  b.append(icon(name));
  b.addEventListener("click", (e) => {
    e.stopPropagation();
    fn();
  });
  return b;
}

function attachmentEl(m, out) {
  const a = m.attachment;
  const st = key(a.state);
  if (st === "ready" && key(a.mime).startsWith("image/")) {
    const btn = el("button", "media");
    btn.type = "button";
    btn.title = a.name;
    const img = el("img");
    img.alt = a.name;
    btn.append(img);
    img.addEventListener("load", () => {
      // Keep the view pinned to the newest message once the picture has its real size.
      const ol = $("messages");
      if (ol.scrollHeight - ol.scrollTop - ol.clientHeight < 400) ol.scrollTop = ol.scrollHeight;
    });
    loadBlob(m).then((url) => url && (img.src = url));
    btn.addEventListener("click", () => openLightbox(m));
    return btn;
  }
  const card = el("div", "filecard");
  const ico = el("span", "file-ico");
  ico.append(icon(key(a.mime).startsWith("image/") ? "clip" : "file"));
  const metaBox = el("span", "file-meta");
  metaBox.append(el("strong", null, a.name));
  let sub = formatSize(a.size);
  if (st === "transferring") {
    const pct = Math.floor((a.done / Math.max(a.chunks, 1)) * 100);
    sub = (out ? "Sending " : "Receiving ") + pct + "% · " + sub;
    metaBox.append(el("small", null, sub));
    const bar = el("div", "progress");
    const fill = el("span");
    fill.style.width = pct + "%";
    bar.append(fill);
    metaBox.append(bar);
  } else {
    if (st === "failed") sub = "Failed · " + sub;
    metaBox.append(el("small", null, sub));
  }
  card.append(ico, metaBox);
  if (st === "ready") {
    const save = el("button", "file-save");
    save.type = "button";
    save.title = "Save to Downloads";
    save.append(icon("download"));
    save.addEventListener("click", () => saveFile(m));
    card.append(save);
  }
  return card;
}

async function loadBlob(m) {
  if (state.blobs.has(m.id)) return state.blobs.get(m.id);
  try {
    const buf = await invoke("file_bytes", { contactId: state.openId, itemId: m.id });
    const url = URL.createObjectURL(new Blob([buf], { type: m.attachment.mime }));
    state.blobs.set(m.id, url);
    return url;
  } catch (_) {
    return null;
  }
}

async function saveFile(m) {
  try {
    const path = await invoke("save_file", { contactId: state.openId, itemId: m.id });
    toast("Saved to " + path);
  } catch (err) {
    toast(String(err), true);
  }
}

let lightboxItem = null;
async function openLightbox(m) {
  lightboxItem = m;
  $("lightbox-img").src = (await loadBlob(m)) ?? "";
  $("lightbox-name").textContent = m.attachment.name;
  $("lightbox").showModal();
}
$("lightbox-save").addEventListener("click", () => lightboxItem && saveFile(lightboxItem));
$("lightbox").addEventListener("click", (e) => e.target === $("lightbox") && $("lightbox").close());

async function deleteMessage(m) {
  const mine = key(m.direction) === "sent";
  const choices = [{ label: "Delete for me", value: "me", cls: mine ? "" : "danger" }];
  if (mine && key(m.status) !== "failed") choices.push({ label: "Delete for everyone", value: "all", cls: "danger" });
  const choice = await confirmDialog(
    "Delete message?",
    mine ? "Delete it just from this device, or from theirs too." : "It's removed from this device only.",
    choices,
  );
  if (!choice) return;
  try {
    await invoke("delete_items", { contactId: state.openId, ids: [m.id], forEveryone: choice === "all" });
  } catch (err) {
    toast(String(err), true);
  }
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
    state.drafts.delete(state.openId);
    autoGrow();
    state.messages.push(item);
    renderMessages();
    refreshContacts();
  } catch (err) {
    toast(String(err), true);
  }
});

// ---- files: picker, drag & drop, paste ----
$("attach-btn").addEventListener("click", () => $("file-input").click());
$("file-input").addEventListener("change", (e) => {
  sendFiles([...e.target.files]);
  e.target.value = "";
});

/** Shrink big photos before sending (faster, and strips most camera metadata). */
async function maybeShrink(file) {
  if (!/^image\/(jpeg|png|webp)$/.test(file.type) || file.size < 1_500_000) return file;
  try {
    const bmp = await createImageBitmap(file);
    const scale = Math.min(1, 2048 / Math.max(bmp.width, bmp.height));
    const canvas = document.createElement("canvas");
    canvas.width = Math.round(bmp.width * scale);
    canvas.height = Math.round(bmp.height * scale);
    canvas.getContext("2d").drawImage(bmp, 0, 0, canvas.width, canvas.height);
    const blob = await new Promise((r) => canvas.toBlob(r, "image/jpeg", 0.85));
    if (!blob || blob.size >= file.size) return file;
    return new File([blob], file.name.replace(/\.\w+$/, "") + ".jpg", { type: "image/jpeg" });
  } catch (_) {
    return file;
  }
}

async function sendFiles(files) {
  const c = current();
  if (!c || $("text").disabled || !files.length) return;
  const caption = $("text").value.trim();
  for (const [i, original] of files.entries()) {
    const file = await maybeShrink(original);
    if (file.size > 10 * 1024 * 1024) {
      toast(`${file.name} is too large (max 10 MB)`, true);
      continue;
    }
    try {
      const bytes = new Uint8Array(await file.arrayBuffer());
      const item = await invoke("send_file", bytes, {
        headers: {
          "x-contact": String(c.id),
          "x-name": encodeURIComponent(file.name || "file"),
          "x-mime": encodeURIComponent(file.type || "application/octet-stream"),
          "x-caption": encodeURIComponent(i === 0 ? caption : ""),
        },
      });
      if (i === 0 && caption) {
        $("text").value = "";
        state.drafts.delete(c.id);
        autoGrow();
      }
      if (state.openId === c.id) {
        state.messages.push(item);
        renderMessages();
      }
    } catch (err) {
      toast(String(err), true);
    }
  }
  refreshContacts();
}

let dragDepth = 0;
const chatCol = document.querySelector(".chat-col");
chatCol.addEventListener("dragenter", (e) => {
  if (![...(e.dataTransfer?.types ?? [])].includes("Files") || $("text").disabled) return;
  dragDepth++;
  $("drop").hidden = false;
});
chatCol.addEventListener("dragleave", () => {
  if (--dragDepth <= 0) {
    dragDepth = 0;
    $("drop").hidden = true;
  }
});
chatCol.addEventListener("dragover", (e) => e.preventDefault());
chatCol.addEventListener("drop", (e) => {
  e.preventDefault();
  dragDepth = 0;
  $("drop").hidden = true;
  sendFiles([...(e.dataTransfer?.files ?? [])]);
});

// Paste: images go to the open chat; an invite link anywhere opens "Add contact".
document.addEventListener("paste", (e) => {
  if (!state.unlocked) return;
  const files = [...(e.clipboardData?.files ?? [])];
  if (files.length && state.openId != null && !$("text").disabled && !document.querySelector("dialog[open]")) {
    e.preventDefault();
    sendFiles(files);
    return;
  }
  const text = e.clipboardData?.getData("text") ?? "";
  const match = text.match(INVITE_RE);
  const inField = e.target.closest?.("#join-link, #relay-paste, #set-relay");
  if (match && !inField) {
    e.preventDefault();
    openAdd("join", match[0]);
  }
});

$("back-btn").addEventListener("click", () => {
  state.drafts.set(state.openId, $("text").value);
  state.openId = null;
  $("info").hidden = true;
  showConversation(false);
  renderContacts();
});

// ============ contact info panel ============
async function renderInfo() {
  const c = current();
  if (!c) return;
  avatarFor(c, $("info-avatar"));
  $("info-avatar").classList.add("big");
  $("info-name").value = c.name;
  $("info-save-name").hidden = true;
  $("info-status").textContent = STATUS[key(c.status)];
  $("info-timer").value = c.timer ? String(c.timer) : "";
  $("info-timer").disabled = key(c.status) !== "ready";
  const code = await invoke("security_code", { contactId: c.id }).catch(() => null);
  $("info-code-sec").hidden = !code;
  $("info-code").replaceChildren(...(code ?? "").split(" ").filter(Boolean).map((g) => el("span", null, g)));
}
function toggleInfo(force) {
  const show = force ?? $("info").hidden;
  $("info").hidden = !show;
  if (show) renderInfo();
}
$("info-btn").addEventListener("click", () => toggleInfo());
$("who-btn").addEventListener("click", () => toggleInfo(true));
$("timer-btn").addEventListener("click", () => {
  toggleInfo(true);
  $("info-timer").focus();
});
$("info-close").addEventListener("click", () => toggleInfo(false));
$("info-name").addEventListener("input", () => ($("info-save-name").hidden = false));
async function saveName() {
  const alias = $("info-name").value.trim() || null;
  await invoke("rename_contact", { contactId: state.openId, alias });
  $("info-save-name").hidden = true;
  await refreshContacts();
  toast("Name saved");
}
$("info-save-name").addEventListener("click", saveName);
$("info-name").addEventListener("keydown", (e) => e.key === "Enter" && saveName());
$("info-timer").addEventListener("change", async () => {
  const v = $("info-timer").value;
  try {
    await invoke("set_timer", { contactId: state.openId, ttl: v ? Number(v) : null });
  } catch (err) {
    toast(String(err), true);
    renderInfo();
  }
});
$("delete-btn").addEventListener("click", async () => {
  const c = current();
  if (!c) return;
  const ok = await confirmDialog(
    `Delete ${c.name}?`,
    "They'll be told you left, and the whole conversation (including files) is erased from this device. This can't be undone.",
    [{ label: "Delete", cls: "danger" }],
  );
  if (!ok) return;
  await invoke("delete_contact", { contactId: c.id });
  state.openId = null;
  $("info").hidden = true;
  showConversation(false);
  refreshContacts();
});

// ============ confirm dialog ============
/** Resolves to the chosen option's value (or true), or false if cancelled. */
function confirmDialog(title, text, options) {
  $("confirm-title").textContent = title;
  $("confirm-text").textContent = text;
  const actions = $("confirm-actions");
  actions.replaceChildren(actions.firstElementChild);
  const dlg = $("confirm-dlg");
  return new Promise((resolve) => {
    let result = false;
    for (const o of options) {
      const b = el("button", "btn " + (o.cls || "primary"), o.label);
      b.type = "button";
      b.addEventListener("click", () => {
        result = o.value ?? true;
        dlg.close();
      });
      actions.append(b);
    }
    dlg.addEventListener("close", () => resolve(result), { once: true });
    dlg.showModal();
  });
}

// ============ add contact ============
function setTab(which) {
  const invite = which === "invite";
  $("tab-invite").setAttribute("aria-selected", String(invite));
  $("tab-join").setAttribute("aria-selected", String(!invite));
  $("pane-invite").hidden = !invite;
  $("pane-join").hidden = invite;
  (invite ? $("invite-alias") : $("join-link")).focus();
}
$("tab-invite").addEventListener("click", () => setTab("invite"));
$("tab-join").addEventListener("click", () => setTab("join"));

function openAdd(tab = "invite", link = "") {
  if (!settings.relay) return openRelaySetup(() => openAdd(tab, link));
  $("invite-form").hidden = false;
  $("invite-result").hidden = true;
  $("invite-alias").value = "";
  $("join-link").value = link;
  $("join-alias").value = $("join-error").textContent = "";
  $("add-dlg").showModal();
  setTab(tab);
  if (link) $("join-alias").focus();
}
$("add-btn").addEventListener("click", () => openAdd());
$("empty-add").addEventListener("click", () => openAdd());

$("invite-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const btn = $("invite-create");
  btn.disabled = true;
  try {
    const inv = await invoke("create_invite", { alias: $("invite-alias").value.trim() || null });
    state.invites.set(inv.contactId, inv);
    $("qr").src = "data:image/svg+xml;base64," + btoa(inv.qrSvg);
    $("invite-link").textContent = inv.link;
    $("invite-form").hidden = true;
    $("invite-result").hidden = false;
    await refreshContacts();
    openChat(inv.contactId);
  } catch (err) {
    toast(String(err), true);
  } finally {
    btn.disabled = false;
  }
});

async function copyText(text, msg) {
  try {
    await navigator.clipboard.writeText(text);
    toast(msg);
  } catch (_) {
    toast("Couldn't copy. Select the text and press Ctrl+C.", true);
  }
}
$("copy-link").addEventListener("click", () => copyText($("invite-link").textContent, "Link copied"));
$("copy-msg").addEventListener("click", () => copyText(inviteMessage($("invite-link").textContent), "Message copied. Paste it into any app."));

$("paste-btn").addEventListener("click", async () => {
  try {
    const t = await navigator.clipboard.readText();
    const m = t.match(INVITE_RE);
    $("join-link").value = m ? m[0] : t.trim();
    if (!m) $("join-error").textContent = "Your clipboard doesn't contain a lethe invite link.";
    else {
      $("join-error").textContent = "";
      $("join-alias").focus();
    }
  } catch (_) {
    $("join-link").focus();
    toast("Press Ctrl+V to paste", false);
  }
});

$("join-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const raw = $("join-link").value;
  const link = raw.match(INVITE_RE)?.[0];
  if (!link) return ($("join-error").textContent = "That doesn't look like a lethe invite. It should start with lethe://inv#");
  $("join-submit").disabled = true;
  try {
    const id = await invoke("accept_invite", { link, alias: $("join-alias").value.trim() || null });
    $("add-dlg").close();
    await refreshContacts();
    openChat(id);
    toast("Connecting… this takes a few seconds");
  } catch (err) {
    $("join-error").textContent = String(err).includes("invitation") ? "That invite link is damaged or incomplete." : String(err);
  } finally {
    $("join-submit").disabled = false;
  }
});

// ============ relay setup ============
let afterRelay = null;
function openRelaySetup(then = null) {
  afterRelay = then;
  $("relay-paste").value = "";
  $("relay-error").textContent = "";
  $("relay-host").disabled = false;
  $("relay-dlg").showModal();
}
async function relayReady(message) {
  await loadSettings();
  $("relay-dlg").close();
  toast(message);
  const next = afterRelay;
  afterRelay = null;
  if (next) next();
}
$("relay-host").addEventListener("click", async () => {
  $("relay-host").disabled = true;
  $("relay-error").textContent = "";
  try {
    await invoke("host_local_relay");
    await relayReady("Relay running on this computer");
  } catch (err) {
    $("relay-error").textContent = String(err);
    $("relay-host").disabled = false;
  }
});
$("relay-paste-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const relay = $("relay-paste").value.trim();
  if (!relay) return ($("relay-error").textContent = "Paste a relay address first.");
  try {
    await invoke("set_settings", { settings: { ...settings, relay } });
    await relayReady("Relay saved");
  } catch (err) {
    $("relay-error").textContent = String(err).includes("relay address") ? "That doesn't look like a relay address. It should start with lethe-relay://" : String(err);
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
  $("set-notify").value = settings.notifications ?? "name";
  $("set-receipts").checked = settings.readReceipts ?? true;
  $("settings-error").textContent = "";
  refreshHostRow();
  $("settings-dlg").showModal();
}
$("settings-btn").addEventListener("click", openSettings);

async function refreshHostRow() {
  const addr = await invoke("local_relay_address");
  $("host-dot").classList.toggle("on", !!addr);
  $("host-text").textContent = addr ? "This computer is hosting a relay" : "Not hosting a relay";
  $("host-toggle").textContent = addr ? "Stop hosting" : "Host on this computer";
  $("host-toggle").dataset.on = addr ? "1" : "";
}
$("host-toggle").addEventListener("click", async () => {
  if ($("host-toggle").dataset.on) {
    const ok = await confirmDialog(
      "Stop hosting the relay?",
      "Conversations that use this relay stop receiving messages until you host it again.",
      [{ label: "Stop hosting", cls: "danger" }],
    );
    if (!ok) return;
    await invoke("stop_local_relay");
  } else {
    try {
      const s = await invoke("host_local_relay");
      $("set-relay").value = s.relay ?? "";
    } catch (err) {
      $("settings-error").textContent = String(err);
    }
  }
  await loadSettings();
  refreshHostRow();
});

$("settings-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const next = {
    relay: $("set-relay").value,
    profileName: $("set-name").value,
    socksProxy: $("set-proxy").value,
    autoLockMinutes: Number($("set-autolock").value),
    notifications: $("set-notify").value,
    readReceipts: $("set-receipts").checked,
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

// ============ keyboard shortcuts ============
document.addEventListener("keydown", (e) => {
  if (!state.unlocked) return;
  const mod = e.ctrlKey || e.metaKey;
  if (mod && e.key.toLowerCase() === "k") {
    e.preventDefault();
    $("search").focus();
    $("search").select();
  } else if (mod && e.key.toLowerCase() === "n") {
    e.preventDefault();
    openAdd();
  } else if (mod && e.key.toLowerCase() === "l") {
    e.preventDefault();
    lockNow();
  } else if (e.key === "Escape" && !document.querySelector("dialog[open]")) {
    if (!$("info").hidden) toggleInfo(false);
    else if (document.activeElement === $("search") && $("search").value) {
      $("search").value = state.filter = "";
      renderContacts();
    }
  }
});

// ============ window title & focus ============
function setTitle(unread) {
  const t = unread > 0 ? `(${unread}) lethe` : "lethe";
  document.title = t;
  appWindow?.setTitle?.(t).catch?.(() => {});
}
window.addEventListener("focus", () => state.unlocked && state.openId != null && markRead());

// ============ events from Rust ============
function replaceItem(item) {
  const i = state.messages.findIndex((m) => m.id === item.id);
  if (i >= 0) state.messages[i] = item;
}

listen("lethe-event", async ({ payload: e }) => {
  if (!state.unlocked) return;
  const here = e.contactId === state.openId;
  switch (e.type) {
    case "message":
      if (here) {
        state.messages.push(e.item);
        renderMessages();
        if (document.hasFocus()) await invoke("mark_read", { contactId: e.contactId }).catch(() => {});
      }
      refreshContacts();
      break;
    case "itemStatus": {
      const m = here && state.messages.find((x) => x.id === e.itemId);
      if (m) {
        m.status = e.status;
        renderMessages();
      }
      refreshContacts();
      break;
    }
    case "itemUpdated":
      if (here) {
        replaceItem(e.item);
        renderMessages();
      }
      if (key(e.item.attachment?.state) !== "transferring") refreshContacts();
      break;
    case "itemsRemoved":
      for (const id of e.ids) {
        const url = state.blobs.get(id);
        if (url) URL.revokeObjectURL(url);
        state.blobs.delete(id);
      }
      if (here) {
        state.messages = state.messages.filter((m) => !e.ids.includes(m.id));
        renderMessages();
      }
      refreshContacts();
      break;
    case "contactUpdated":
      await refreshContacts();
      if (here && !$("info").hidden) renderInfo();
      break;
    case "contactConnected": {
      state.invites.delete(e.contactId);
      await refreshContacts();
      const c = state.contacts.find((x) => x.id === e.contactId);
      if (c) toast(`${c.name} connected`);
      if ($("add-dlg").open && !$("invite-result").hidden) $("add-dlg").close();
      if (here) {
        renderMessages();
        if (!$("info").hidden) renderInfo();
      }
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
