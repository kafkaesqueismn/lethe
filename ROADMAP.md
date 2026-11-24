# lethe roadmap

Where lethe stands, what to build next, and how the pieces fit, so work can continue at any pace. Items are roughly in priority order within each section.

## Do these first

1. **Android signing (5 minutes).** Run `scripts/setup-android-signing.sh` once, then back up `~/.config/lethe-signing/`. After that, every tagged release includes a signed `lethe-android.apk`.
2. **A public relay.** Follow "Run a public relay" in the README on any small VPS. Until then, people outside your Wi-Fi can't reach you. Consider putting its address in the app as a suggested default.
3. **Test on two real devices** (PC + laptop, or PC + Android): invite, files, disappearing messages, lock/unlock while messages arrive.

## Security and privacy (before anyone relies on it)

- **Header encryption** for the Double Ratchet (Signal's "header encryption" variant). Today the ratchet public key and counters are visible to the relay inside the queue layer. Code: `crates/crypto/src/ratchet.rs`.
- **Queue rotation:** periodically move a conversation to fresh queues (possibly on another relay), so a relay can't watch one queue for months. SimpleX's design is a good reference.
- **Delivery-receipt timing:** receipts reveal when a device was online. Add an option to batch or delay them.
- **Relay abuse limits:** cap queue creation per connection, and add a proof-of-work or an access password for private relays.
- **Hosted relay address changes:** the in-app relay advertises the PC's LAN IP. If that changes, contacts using it break. Options: mDNS (`lethe.local`), or letting contacts learn a new address through the existing encrypted channel.
- **Independent audit** of `crates/crypto` and the handshake/queue flow in `crates/client/src/agent.rs`.
- **Reproducible builds** so people can check that the published installers match the source.

## Features

- **Group chats:** start with pairwise fan-out (each member gets their own copy over the existing 1:1 channels), like early SimpleX.
- **Deep links:** clicking `lethe://inv#…` opens the app (`tauri-plugin-deep-link`).
- **QR scanning** with the camera (mobile first).
- **Replies, reactions, message editing.** These are new `AppMsg` variants in `crates/client/src/model.rs`.
- **Voice messages:** record in the web view and send them as attachments.
- **Multiple profiles / incognito per contact.**
- **Export/backup** of a profile, encrypted with the passphrase.
- **Background delivery on mobile:** decide between periodic polling (most private) and a push relay (reveals some timing metadata).
- **iOS:** needs a Mac with Xcode, and an Apple Developer account to distribute.

## Polish

- Deleting a message for everyone could leave a "message deleted" placeholder on the other side.
- Show a "new messages" divider when opening a chat with unread messages.
- Link previews: never fetched automatically (privacy); maybe an opt-in "tap to load".
- Code-sign the Windows and macOS installers so the "unknown publisher" warnings go away.

## How the code fits together

```
crates/crypto   primitives, padding, Argon2id, X3DH-style handshake, Double Ratchet
crates/proto    wire protocol: commands, fixed 16 KB frames, relay addresses, relay→recipient layer
crates/relay    lethe-relay: queues, signature checks, persistence (persist.rs), TLS (tls.rs)
crates/client   the agent: contacts, connection state machine, outbox, files, receipts, timers
                  model.rs  stored state + messages inside the ratchet (AppMsg)
                  agent.rs  everything that happens (public API at the top)
                  store.rs  encrypted profile + encrypted attachment blobs
crates/cli      terminal client, handy for debugging
app/src-tauri   desktop/mobile shell: Tauri commands wrapping the agent, in-app relay, notifications
app/ui          the interface: plain HTML/CSS/JS, no npm dependencies
```

**Adding a message feature** usually means:

1. Add a variant to `AppMsg` in `model.rs`. Append it, and give new stored fields `#[serde(default)]` so existing profiles keep opening.
2. Send it from a new `Agent` method in `agent.rs`. Copy `set_timer` or `delete_items`: seal with the ratchet → `enqueue_sealed` → save → `spawn_flush`.
3. Handle it in `process_incoming` and emit an `Event`.
4. Add an end-to-end test in `crates/client/tests/e2e.rs`. The existing tests show how to spin up relays and agents.
5. Expose it with a `#[tauri::command]` in `app/src-tauri/src/lib.rs` (and register it in `generate_handler!`), then use it from `app/ui/main.js`.

**Rules that keep it secure (please keep them):**

- Persist ratchet output *before* sending it. Never encrypt twice with the same state.
- Process incoming messages on a copy and commit only on success.
- In the UI, never put message or contact text into `innerHTML`; always use `textContent`.
- Keep the web view's permissions minimal (`app/src-tauri/capabilities/default.json`).

## Everyday commands

```sh
cargo test --workspace                     # all tests (about 30 s)
cargo test -p lethe-client --test e2e -- --ignored   # + the slow 6 MB transfer test
cargo clippy --workspace --all-targets -- -D warnings
./run.sh two                               # relay + two app windows (alice, bob)
scripts/install-linux.sh                   # install the app from source
```

## Releasing

1. Work on `dev`. CI runs the tests on every push.
2. Bump the version in `Cargo.toml` (`[workspace.package]`), `app/src-tauri/Cargo.toml` and `app/src-tauri/tauri.conf.json`. Use plain numbers like `0.3.0`, because Windows MSI installers reject versions like `-alpha`.
3. Optionally merge `dev` into `main`.
4. `git tag v0.3.0 && git push origin v0.3.0`. GitHub builds Windows, Linux, macOS and Android installers and publishes a pre-release in about 15 minutes.
