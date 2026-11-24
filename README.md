# lethe

*Named after Lethe, the river of forgetfulness in Greek myth: relays forget every message once it's delivered, and there's no identity to remember you by.*

A private messenger with **no user identifiers at all**: no accounts, phone numbers, emails, usernames or public keys that identify you. The design follows [SimpleX](https://simplex.chat/): contacts are connected by **pairwise, anonymous one-way queues** on relays, and messages are end-to-end encrypted with the **Double Ratchet**.

> 🚧 **This is a prototype.** It's a personal project I'll keep working on over time, and the goal is for it to grow into a fully fledged app. For now it's an early prototype. Expect rough edges, missing features, and breaking changes to the protocol and storage formats between versions.
>
> ⚠️ The cryptography has **not** been independently audited. Please don't rely on it where your safety is at stake.

## How it works

```
  Alice                         relay A            relay B                  Bob
  NEW ─────────────────────────▶ q_A
  link(q_A sender id, ik_a, ek_a) ═══════ out of band (QR / paste) ═══════▶
                                                    q_B ◀──────────────── NEW
                                 q_A ◀── SEND Confirmation(ik_b, ek_b, ratchet[ConnInfo{key_b, q_B}])
  KEY(key_b) ──────────────────▶ q_A   (now only Bob can send to q_A)
  SEND ratchet[ConnInfo{key_a}] ───────────────────▶ q_B
                                                    q_B ◀─────────── KEY(key_a)
  ═══════════════ both queues secured; Double Ratchet messages flow ═══════════════
```

| Layer | What it protects |
|---|---|
| X3DH-style handshake → **Double Ratchet** (X25519, HKDF-SHA256, HMAC-SHA256, XChaCha20-Poly1305) | Message content. Forward secrecy and post-compromise security. |
| Per-queue relay→recipient encryption (DH between the relay's and recipient's queue keys) | Incoming and outgoing ciphertext at a relay can't be matched, even if TLS is broken. |
| TLS 1.3, with the relay certificate **pinned by fingerprint** in its address | Transport. No certificate authorities or DNS trust involved. |
| Fixed 16 KB frames, and fixed-size padded plaintext inside the ratchet | Message length, and which command is being sent. |
| Separate random **recipient ID** and **sender ID** per queue, Ed25519 auth key per queue | The relay can't link a sender to a recipient, or two queues to one person. |
| Optional SOCKS5 / Tor for all connections | Your IP address, hidden from relays. `.onion` relays work too. |
| Local store: Argon2id(passphrase) → XChaCha20-Poly1305, atomic writes, `0600` | Data at rest on the device. |

What a relay sees: queue IDs, the public keys authorizing them, timing, and opaque fixed-size blobs until they're acknowledged. It never logs client IPs. Invitations are **one-time**: once the first person connects, the queue is locked to their key.

Known gaps, tracked for later:
- The ratchet header isn't encrypted yet.
- There's no queue rotation yet.
- There are no groups or file transfer yet.

## Layout

```
crates/crypto   primitives, padding, Argon2id, X3DH-style handshake, Double Ratchet
crates/proto    wire protocol: commands, fixed-size framing, relay addresses, delivery layer
crates/relay    lethe-relay server (lib + bin)
crates/client   agent: queues, contacts, connection state machine, outbox, encrypted store
crates/cli      `lethe` terminal client
app/            Tauri 2 desktop + mobile app (src-tauri = Rust shell, ui = dependency-free HTML/JS)
```

## Install

Pre-built installers are on the [Releases page](https://github.com/kafkaesqueismn/lethe/releases) once a version is tagged. GitHub Actions builds them automatically.

| Platform | How |
|---|---|
| **Windows** | Download the `.exe` installer (or `.msi`) from Releases. Windows SmartScreen will warn about an unknown publisher, because the prototype isn't code-signed: click *More info → Run anyway*. |
| **Arch / any Linux** | Download the `.AppImage`, `chmod +x` it and run it. Or build and install from source with `scripts/install-linux.sh` (adds lethe to your app menu; `scripts/install-linux.sh uninstall` removes it). |
| **Debian / Ubuntu, Fedora** | `.deb` / `.rpm` from Releases. |
| **macOS** | `.dmg` from Releases. It's unsigned, so right-click → *Open* the first time. |
| **Android** | `lethe-android.apk` from Releases. Allow your browser or file manager to *install unknown apps*. |
| **iOS** | Not yet. Building for iOS needs a Mac with Xcode, and installing on other people's phones needs an Apple Developer account. |

**Every device needs to reach the same relay.** A relay on `127.0.0.1` only works on that one computer. To test between your PC and phone on the same Wi-Fi, run `lethe-relay --listen 0.0.0.0:5223 --host <your PC's LAN IP>` and use the address it prints. For real use, run it on a server with a public address.

## Running it (development)

The quickest way to try it is a local relay plus two app windows, so you can message yourself:

```sh
./run.sh two     # alice + bob windows; create a profile in each, invite in one, join in the other
./run.sh         # one app window
./run.sh cli me  # terminal client
```

Or by hand:

```sh
cargo test --workspace                       # crypto, protocol, store, full end-to-end tests

# a relay (prints its lethe-relay://… address, including the cert fingerprint)
cargo run --release -p lethe-relay -- --host <public-host-or-ip> --data-dir relay-data

# two terminal clients
cargo run -p lethe-cli -- --profile alice --relay 'lethe-relay://…' --name Alice
cargo run -p lethe-cli -- --profile bob   --relay 'lethe-relay://…' --name Bob
#  alice> /invite            → copy the link to bob
#  bob>   /join <link>
#  then /open <id> and type
```

### Desktop app

Needs webkit2gtk-4.1 on Linux (Arch: `sudo pacman -S --needed webkit2gtk-4.1 base-devel`), WebView2 on Windows (preinstalled on Windows 10/11), nothing extra on macOS.

```sh
cargo install tauri-cli --version '^2' --locked
cd app/src-tauri
cargo tauri dev        # or: cargo tauri build
```

On first launch, set your relay address in Settings.

### Mobile (Android / iOS)

The same app targets mobile through Tauri 2. You need `rustup` (the Arch `rust` package can't add cross targets) plus the Android SDK/NDK or Xcode:

```sh
rustup target add aarch64-linux-android armv7-linux-androideabi x86_64-linux-android
cd app/src-tauri && cargo tauri android init && cargo tauri android dev
```

Release APKs are signed in CI with a key that the maintainer sets up once with `scripts/setup-android-signing.sh`.

Background delivery on mobile is still an open design question. Polling keeps the most privacy; push notifications would need a push relay that learns some metadata.

## Branches and releases

- `dev` is where work happens. Every push runs the tests (see `.github/workflows/ci.yml`).
- `main` holds stable states. Merge `dev` into it when something is ready.
- Tag a commit (`git tag v0.1.0 && git push --tags`) to build installers for every platform and publish a pre-release. Builds can also be started by hand from the Actions tab (*Build installers → Run workflow*), with files attached to the run instead of a release.

## License

[GNU AGPL-3.0-or-later](LICENSE). You can use, study, modify and share lethe freely. If you distribute a modified version, or run a modified relay as a network service, you must publish its source under the same license.
