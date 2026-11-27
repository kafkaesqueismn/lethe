# Lethe: design, threat model and research notes

> **Status: research and learning project. Not production cryptography.**
> Lethe is where I study end-to-end encryption by building it. The protocols are
> wired together by hand from their specifications, on top of audited primitive
> libraries. It has not been reviewed by anyone else. Don't use it to protect
> anything that matters.

## 1. What Lethe is for

Lethe started as a private messenger for me and a friend. It is now mainly a
**lab for studying applied cryptography**, and its real output is written:

- **Understanding.** I should be able to explain every line of `crates/crypto`,
  why it is there, and what breaks if it is removed.
- **Writeups.** Each protocol component becomes a research-style post: what the
  spec says, how I implemented it, where I deviated and why, what I got wrong,
  and anything interesting I found along the way.

The messenger still has to work. A protocol you can't run end to end can't be
tested or attacked. But features are only worth building when they open up
something to study.

### Goals

1. Implement X3DH-style key agreement, the Double Ratchet, AEAD usage and local
   key management from the primary specifications, and document each one.
2. Make every deviation from a spec explicit, deliberate and written down.
3. Look for weaknesses in my own implementation and publish them, including the
   embarrassing ones.
4. Keep the code readable enough for someone else to study it alongside the writeups.

### Non-goals

- Being a messenger other people rely on for safety.
- Implementing primitives (curve arithmetic, ciphers, hashes, KDFs). Those come
  from vetted crates: `x25519-dalek`, `ed25519-dalek`, `chacha20poly1305`,
  `hkdf`, `hmac`, `sha2`, `argon2`. Hand-rolling them teaches less than it
  risks, and it isn't what this project is about.
- Feature count, polish and platform coverage, except where they serve the goals.

## 2. Ground rules

1. **Primitives come from libraries; protocols are mine.** Library code stops at
   `crates/crypto/src/primitives.rs`. Everything above that line is something I
   should be able to derive on a whiteboard.
2. **Cite the spec.** Each protocol module's doc comment names the document and
   section it implements, and lists its deviations.
3. **Domain-separate everything.** Every KDF call gets its own versioned `info`
   label (`"lethe x3dh v1"`, `"lethe ratchet rk v1"`, …), so a key derived for one
   purpose can never be confused with another.
4. **Fail closed and stay consistent.** Decryption works on a copy of the state
   and commits only on success, so a forged message can't corrupt a session.
5. **Write decisions down when they're made** (section 8), not afterwards.

## 3. Architecture

```
            ┌─────────────────────────────────────────────┐
  app/      │ Tauri shell + plain HTML/JS UI              │  presentation
            └──────────────────────┬──────────────────────┘
            ┌──────────────────────▼──────────────────────┐
  client    │ agent: contacts, connection state machine,  │  orchestration
            │ outbox  ── store.rs (encrypted at rest)     │  + storage
            │         ── transport.rs (TLS, pinning)      │  + transport
            └───────┬──────────────────────────┬──────────┘
            ┌───────▼────────┐        ┌────────▼─────────┐
  crypto    │ x3dh, ratchet, │        │ proto: commands, │  protocol
            │ pad, passphrase│◀───────│ framing, delivery│
            ├────────────────┤        └──────────────────┘
            │ primitives.rs  │  ◀── the only file that touches crypto libraries
            └────────────────┘
  relay     separate binary; sees only `proto`, never ratchet plaintext
```

| Crate | Responsibility | Crypto it owns |
|---|---|---|
| `crypto` | Pure, I/O-free protocol logic | X3DH-style handshake, Double Ratchet, padding, Argon2id |
| `proto` | Wire format, fixed 16 KB frames | Relay→recipient delivery layer, command signatures |
| `relay` | Store-and-forward queues | TLS identity, queue auth checks |
| `client` | Agent and state machine | Store encryption, security codes, the order of seal → persist → send |
| `app` | UI | None, and it should stay that way |

**Structural debt that matters for the research:** `client/src/agent.rs` (~1000
lines) mixes the connection state machine with transport and storage calls. The
handshake *protocol* lives there, not in `crypto`. To write about the handshake
as a protocol, I need to be able to read and test it in isolation, so moving the
connection state machine into its own module is a candidate refactor.

## 4. Threat model

### Assets

- **Message content** (text, files) and metadata inside the ratchet.
- **Who talks to whom** (the social graph).
- **When and how much** people talk (timing and volume).
- **Data at rest** on a device: profile, ratchet states, history, attachments.

### Adversaries

| # | Adversary | Capabilities | Lethe's intended defence |
|---|---|---|---|
| A1 | Passive network observer | Sees all traffic between clients and relays | TLS 1.3 with pinned certificates; fixed-size frames; optional Tor |
| A2 | Malicious or compromised relay | Reads and changes everything it stores and forwards; drops, delays, replays or reorders | E2E AEAD (relay can't read or forge); per-queue IDs (relay can't easily link queues); ratchet replay protection |
| A3 | Invitation interceptor | Sees or replaces the invitation link before the intended peer uses it | **Security codes only.** See 4.1 |
| A4 | Offline device thief | Has the disk, not the passphrase | Argon2id + XChaCha20-Poly1305 store |
| A5 | Later key compromise | Gets ratchet state at time *t* | Forward secrecy for messages before *t*, but only for ones not kept in the store (see 7.3); post-compromise security after the next DH ratchet step |
| A6 | Malicious contact | A legitimate peer sending crafted messages | Bounded skipped keys (`MAX_SKIP`), transactional decryption, size limits |

### Explicitly out of scope

- **Live endpoint compromise** (malware, a compromised OS, an unlocked device). No messaging protocol defends against this.
- **A global passive adversary doing traffic correlation.** Padding and Tor help, but I make no claims.
- **Side channels** (timing, cache, power) in my code. The primitive libraries aim to be constant time; my protocol code makes no such promise.
- **Denial of service** by a relay. A relay can always drop messages.
- **Any security property that depends on this code being correct.** It hasn't been reviewed.

### 4.1 The trust anchor is the invitation

Lethe has **no long-term identity keys**. Each connection's "identity" keys
(`ik_a`, `ik_b`) are fresh, so authentication reduces to:

- *The joiner authenticates the inviter* only because the link (`ik_a`, `ek_a`,
  queue address) arrived over a channel they trust.
- *The inviter doesn't authenticate the joiner at all.* Whoever uses the
  one-time link first becomes the contact.

So an adversary who can **read** the link can race the real joiner, and one who
can **replace** it can sit in the middle (A3). Comparing security codes (a hash
of `ik_a || ik_b`) in person is the only thing that detects this. Writing this
down precisely, and finding out how SimpleX handles the same problem, is a
research item (R1).

## 5. Protocol inventory

| Component | Code | Primary reference | Status |
|---|---|---|---|
| Key agreement | `crypto/src/x3dh.rs` | Signal, *The X3DH Key Agreement Protocol* | Implemented, with deviations (6.1) |
| Double Ratchet | `crypto/src/ratchet.rs` | Signal, *The Double Ratchet Algorithm* | Implemented, without header encryption (6.2) |
| AEAD | `crypto/src/primitives.rs` | RFC 8439; XChaCha20 draft (`draft-irtf-cfrg-xchacha`) | Library-backed wrappers |
| Padding | `crypto/src/pad.rs` | Own design | Implemented |
| Delivery layer | `proto/src/lib.rs` (`delivery`) | SimpleX messaging protocol (SMP) | Implemented, with deviations (6.3) |
| Store encryption | `crypto/src/passphrase.rs`, `client/src/store.rs` | RFC 9106 (Argon2) | Implemented |
| Security codes | `client/src/agent.rs` (`security_code`) | Signal safety numbers (inspiration) | Implemented |
| Queue auth | `proto`, `relay` | SimpleX SMP | Implemented |

## 6. How Lethe differs from the specs

This section is the core of the writeups. Each entry should eventually say what
the spec does, what I do, why, and what it costs.

### 6.1 X3DH-style handshake

Name mapping. In Signal, Bob publishes a prekey bundle and Alice initiates. In
Lethe, the **inviter** publishes (so plays Signal's Bob) and the **joiner**
initiates (so plays Signal's Alice):

| Signal | Lethe | Note |
|---|---|---|
| `IK_B` (Bob's identity key) | `ik_a` (inviter) | Fresh per invitation, not long-term |
| `SPK_B` (signed prekey) | `ek_a` (inviter) | **Not signed.** The link's integrity stands in for the signature |
| `OPK_B` (one-time prekey) | none | The whole invitation is one-time instead |
| `IK_A` (Alice's identity key) | `ik_b` (joiner) | Fresh per connection |
| `EK_A` (Alice's ephemeral key) | `ek_b` (joiner) | |

With that mapping, the three DHs match the spec exactly:
`DH1 = DH(IK_A, SPK_B) = DH(ik_b, ek_a)`,
`DH2 = DH(EK_A, IK_B) = DH(ek_b, ik_a)`,
`DH3 = DH(EK_A, SPK_B) = DH(ek_b, ek_a)`.

Matches the spec:
- KDF input is `F || DH1 || DH2 || DH3`, with `F` = 32 × `0xFF` for X25519, and a zero-filled salt the length of the hash output.
- `ek_a` is reused as the inviter's first ratchet key, the way Signal reuses `SPK_B`.

Deviations to write up:
- **No long-term identities, so no signatures (XEdDSA).** This is deliberate (no
  identifiers), and it changes what the three DHs buy you. With fresh identity
  keys on both sides, what does each DH still contribute? Is DH1 or DH2 doing
  anything a plain ephemeral–ephemeral DH plus an authenticated link wouldn't?
  (R2)
- **AD order and encoding.** The spec defines `AD = Encode(IK_A) || Encode(IK_B)`,
  initiator first, where `Encode` includes a curve-type byte. Lethe uses raw
  `ik_a || ik_b`, responder first. That's consistent on both ends, so it isn't a
  bug, but it is a deviation and should be noted.
- **Low-order points.** `DhKeyPair::dh` rejects non-contributory results. Worth
  explaining why X25519 needs this check at all (R3).

### 6.2 Double Ratchet

Matches the spec's recommended algorithms:
- `KDF_RK` = HKDF-SHA256 with the root key as salt.
- `KDF_CK` = HMAC-SHA256 with constant inputs `0x01` (message key) and `0x02` (next chain key).
- The skipped-message-key dictionary is bounded (`MAX_SKIP` = 1000 per chain).

Deviations and design choices:
- **AEAD instead of AES-CBC + HMAC.** The message key goes through HKDF to produce
  a 32-byte key and a 24-byte nonce for XChaCha20-Poly1305. That's safe because
  each message key is used exactly once. I need to explain why "used once"
  makes a deterministic nonce acceptable (R4).
- **Header in the clear.** `(dh, pn, n)` is authenticated as AD but not encrypted,
  so the relay sees ratchet public keys and counters (only under the delivery
  layer, but still). Header encryption (spec §4) is the next big component to
  implement. (R5)
- **Global cap on stored skipped keys** (`MAX_STORED_SKIPPED` = 2000, oldest
  dropped). The spec leaves this to the implementation. The cost is that very
  late messages silently become undecryptable.
- **Transactional decrypt.** `decrypt` clones the state and commits only if the
  AEAD check passes. Without this, a forged header with a fresh `dh` would force
  a DH ratchet step and desync the session. That's a good concrete example for
  a writeup on why error handling *is* security (R6).

### 6.3 Relay→recipient delivery layer

- Key = HKDF(DH(relay queue key, recipient queue key)), constant for the life of
  the queue. Nonce = `msg_id`, 24 random bytes chosen **by the relay**.
  Confidentiality therefore depends on the relay never repeating a `msg_id`,
  which is reasonable with 192 random bits. Still, it's worth stating that this
  layer trusts the relay for nonce uniqueness, against the relay itself only
  for… what exactly? (R7)
- The HKDF call puts a label in the *salt* slot and another in *info*. That's
  unconventional. Check what RFC 5869 says about salt versus info.

### 6.4 Data at rest

- Argon2id with m = 64 MiB, t = 3, p = 1. The code comment calls this an
  "OWASP-recommended baseline". **That needs checking:** it looks closer to RFC
  9106's second recommended option (m = 64 MiB, t = 3, p = 4) with fewer lanes.
  Fix the comment or the parameters once I've read both sources.
- One store key encrypts the state and every attachment blob, each with a fresh
  random nonce and the blob name as AD (so blobs can't be swapped).

## 7. Open questions and candidate findings

This is the research backlog. Each item is a potential post. Mark items
*verified* only after writing a test or a proof sketch.

| ID | Question | Status |
|---|---|---|
| R1 | How exactly does the invitation-interception attack (A3) play out? Does SimpleX defend against it better than Lethe? | Open |
| R2 | With no long-term identities, what does each of the three DHs actually contribute? | Open |
| R3 | Why does X25519 need the contributory check? What attack does it prevent here? | Open |
| R4 | Why is a deterministic nonce safe with a single-use message key? | Open |
| R5 | Implement header encryption from the spec and measure what the relay can no longer learn | Open |
| R6 | Demonstrate the desync attack against a *non*-transactional decrypt (a test that fails without the clone) | Open |
| R7 | Delivery layer: what is it actually meant to protect against, given that the relay chooses the nonce? | Open |
| R8 | Forward secrecy versus retention. Message history is stored in the profile, so a device compromise reveals old messages regardless of the ratchet. Disappearing messages are the real forward secrecy at rest. Write this up honestly. | Open |
| R9 | Zeroization. Ratchet keys are zeroized on drop, but are serialized copies (CBOR buffer, clones, serde intermediates) as well? | Open |
| R10 | Security-code entropy: 6 groups of 5 digits from SHA-256 is about 99.7 bits. Is that the right size for an ephemeral key pair, and why does Signal iterate its hash? | Open |

## 8. Decision log

Short entries, newest first. A decision gets an entry when choosing differently
would have changed the security argument.

```
### YYYY-MM-DD: <decision>
Context:   what forced the choice
Options:   what I considered
Decision:  what I picked
Why:       the argument, citing the spec where possible
Cost:      what this gives up
```

### 2026-11-27: Reframe Lethe as a research project
Context:   The goal moved from "a messenger for a friend" to "learn and publish".
Decision:  Writeups and understanding are the deliverable. Use vetted primitives;
           write the protocols by hand from the specs; no claim of production security.
Why:       Studying protocols means wiring them yourself. Implementing primitives
           would add risk without matching learning value.
Cost:      Feature work slows down, and the README stops promising a full app.

## 9. Writing workflow

For each component:

1. Read the primary spec and write a one-page summary in my own words, *before*
   looking at the code.
2. Read or rewrite the implementation against that summary, and fill in section 6.
3. Write a test for every claim in the writeup (each "this prevents X" gets a
   test that shows X failing without it).
4. Draft the post: spec → implementation → deviations → what I got wrong → open questions.
