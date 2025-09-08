# rssh-agent v0.1.0 — TODO Checklist

> **Scope:** Linux (Ubuntu ≥ 22.04, Debian 12+), OpenSSH ≥ 8.
> **Lang/Targets:** Rust 2021 (MSRV 1.74), `x86_64/aarch64` (gnu + optional musl).
> **License:** Dual MIT/Apache-2.0.
> **Core tenets:** security-by-default, tests-first, small incremental steps, no orphaned code.

---

## 0) Preflight

- [x] Confirm version set to **0.1.0** in all `Cargo.toml` and `--version` output.
- [ ] Create repo with Dual **MIT/Apache-2.0** license files.
- [x] Enable `rustfmt`, `clippy` (CI will enforce `-D warnings`).
- [ ] Record distro matrix: Ubuntu 22.04/24.04, Debian 12.
- [ ] Decide CI provider; cache cargo registry & target artifacts.

---

## 1) Workspace & Scaffolding (M0)

- [x] Create Cargo workspace layout:
  - [x] `crates/rssh-core`
  - [x] `crates/rssh-proto`
  - [x] `crates/rssh-daemon`
  - [x] `crates/rssh-cli` (bin: `rssh-agent`)
  - [x] `crates/rssh-tui` (optional; feature `tui` **enabled by default**)
- [x] `rssh-cli --version` prints `rssh-agent 0.1.0`.
- [ ] Add top-level `deny.toml` (or clippy settings) to enforce no warnings.
- [ ] CI (baseline): build, clippy `-D warnings`, unit-test.

**Tests**
- [x] CLI integration test: `--version` exits 0 and prints exact semver.

---

## 2) Error Types & Exit Codes (M1)

- [x] Implement shared `Error` enum in **rssh-core** with Display + `std::error::Error`.
- [x] Map errors → exit codes in **rssh-cli** exactly per spec (`2` bad args, `3` no socket, `4` already running/in use, … `11` resource).
- [x] Provide helper: `fn exit_code_for(err: &Error) -> i32`.

**Tests**
- [x] Snapshot test for error → exit code mapping.
- [x] Readable Display messages (no secrets).

---

## 3) Filesystem Policy & Atomic I/O (M2 partial)

- [x] `ensure_dir_secure(path)` → create 0700 (owner-only); error on wrong owner/mode.
- [x] `ensure_file_mode_0600(fd)` after open.
- [x] `atomic_write(path, bytes)` → `.tmp.<pid>.<rand>` → `fsync(file)` → `rename()` → `fsync(dir)`.
- [x] Reject symlinks/hardlinks (use `lstat`, `O_NOFOLLOW`).

**Tests**
- [x] Tempdir happy path; mode check 0700.
- [x] Atomicity withstands simulated crash (old file intact).
- [x] Symlink path rejected.

---

## 4) Config & `init --dir` (M2)

- [x] JSON model `rssh-config/v1` with **sentinel** AEAD("ok").
- [x] Path expansion: `~` + env → **canonical absolute path** (realpath).
- [x] Strict init policy:
  - [x] Create dir if missing (0700, owner check).
  - [x] Error if dir contains `config.json` or `sha256-*.json` (no repair/wipe in v0.1.0).
- [x] Master password prompt rules:
  - [x] UTF-8, len **8..1024**, not empty/whitespace-only.
  - [x] Input via **TTY** or **ASKPASS** only (see §9).
- [x] Write `config.json` atomically with mode 0600.

**Tests**
- [x] `verify_sentinel(master_pw)` true/false.
- [x] Bad perms (0755) rejected.
- [x] Existing content triggers `already_initialized`.

---

## 5) Keyfile Format & Fingerprint (M3)

- [x] Define `rssh-keyfile/v1` envelope (Argon2id + XChaCha20-Poly1305).
- [x] Payload fields: `type`, `description`, `secret_openssh_b64`, optional `cert_openssh_b64`, `created`, `updated`.
- [x] Filename: `sha256-<hex>.json` (lowercase, no separators).
- [x] Recompute fingerprint from **public** part; on mismatch → **error** `fingerprint_mismatch` (no rename).
- [x] Description validation: UTF-8, 1..256, no NUL/CR/LF.

**Tests**
- [x] Roundtrip write/read with injected RNG.
- [ ] Mismatch filename detection.

---

## 6) OpenSSH private keys (`openssh-key-v1`) (M3)

- [x] Parse/serialize Ed25519 and RSA using `ssh-key` crate.
- [x] Internal passphrase policy:
  - [x] bcrypt kdf; salt 16B; rounds default **16**, allowed **14–22**.
  - [x] **Empty** passphrase **forbidden** (either set or none).
- [x] RSA policy: min 2048 (warn if 2048), max 8192.

**Tests**
- [x] Roundtrip Ed25519 + passphrase.
- [x] RSA 2048/3072 ok; <2048 → `rsa_too_small`; >8192 → `rsa_too_large`.

---

## 7) RAM Store & Master Lock (M4)

- [x] MemKey derivation: Argon2id with domain `"rssh-agent:v1:mem"`; per-daemon random mem-salt (RAM only).
- [x] Store loaded keys **as AEAD ciphertexts**; decrypt ephemerally to sign/manage; **zeroize** buffers.
- [x] Capacity limit: **1024** loaded keys.
- [ ] Anti-bruteforce for unlock: 3 tries (1s→2s→4s) then global **60s** cooldown.

**API**
- [x] `RamStore::new()`, `is_locked()`, `lock()`, `unlock(master)`.
- [x] `load_from_disk(fp, payload, key_pass?)`, `unload(fp)`, `list()` (internal snapshot for TUI).

**Tests**
- [x] Locked denies operations; unlock flips state.
- [x] Limit 1024 enforced.
- [ ] Cooldown timer via fake Clock.

---

## 8) SSH-Agent Framing, Socket, ACL, Skeleton (M5)

- [x] Length-prefixed codec (u32 BE) with **1 MiB** limit.
- [x] Unix socket layout: `/tmp/ssh-<random>/agent.<pid>` (dir 0700; sock 0600); `--socket <PATH>` exact path (parent must exist).
- [x] ACL: `SO_PEERCRED` → accept **same UID only** (root no special rights).
- [x] Locked default: all except `UNLOCK` return **FAILURE**.
- [x] `REQUEST_IDENTITIES` returns empty when unlocked & no keys.

**CLI**
- [x] `daemon` prints **only** `SSH_AUTH_SOCK` snippet; autodetect `-s|-c|-f` from `$SHELL`.
- [x] `daemon` forks by default; `--foreground` stays attached.
- [x] If env `SSH_AUTH_SOCK` is **alive** → error `already_running`.

**Tests**
- [x] Codec rejects >1 MiB.
- [x] Connect as same UID ok; different UID rejected (where testable).
- [x] Unlock flow success path.

---

## 9) Prompting (Master & Confirm) (shared)

- [x] Implement **Prompter** decision logic:
  - [x] ASKPASS considered **only** `$SSH_ASKPASS`.
  - [x] Use ASKPASS if: (no TTY & `DISPLAY`) OR (`SSH_ASKPASS_REQUIRE=force`) OR (`SSH_ASKPASS_REQUIRE=prefer`).
  - [x] `SSH_ASKPASS_REQUIRE=never` disables ASKPASS.
  - [x] Spawn program with one prompt arg; read stdout; trim trailing `\n`; empty/rc!=0 => cancel.
- [x] TTY hidden prompt via `rpassword`.

**Tests**
- [x] Matrix of env/TTY permutations → correct prompter selection.

---

## 10) Add/Remove/List Identities (M6)

- [x] `ADD_IDENTITY (17)` for Ed25519/RSA; reject duplicates → **FAILURE `already_loaded`**.
- [x] `ADD_ID_CONSTRAINED (25)`:
  - [x] only `confirm` and `lifetime` (0 = none; **max 30 days**); unknown constraints → **FAILURE**.
  - [x] Constraints live **in RAM** (survive lock/unlock; cleared on restart).
- [x] `REQUEST_IDENTITIES`:
  - [x] insertion order,
  - [x] `comment` = current description (mutated live).
- [x] `REMOVE_IDENTITY`: exact key match; not found → **FAILURE**.
- [x] `REMOVE_ALL_IDENTITIES`: remove all from RAM; clear lifetimes + confirm cache.

**Tests**
- [ ] Add two keys → list order preserved.
- [ ] Constraints respected; expiration timers with fake clock.
- [x] Remove one & remove all.

---

## 11) Signing & Algorithm Policy (M7)

- [x] Ed25519 → `ssh-ed25519`.
- [x] RSA: support `rsa-sha2-256` + `rsa-sha2-512`.
  - [x] **Default** when none/both flags → **512**.
  - [x] Deny `ssh-rsa` (SHA-1) → **FAILURE**.
- [x] While locked → **FAILURE**.

**Tests**
- [ ] Positive ed25519; RSA flag combos.
- [ ] Negative legacy SHA-1.

---

## 12) Confirm-on-sign UX & Cache (M7)

- [x] Prompt content: fp (SHA256), type, description, cert present, client uid/pid/exe, **Forwarded: unknown**.
- [x] Actions: **Allow once**, **Allow 15 min**, **Deny**. Timeout **30s** => Deny.
- [x] Cache key: `(fp + peer_uid + pid + process_start_time + exe_path)`, TTL 15 min; **clear on lock** and process exit.
- [x] If neither TTY nor ASKPASS available → **immediate FAILURE**.

**Tests**
- [ ] Cache per-process works; different pid prompts again.
- [ ] Lock clears cache.
- [ ] No TTY & no ASKPASS → immediate failure.

---

## 13) Stop, Signals, Hardening (M8)

- [x] `stop` sends `control.shutdown`; daemon:
  - [x] stop accepting new requests,
  - [x] wait up to **5s** for in-flight ops,
  - [x] cancel remaining, zeroize, exit.
- [x] Signals: `INT/TERM` graceful; `HUP` → **lock**; ignore `PIPE/CHLD`.
- [x] Hardening on start:
  - [x] `mlockall(MCL_CURRENT|MCL_FUTURE)` **required**,
  - [x] `PR_SET_DUMPABLE=0`, `RLIMIT_CORE=0`, `PR_SET_NO_NEW_PRIVS=1`,
  - [x] `MADV_DONTDUMP` on sensitive buffers,
  - [x] fail to start if `mlockall` not possible.

**Tests**
- [ ] In-flight op with `stop` waits then exits.
- [ ] Hardening errors cause startup failure.

---

## 14) Extensions: CBOR Envelope + `manage.list` (M9)

- [x] Namespace `rssh-agent@local`.
- [x] Always protocol success with CBOR `{ok:true,...}` or `{ok:false,error{code,msg}}`.
- [x] Malformed CBOR/oversize → protocol **FAILURE**.
- [x] `manage.list` returns full metadata; **8 MiB** response cap (others 1 MiB).

**Tests**
- [ ] Locked → `need_master_unlock`; unlocked → list shows fields.
- [ ] Oversize guard.

---

## 15) Extensions: load/unload/import/desc/change_pass/update_cert/create (M9)

- [x] `manage.load` (requires unlock; optional key pass) → RAM load.
- [x] `manage.unload` → RAM only.
- [x] `manage.import` → create file (auto-save current RAM cert).
- [x] `manage.set_desc` → validate + update disk & RAM immediately.
- [x] `manage.change_pass` → old→new (deny if wrong old).
- [x] `manage.update_cert` → validate matches pubkey; store in disk + RAM.
- [x] `manage.create` → ed25519|rsa; default bits 3072; bcrypt rounds default 16; prompt later in TUI for constraints; load to RAM if unlocked.

**Tests**
- [ ] Each op happy path + error paths (`already_exists`, `not_external`, `bad_key_password`, `no_disk_entry`, `bad_cert_format/mismatch`).

---

## 16) TUI — List & Navigation (M10)

- [x] Table layout exactly:
```

> TYPE  FINGERPRINT              SRC   DISK  CERT  CONSTR  TTL   DESCRIPTION

```
- [x] Icons: `☑`/`☐`/`–`; `✓` for cert; `c` for confirm; `∞` for no lifetime.
- [x] Navigation: arrows/`j`/`k`, `Enter` menu; hotkeys `l/u/i/d/p/c`; `/` search; `s` sort; `r` refresh; `q` quit.
- [x] Entering **manage** always prompts master password (even if unlocked) and performs unlock; exit leaves agent **unlocked**.

**Tests**
- [ ] Headless snapshot render of table (mock extension server).

---

## 17) TUI — Actions & Constraints Dialog (M10)

- [x] Implement actions: load/unload/import/change description/change password/update cert/delete from disk (best-effort secure delete).
- [x] After `load`/`create`, show dialog: set **confirm** & **lifetime (secs)** (RAM-only constraints).
- [x] Reflect TTL countdown & `c` flag.

**Tests**
- [ ] Drive through mocked extensions and verify state updates.

---

## 18) Logging & Exit Codes (M11)

- [x] Logging:
- [x] human key=value (stderr), `--json`, optional `--journald`.
- [x] Foreground default **info**; background (journald) default **warn**.
- [x] Never log secrets/payloads.
- [x] Exit codes mapped everywhere in CLI paths.

**Tests**
- [ ] Verify flag switches; snapshot a few log lines.

---

## 19) Certificates (M12)

- [x] Parse cert, validate matches pubkey; extract principals & `valid_after/before`.
- [x] `REQUEST_IDENTITIES` includes cert (even expired/not-yet-valid).
- [x] Prompt marks "Expired"/"Not yet valid".

**Tests**
- [ ] Expired cert still included; mismatch rejected.

---

## 20) Runtime Limits, Concurrency & Timers (M13)

- [x] Message size caps (1 MiB default; 8 MiB manage.list).
- [x] Max **64** concurrent clients; backlog **128**.
- [x] IO timeouts: read **10s**, write **10s**, idle **60s**.
- [x] Per-key signing concurrency: **1** at a time (queue).
- [x] Lifetimes tick in real time across lock; on expiry auto-unload; **lock clears confirm cache**.

**Tests**
- [ ] Two concurrent signs on one key: serialize.
- [ ] Lifetime expiry across lock; cache cleared on lock.

---

## 21) CLI Polish (M14/M8 finish)

- [x] `daemon`:
- [x] prints only `SSH_AUTH_SOCK` (no `SSH_AGENT_PID` touch),
- [x] autodetect shell style from `$SHELL`,
- [x] if `SSH_AUTH_SOCK` live → `already_running` (exit 4),
- [x] `--socket <PATH>` semantics: alive → `already_in_use` (exit 4); dead → unlink and bind.
- [x] `unlock [--pass-fd N]` (single attempt on fd; anti-brute rules).
- [x] `lock`, `stop [--socket PATH]` → extension `control.shutdown`.

**Tests**
- [x] Style snippets for `-s/-c/-f` verified.
- [ ] Live-socket collision behavior.

---

## 22) Completions & Man (M14)

- [x] `rssh-agent completion <bash|zsh|fish>` prints scripts to stdout.
- [x] `rssh-agent man` outputs `rssh-agent(1)` in roff.

**Tests**
- [ ] Snapshot outputs for completion and man.

---

## 23) End-to-End & Manual QA (M15)

**Automated E2E (temp dirs/sockets):**
- [ ] `init` → `daemon --foreground` → `ssh-add` ed25519 → `ssh` sign with confirm; deny/allow paths.
- [ ] `lock` blocks all but unlock; `unlock` restores; lifetime expiry removes key.
- [ ] Duplicates rejected (`already_loaded`).

**Manual QA checklist:**
- [ ] `daemon` refuses to start if `mlockall` fails (simulate with limited memlock).
- [ ] ASKPASS flows: no TTY + DISPLAY; force/prefer/never envs.
- [ ] `manage` always prompts master (even if unlocked).
- [ ] Delete from disk warns about best-effort semantics.
- [ ] RSA default algorithm behavior (no flags → 512; both → 512).
- [ ] Constraints dialog in TUI; confirm cache per-process.

---

## 24) Docs & Packaging

- [ ] `README.md` with quick start:
- [ ] `init --dir`, `eval "$(rssh-agent daemon)"`, `ssh-add`, `lock/unlock`, `manage`.
- [ ] Security section: hardening requirements (memlock), limits, unsupported features (ECDSA/FIDO/PKCS#11).
- [ ] Examples of `completion` and `man` install locations.
- [ ] Changelog `CHANGELOG.md` for 0.1.0.
- [ ] `CONTRIBUTING.md` with test-first guideline.

---

## 25) Release Readiness

- [ ] Ensure `--no-default-features` builds (no TUI).
- [ ] Build artifacts for glibc + (optionally) musl targets.
- [ ] Run E2E on Ubuntu 22.04/24.04 & Debian 12 VMs/containers.
- [ ] Tag `v0.1.0`; attach artifacts; publish.

---

## 26) Guardrails / Non-Goals (assertions to keep)

- [x] **ECDSA/DSA/FIDO/PKCS#11**: not supported in v0.1.0.
- [x] **Certificate forwarding detection**: label as `Forwarded: unknown`.
- [x] **Storage concurrency**: last-writer-wins; no lock files.
- [x] **No persistent constraints**: RAM-only.
- [x] **No master-pass change** command (requires wipe/re-init to change).

---

## 27) Nice-to-haves (post-0.1.0 backlog)

- [ ] Property tests + fuzzing (`cargo-fuzz`) for codec/CBOR/keyfile.
- [ ] Read-only storage mode & conflict resolution (optimistic rev).
- [ ] Systemd socket activation.
- [ ] ECDSA/FIDO key support.
- [ ] PKCS#11 integration.

---