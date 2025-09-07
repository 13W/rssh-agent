# rssh-agent v0.1.0 — TODO Checklist

> **Scope:** Linux (Ubuntu ≥ 22.04, Debian 12+), OpenSSH ≥ 8.
> **Lang/Targets:** Rust 2021 (MSRV 1.74), `x86_64/aarch64` (gnu + optional musl).
> **License:** Dual MIT/Apache-2.0.
> **Core tenets:** security-by-default, tests-first, small incremental steps, no orphaned code.

---

## 0) Preflight

- [ ] Confirm version set to **0.1.0** in all `Cargo.toml` and `--version` output.
- [ ] Create repo with Dual **MIT/Apache-2.0** license files.
- [ ] Enable `rustfmt`, `clippy` (CI will enforce `-D warnings`).
- [ ] Record distro matrix: Ubuntu 22.04/24.04, Debian 12.
- [ ] Decide CI provider; cache cargo registry & target artifacts.

---

## 1) Workspace & Scaffolding (M0)

- [ ] Create Cargo workspace layout:
  - [ ] `crates/rssh-core`
  - [ ] `crates/rssh-proto`
  - [ ] `crates/rssh-daemon`
  - [ ] `crates/rssh-cli` (bin: `rssh-agent`)
  - [ ] `crates/rssh-tui` (optional; feature `tui` **enabled by default**)
- [ ] `rssh-cli --version` prints `rssh-agent 0.1.0`.
- [ ] Add top-level `deny.toml` (or clippy settings) to enforce no warnings.
- [ ] CI (baseline): build, clippy `-D warnings`, unit-test.

**Tests**
- [ ] CLI integration test: `--version` exits 0 and prints exact semver.

---

## 2) Error Types & Exit Codes (M1)

- [ ] Implement shared `Error` enum in **rssh-core** with Display + `std::error::Error`.
- [ ] Map errors → exit codes in **rssh-cli** exactly per spec (`2` bad args, `3` no socket, `4` already running/in use, … `11` resource).
- [ ] Provide helper: `fn exit_code_for(err: &Error) -> i32`.

**Tests**
- [ ] Snapshot test for error → exit code mapping.
- [ ] Readable Display messages (no secrets).

---

## 3) Filesystem Policy & Atomic I/O (M2 partial)

- [ ] `ensure_dir_secure(path)` → create 0700 (owner-only); error on wrong owner/mode.
- [ ] `ensure_file_mode_0600(fd)` after open.
- [ ] `atomic_write(path, bytes)` → `.tmp.<pid>.<rand>` → `fsync(file)` → `rename()` → `fsync(dir)`.
- [ ] Reject symlinks/hardlinks (use `lstat`, `O_NOFOLLOW`).

**Tests**
- [ ] Tempdir happy path; mode check 0700.
- [ ] Atomicity withstands simulated crash (old file intact).
- [ ] Symlink path rejected.

---

## 4) Config & `init --dir` (M2)

- [ ] JSON model `rssh-config/v1` with **sentinel** AEAD("ok").
- [ ] Path expansion: `~` + env → **canonical absolute path** (realpath).
- [ ] Strict init policy:
  - [ ] Create dir if missing (0700, owner check).
  - [ ] Error if dir contains `config.json` or `sha256-*.json` (no repair/wipe in v0.1.0).
- [ ] Master password prompt rules:
  - [ ] UTF-8, len **8..1024**, not empty/whitespace-only.
  - [ ] Input via **TTY** or **ASKPASS** only (see §9).
- [ ] Write `config.json` atomically with mode 0600.

**Tests**
- [ ] `verify_sentinel(master_pw)` true/false.
- [ ] Bad perms (0755) rejected.
- [ ] Existing content triggers `already_initialized`.

---

## 5) Keyfile Format & Fingerprint (M3)

- [ ] Define `rssh-keyfile/v1` envelope (Argon2id + XChaCha20-Poly1305).
- [ ] Payload fields: `type`, `description`, `secret_openssh_b64`, optional `cert_openssh_b64`, `created`, `updated`.
- [ ] Filename: `sha256-<hex>.json` (lowercase, no separators).
- [ ] Recompute fingerprint from **public** part; on mismatch → **error** `fingerprint_mismatch` (no rename).
- [ ] Description validation: UTF-8, 1..256, no NUL/CR/LF.

**Tests**
- [ ] Roundtrip write/read with injected RNG.
- [ ] Mismatch filename detection.

---

## 6) OpenSSH private keys (`openssh-key-v1`) (M3)

- [ ] Parse/serialize Ed25519 and RSA using `ssh-key` crate.
- [ ] Internal passphrase policy:
  - [ ] bcrypt kdf; salt 16B; rounds default **16**, allowed **14–22**.
  - [ ] **Empty** passphrase **forbidden** (either set or none).
- [ ] RSA policy: min 2048 (warn if 2048), max 8192.

**Tests**
- [ ] Roundtrip Ed25519 + passphrase.
- [ ] RSA 2048/3072 ok; <2048 → `rsa_too_small`; >8192 → `rsa_too_large`.

---

## 7) RAM Store & Master Lock (M4)

- [ ] MemKey derivation: Argon2id with domain `"rssh-agent:v1:mem"`; per-daemon random mem-salt (RAM only).
- [ ] Store loaded keys **as AEAD ciphertexts**; decrypt ephemerally to sign/manage; **zeroize** buffers.
- [ ] Capacity limit: **1024** loaded keys.
- [ ] Anti-bruteforce for unlock: 3 tries (1s→2s→4s) then global **60s** cooldown.

**API**
- [ ] `RamStore::new()`, `is_locked()`, `lock()`, `unlock(master)`.
- [ ] `load_from_disk(fp, payload, key_pass?)`, `unload(fp)`, `list()` (internal snapshot for TUI).

**Tests**
- [ ] Locked denies operations; unlock flips state.
- [ ] Limit 1024 enforced.
- [ ] Cooldown timer via fake Clock.

---

## 8) SSH-Agent Framing, Socket, ACL, Skeleton (M5)

- [ ] Length-prefixed codec (u32 BE) with **1 MiB** limit.
- [ ] Unix socket layout: `/tmp/ssh-<random>/agent.<pid>` (dir 0700; sock 0600); `--socket <PATH>` exact path (parent must exist).
- [ ] ACL: `SO_PEERCRED` → accept **same UID only** (root no special rights).
- [ ] Locked default: all except `UNLOCK` return **FAILURE**.
- [ ] `REQUEST_IDENTITIES` returns empty when unlocked & no keys.

**CLI**
- [ ] `daemon` prints **only** `SSH_AUTH_SOCK` snippet; autodetect `-s|-c|-f` from `$SHELL`.
- [ ] `daemon` forks by default; `--foreground` stays attached.
- [ ] If env `SSH_AUTH_SOCK` is **alive** → error `already_running`.

**Tests**
- [ ] Codec rejects >1 MiB.
- [ ] Connect as same UID ok; different UID rejected (where testable).
- [ ] Unlock flow success path.

---

## 9) Prompting (Master & Confirm) (shared)

- [ ] Implement **Prompter** decision logic:
  - [ ] ASKPASS considered **only** `$SSH_ASKPASS`.
  - [ ] Use ASKPASS if: (no TTY & `DISPLAY`) OR (`SSH_ASKPASS_REQUIRE=force`) OR (`SSH_ASKPASS_REQUIRE=prefer`).
  - [ ] `SSH_ASKPASS_REQUIRE=never` disables ASKPASS.
  - [ ] Spawn program with one prompt arg; read stdout; trim trailing `\n`; empty/rc!=0 => cancel.
- [ ] TTY hidden prompt via `rpassword`.

**Tests**
- [ ] Matrix of env/TTY permutations → correct prompter selection.

---

## 10) Add/Remove/List Identities (M6)

- [ ] `ADD_IDENTITY (17)` for Ed25519/RSA; reject duplicates → **FAILURE `already_loaded`**.
- [ ] `ADD_ID_CONSTRAINED (25)`:
  - [ ] only `confirm` and `lifetime` (0 = none; **max 30 days**); unknown constraints → **FAILURE**.
  - [ ] Constraints live **in RAM** (survive lock/unlock; cleared on restart).
- [ ] `REQUEST_IDENTITIES`:
  - [ ] insertion order,
  - [ ] `comment` = current description (mutated live).
- [ ] `REMOVE_IDENTITY`: exact key match; not found → **FAILURE**.
- [ ] `REMOVE_ALL_IDENTITIES`: remove all from RAM; clear lifetimes + confirm cache.

**Tests**
- [ ] Add two keys → list order preserved.
- [ ] Constraints respected; expiration timers with fake clock.
- [ ] Remove one & remove all.

---

## 11) Signing & Algorithm Policy (M7)

- [ ] Ed25519 → `ssh-ed25519`.
- [ ] RSA: support `rsa-sha2-256` + `rsa-sha2-512`.
  - [ ] **Default** when none/both flags → **512**.
  - [ ] Deny `ssh-rsa` (SHA-1) → **FAILURE**.
- [ ] While locked → **FAILURE**.

**Tests**
- [ ] Positive ed25519; RSA flag combos.
- [ ] Negative legacy SHA-1.

---

## 12) Confirm-on-sign UX & Cache (M7)

- [ ] Prompt content: fp (SHA256), type, description, cert present, client uid/pid/exe, **Forwarded: unknown**.
- [ ] Actions: **Allow once**, **Allow 15 min**, **Deny**. Timeout **30s** => Deny.
- [ ] Cache key: `(fp + peer_uid + pid + process_start_time + exe_path)`, TTL 15 min; **clear on lock** and process exit.
- [ ] If neither TTY nor ASKPASS available → **immediate FAILURE**.

**Tests**
- [ ] Cache per-process works; different pid prompts again.
- [ ] Lock clears cache.
- [ ] No TTY & no ASKPASS → immediate failure.

---

## 13) Stop, Signals, Hardening (M8)

- [ ] `stop` sends `control.shutdown`; daemon:
  - [ ] stop accepting new requests,
  - [ ] wait up to **5s** for in-flight ops,
  - [ ] cancel remaining, zeroize, exit.
- [ ] Signals: `INT/TERM` graceful; `HUP` → **lock**; ignore `PIPE/CHLD`.
- [ ] Hardening on start:
  - [ ] `mlockall(MCL_CURRENT|MCL_FUTURE)` **required**,
  - [ ] `PR_SET_DUMPABLE=0`, `RLIMIT_CORE=0`, `PR_SET_NO_NEW_PRIVS=1`,
  - [ ] `MADV_DONTDUMP` on sensitive buffers,
  - [ ] fail to start if `mlockall` not possible.

**Tests**
- [ ] In-flight op with `stop` waits then exits.
- [ ] Hardening errors cause startup failure.

---

## 14) Extensions: CBOR Envelope + `manage.list` (M9)

- [ ] Namespace `rssh-agent@local`.
- [ ] Always protocol success with CBOR `{ok:true,...}` or `{ok:false,error{code,msg}}`.
- [ ] Malformed CBOR/oversize → protocol **FAILURE**.
- [ ] `manage.list` returns full metadata; **8 MiB** response cap (others 1 MiB).

**Tests**
- [ ] Locked → `need_master_unlock`; unlocked → list shows fields.
- [ ] Oversize guard.

---

## 15) Extensions: load/unload/import/desc/change_pass/update_cert/create (M9)

- [ ] `manage.load` (requires unlock; optional key pass) → RAM load.
- [ ] `manage.unload` → RAM only.
- [ ] `manage.import` → create file (auto-save current RAM cert).
- [ ] `manage.set_desc` → validate + update disk & RAM immediately.
- [ ] `manage.change_pass` → old→new (deny if wrong old).
- [ ] `manage.update_cert` → validate matches pubkey; store in disk + RAM.
- [ ] `manage.create` → ed25519|rsa; default bits 3072; bcrypt rounds default 16; prompt later in TUI for constraints; load to RAM if unlocked.

**Tests**
- [ ] Each op happy path + error paths (`already_exists`, `not_external`, `bad_key_password`, `no_disk_entry`, `bad_cert_format/mismatch`).

---

## 16) TUI — List & Navigation (M10)

- [ ] Table layout exactly:
```

> TYPE  FINGERPRINT              SRC   DISK  CERT  CONSTR  TTL   DESCRIPTION

```
- [ ] Icons: `☑`/`☐`/`–`; `✓` for cert; `c` for confirm; `∞` for no lifetime.
- [ ] Navigation: arrows/`j`/`k`, `Enter` menu; hotkeys `l/u/i/d/p/c`; `/` search; `s` sort; `r` refresh; `q` quit.
- [ ] Entering **manage** always prompts master password (even if unlocked) and performs unlock; exit leaves agent **unlocked**.

**Tests**
- [ ] Headless snapshot render of table (mock extension server).

---

## 17) TUI — Actions & Constraints Dialog (M10)

- [ ] Implement actions: load/unload/import/change description/change password/update cert/delete from disk (best-effort secure delete).
- [ ] After `load`/`create`, show dialog: set **confirm** & **lifetime (secs)** (RAM-only constraints).
- [ ] Reflect TTL countdown & `c` flag.

**Tests**
- [ ] Drive through mocked extensions and verify state updates.

---

## 18) Logging & Exit Codes (M11)

- [ ] Logging:
- [ ] human key=value (stderr), `--json`, optional `--journald`.
- [ ] Foreground default **info**; background (journald) default **warn**.
- [ ] Never log secrets/payloads.
- [ ] Exit codes mapped everywhere in CLI paths.

**Tests**
- [ ] Verify flag switches; snapshot a few log lines.

---

## 19) Certificates (M12)

- [ ] Parse cert, validate matches pubkey; extract principals & `valid_after/before`.
- [ ] `REQUEST_IDENTITIES` includes cert (even expired/not-yet-valid).
- [ ] Prompt marks “Expired”/“Not yet valid”.

**Tests**
- [ ] Expired cert still included; mismatch rejected.

---

## 20) Runtime Limits, Concurrency & Timers (M13)

- [ ] Message size caps (1 MiB default; 8 MiB manage.list).
- [ ] Max **64** concurrent clients; backlog **128**.
- [ ] IO timeouts: read **10s**, write **10s**, idle **60s**.
- [ ] Per-key signing concurrency: **1** at a time (queue).
- [ ] Lifetimes tick in real time across lock; on expiry auto-unload; **lock clears confirm cache**.

**Tests**
- [ ] Two concurrent signs on one key: serialize.
- [ ] Lifetime expiry across lock; cache cleared on lock.

---

## 21) CLI Polish (M14/M8 finish)

- [ ] `daemon`:
- [ ] prints only `SSH_AUTH_SOCK` (no `SSH_AGENT_PID` touch),
- [ ] autodetect shell style from `$SHELL`,
- [ ] if `SSH_AUTH_SOCK` live → `already_running` (exit 4),
- [ ] `--socket <PATH>` semantics: alive → `already_in_use` (exit 4); dead → unlink and bind.
- [ ] `unlock [--pass-fd N]` (single attempt on fd; anti-brute rules).
- [ ] `lock`, `stop [--socket PATH]` → extension `control.shutdown`.

**Tests**
- [ ] Style snippets for `-s/-c/-f` verified.
- [ ] Live-socket collision behavior.

---

## 22) Completions & Man (M14)

- [ ] `rssh-agent completion <bash|zsh|fish>` prints scripts to stdout.
- [ ] `rssh-agent man` outputs `rssh-agent(1)` in roff.

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

- [ ] **ECDSA/DSA/FIDO/PKCS#11**: not supported in v0.1.0.
- [ ] **Certificate forwarding detection**: label as `Forwarded: unknown`.
- [ ] **Storage concurrency**: last-writer-wins; no lock files.
- [ ] **No persistent constraints**: RAM-only.
- [ ] **No master-pass change** command (requires wipe/re-init to change).

---

## 27) Nice-to-haves (post-0.1.0 backlog)

- [ ] Property tests + fuzzing (`cargo-fuzz`) for codec/CBOR/keyfile.
- [ ] Read-only storage mode & conflict resolution (optimistic rev).
- [ ] Systemd socket activation.
- [ ] ECDSA/FIDO key support.
- [ ] PKCS#11 integration.

---
