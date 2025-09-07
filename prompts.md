# High-Level Blueprint

## Architecture (workspace you approved)

```
crates/
  rssh-core    # crypto, storage, RAM manager, constraints, error types, time/OS abstractions
  rssh-proto   # SSH agent wire (OpenSSH) + CBOR extensions namespace `rssh-agent@local`
  rssh-daemon  # server lifecycle, socket/ACL, signals, limits, per-key concurrency, prompts
  rssh-cli     # single binary `rssh-agent` (init/daemon/lock/unlock/stop/manage; completion/man)
  rssh-tui     # manage TUI (feature `tui`, default on)
```

## Core principles

* **Security by default:** strict memory hardening, zeroize, strict perms, failure on weak configs.
* **Small surfaces + seams:** thin traits for filesystem, time, RNG, process-introspection → deterministic tests.
* **RAM-at-rest:** keys in RAM are AEAD-encrypted under a MemKey; `lock` zeroizes MemKey; `unlock` restores.
* **Strict compatibility:** OpenSSH ≥8 messages; reject `ssh-rsa` (SHA-1); constraints `-c/-t`; correct failure modes.
* **Ops UX:** `daemon` prints only `SSH_AUTH_SOCK`; `manage` always re-prompts master password and unlocks.
* **Storage:** `$HOME/.ssh/rssh-agent/`, `config.json` sentinel AEAD("ok"), key files `sha256-<hex>.json` (payload openssh-key-v1 + optional cert).
* **Limits:** 1 MiB messages (8 MiB for `manage.list`), 64 clients, 1024 loaded keys, per-key signing serialization.

## Key risks (mitigations)

* **OS calls:** wrap `mlockall`, `prctl`, signals in small modules with feature-gated mocks.
* **Atomics & races:** always use tmp→fsync(file)→rename→fsync(dir); last-writer-wins accepted by spec.
* **Prompting:** ASKPASS vs TTY matrix—centralize in a `Prompter` with unit/integration tests.

---

# Roadmap by Milestones (coarse → fine)

## M0 — Bootstrap & Scaffolding

* Cargo workspace, crates, features, clippy config, baseline tests, `--version`, CI (baseline).

## M1 — Common domain & errors

* Shared error enum, `Result<T>`, exit code mapping, logging init.

## M2 — Config & `init`

* Sentinel AEAD("ok") format, `config.json` IO, path canonicalization, strict perms, `init --dir` behavior + master password policy.

## M3 — Keyfile format & atomic IO

* Read/write `rssh-keyfile/v1`, bcrypt-KDF for openssh-key-v1, RSA/Ed25519 parsing, fingerprint SHA-256 naming check.

## M4 — RAM manager & master lock

* MemKey derivation (Argon2id), RAM ciphertext envelopes, `lock/unlock` semantics, anti-bruteforce, limits on loaded keys.

## M5 — Wire framing & daemon skeleton

* Length-prefixed SSH agent framing over Unix socket, ACL (`SO_PEERCRED` same UID), empty `REQUEST_IDENTITIES`, locked behavior.

## M6 — Add/remove/list identities (OpenSSH)

* Implement `ADD_IDENTITY`/`ADD_ID_CONSTRAINED` (confirm/lifetime only), `REMOVE_*`, persistence of constraints in RAM only.

## M7 — Signing & policies

* `SIGN_REQUEST`: ed25519, rsa-sha2-256/512 defaults; deny SHA-1; confirm prompts w/ ASKPASS/TTY and 15-min per-process cache.

## M8 — Daemon lifecycle & CLI

* `daemon` env printing (-s/-c/-f autodetect), socket policy (`/tmp/ssh-XXX/agent.<pid>` or `--socket`), `stop` control.shutdown, signals, hardening gates.

## M9 — Extensions (CBOR) & `manage` ops

* `manage.list` (8 MiB cap), `load/unload/import/set_desc/change_pass/update_cert/create` with errors as `{ok:false,...}`.

## M10 — TUI (feature `tui`)

* Table UI, actions wiring via extensions, constraints dialog on load/create, delete from disk (best-effort secure delete).

## M11 — Logging & exit codes

* Human key=value vs JSON; foreground info / background warn; exit codes you picked.

## M12 — Certificates

* Validate cert matches pubkey, parse validity/principals, expose in list & prompts; always return cert in identities.

## M13 — Resource limits & timeouts

* 1 MiB/8 MiB, client caps, IO timeouts, per-key signing queue, timers with real-time behavior across lock/unlock.

## M14 — Completions & man

* `rssh-agent completion …` and `man` generation from clap.

## M15 — End-to-end tests & polish

* Tempdir runs of init→daemon→ssh-add flows; lock/unlock; confirm prompt fallbacks.

---

# Chunking Each Milestone into Implementable Steps (first pass)

I keep steps thin, testable, and integrated:

* **M0.1** Workspace skeleton + `rssh-cli --version`; CI script (build, clippy, unit).
* **M1.1** `rssh-core::error` + `ExitCode` mapping in CLI.
* **M2.1** `PathPolicy` + perms check helpers.
* **M2.2** Sentinel struct + AEAD(“ok”).
* **M2.3** `init --dir`: prompt API (TTY/ASKPASS), config write atomically.
* **M3.1** Key types & fingerprint calc; filename policy.
* **M3.2** Read/write keyfile envelope atomically.
* **M3.3** openssh-key-v1 encode/decode with bcrypt rounds policy.
* **M4.1** MemKey derivation (`argon2id`) + zeroize.
* **M4.2** RAM store for loaded keys (ciphertexts), per-key caps, anti-brute.
* **M4.3** `lock/unlock` commands in CLI (no daemon yet; local mock).
* **M5.1** Framing codec + Unix listener, ACL (same UID).
* **M5.2** Daemon main loop skeleton; locked default; `REQUEST_IDENTITIES` empty.
* **M5.3** `daemon` CLI emits env snippet; socket policy & `/tmp` layout.
* **M6.1** Parse `ADD_IDENTITY` & constraints; RAM insertion.
* **M6.2** `REMOVE_IDENTITY` & `REMOVE_ALL_IDENTITIES`.
* **M6.3** `REQUEST_IDENTITIES` with insertion order + live description.
* **M7.1** ed25519 sign; RSA-sha2-256/512 selection & defaults, reject SHA-1.
* **M7.2** Confirm prompts (TTY/ASKPASS) + 15-min per-process cache; failure if prompt unavailable.
* **M8.1** `stop` → `control.shutdown` graceful 5s; signals (`HUP`→lock, INT/TERM graceful).
* **M8.2** Hardening gates (mlockall, prctl) with fail-fast.
* **M8.3** Socket collision behavior vs `SSH_AUTH_SOCK` live.
* **M9.1** CBOR extension plumbing + `{ok:..., error:...}` contract; `manage.list` (8 MiB cap).
* **M9.2** `load/unload/import/set_desc/change_pass/update_cert/create`.
* **M10.1** TUI table layout & navigation; list rendering.
* **M10.2** Wire all actions to extensions + constraints dialog.
* **M11.1** Logging levels/format flags; exit codes from errors.
* **M12.1** Cert validation & details.
* **M13.1** Limits: message sizes, clients, timeouts; per-key queue; lifetimes continue across lock.
* **M14.1** completions + man.
* **M15.1** E2E scripts for happy paths + lock/confirm/failures.

---

# Micro-Steps (second pass split)

Below I split a subset to the granularity of a half-day each, always test-first:

* **M0.1a** Cargo workspace + crates + feature `tui` (default), compile empty.

* **M0.1b** `--version` wired through `rssh-cli` + unit test prints semver from env.

* **M0.1c** CI YAML (build, clippy -D warnings, unit tests).

* **M2.2a** Define `Sentinel` structs + serialize/deserialize; unit roundtrip test with fixed test vector nonce/salt.

* **M2.3a** Prompt API: TTY (rpassword) & ASKPASS decision matrix; unit tests with env permutations.

* **M2.3b** Write `init --dir` happy path using tempdir; verify perms 0700/0600; failure paths (`already_initialized`, bad perms).

* **M3.1a** SHA-256 fingerprint from public key; unit tests against known ed25519/rsa vectors.

* **M3.2a** Atomic write helper (tmp→fsync→rename→fsyncdir); unit tests with fault injection (simulated fsync failure).

* **M3.3a** openssh-key-v1 encode/decode (bcrypt rounds policy 14–22, default 16); deny empty passphrase; unit tests.

* **M4.1a** Argon2id MemKey derivation + domain separation; test vectors.

* **M4.2a** RAM store (hashmap by fp) storing AEAD ciphertexts; limit 1024; unit tests add/overflow.

* **M4.2b** Anti-brute counters & global cooldown; tests with fake clock.

* **M4.3a** `lock/unlock` logic with zeroize hooks; unit tests ensure sign fails while locked.

* **M5.1a** Wire codec for SSH-agent framing; fuzz seed test; size cap 1 MiB.

* **M5.1b** Unix socket ACL same UID via `SO_PEERCRED`; integration test spawns child of different UID (skip on CI if not root).

* **M5.2a** Minimal daemon loop responding FAILURE when locked to all but UNLOCK.

* **M6.1a** Parse `ADD_IDENTITY` ed25519; store; `REQUEST_IDENTITIES` returns one.

* **M6.1b** RSA add with policy (min/max bits).

* **M6.1c** Constrained add; ignore unknown constraints → **FAILURE**; tests.

* **M6.2a** Remove exact; `REMOVE_ALL_IDENTITIES`.

* **M6.3a** Insertion order + live description field (mutations reflect).

* **M7.1a** ed25519 sign; negative tests.

* **M7.1b** RSA sha2 flags: default 512; both set → 512; missing/legacy → FAILURE.

* **M7.2a** Confirm prompt flow (TTY) + cache key; tests with fake prompter.

* **M7.2b** ASKPASS fallbacks & `SSH_ASKPASS_REQUIRE`; no TTY and no ASKPASS → immediate FAILURE.

* **M8.1a** `stop` → control.shutdown; graceful 5s with in-flight blocking test.

* **M8.2a** mlockall/prctl wrapper with failfast; unit tests with “deny” feature to simulate failure.

* **M8.3a** `/tmp/ssh-XXXX/agent.<pid>` layout; collision with live `SSH_AUTH_SOCK` → error.

* **M9.1a** CBOR extension envelope + error contract; size cap 8 MiB for list.

* **M9.2a** `manage.load` (needs unlock, optional key pass), `unload`.

* **M9.2b** `import` (auto-save cert), `set_desc` (validate UTF-8 1..256), `change_pass` (old→new), `update_cert`, `create`.

* **M10.1a** TUI table & navigation only (reads list).

* **M10.2a** Wire `load/unload/import`, confirm/lifetime dialog.

* **M10.2b** `change desc/pass`, `update cert`, `delete from disk`.

* **M11.1a** Logging levels/format switches + exit codes mapping tests.

* **M12.1a** Cert parse & match; validity labels in list & prompt.

* **M13.1a** Client/timeouts; per-key queue; lifetime timers across lock; tests with fake clock.

* **M14.1a** Completion & man outputs snapshot tests.

* **M15.1a** E2E: tempdir init→daemon→ssh-add→ssh sign with confirm.

---

# Test-First Prompts for a Code-Gen LLM

Each prompt is **self-contained**, references prior state, and asks for tests first. You can paste them one-by-one as you progress. (I keep \~22 prompts to balance granularity vs progress; feel free to split further.)

---

## Prompt 1 — Workspace bootstrap

```text
You are implementing the rssh-agent project per the linked spec (assume it’s known):

Goal of this prompt:
- Create a Cargo workspace with crates: rssh-core, rssh-proto, rssh-daemon, rssh-cli, rssh-tui.
- Feature `tui` is defined in `rssh-cli` and enabled by default; when disabled, the CLI still builds without TUI.
- rssh-cli provides a binary `rssh-agent` with `--version` printing semver `0.1.0`.

Do this TDD-style:
1) Write minimal tests:
   - In rssh-cli: a test that `--version` exits 0 and prints "rssh-agent 0.1.0".
   - In workspace: `cargo clippy` runs clean with `-D warnings` (CI config added later).
2) Implement workspace:
   - Set Rust 2021 edition, MSRV 1.74 in `rust-toolchain.toml` or CI notes.
   - Create crates with lib targets (empty stubs) except rssh-cli which has bin.
   - Feature `tui` defaults on and pulls `rssh-tui` as optional dependency; when `--no-default-features`, it compiles without it.
3) Make sure `cargo build` passes and tests pass.

Return:
- The new Cargo files, minimal code, and the tests.
```

---

## Prompt 2 — Common errors & exit codes

```text
Add a shared error type and exit-code mapping per the spec.

TDD:
1) In rssh-core, create `error.rs` with an `Error` enum covering: Io, Config, Crypto, Locked, NotInitialized, AlreadyRunning, AlreadyInUse, AccessDenied, Unsupported, Timeout, TooManyKeys, BadArgs, WrongPassword, NeedMasterUnlock, NotFound, AlreadyLoaded, NotLoaded, AlreadyExists, FingerprintMismatch, RsaTooSmall, RsaTooLarge.
2) Provide `impl std::error::Error + Display + From<std::io::Error>`.
3) In rssh-cli, add mapping `Error -> ExitCode` exactly:
   0 ok; 2 BadArgs; 3 no_socket; 4 AlreadyRunning/AlreadyInUse; 5 Locked/NeedMasterUnlock; 6 WrongPassword; 7 NotInitialized; 8 Unsupported; 9 Timeout/Io; 10 AccessDenied; 11 TooManyKeys; else 1.
4) Tests:
   - Unit tests for Display strings (non-leaky, human-readable).
   - Mapping table snapshot test: construct each variant and assert exit code.

Return code & tests only.
```

---

## Prompt 3 — Path & perms helpers; strict checks

```text
Implement in rssh-core a module `fs_policy`:

Requirements (with tests):
- `ensure_dir_secure(path)`: creates if missing; must be owned by current UID; mode 0700; error otherwise. Ignores umask by setting explicit perms.
- `ensure_file_mode_0600(fd)`: after open, enforce 0600.
- `atomic_write(path, data: &[u8])`: write to `.tmp.<pid>.<rand>`, fsync(file) → rename → fsync(dir).
- Tests using `tempfile`:
  - Creates directory and ensures 0700.
  - Atomic write preserves content across simulated crash between write and rename (simulate by skipping rename and verifying old file unchanged).
  - No symlinks: if `path` is symlink, return error.

Return module code + tests.
```

---

## Prompt 4 — Sentinel & config (`init` groundwork)

```text
Implement config per "rssh-config/v1" with a sentinel AEAD("ok").

Do TDD:
1) In rssh-core::config:
   - Define structs mirroring the JSON (version, sentinel{kdf{mib,t,p,salt_b64}, aead{nonce_b64}, ciphertext_b64}, settings{storage_dir,fingerprint_ui,allow_rsa_sha1=false}).
   - Implement `new_with_sentinel(storage_dir: &Path, rng, aead, kdf_params)` that produces a config containing AEAD("ok") with random salt/nonce.
   - Implement `verify_sentinel(master_password) -> bool` that attempts to decrypt and checks equals "ok".
2) JSON (de)serialization via serde + canonical ordering (just derive; tests compare fields).
3) Tests:
   - Roundtrip serialization equality (excluding random salt/nonce).
   - `verify_sentinel` true/false with known password.
   - Reject malformed/missing fields.

Return code & tests.
```

---

## Prompt 5 — Prompting API (TTY/ASKPASS policy)

```text
Create rssh-daemon (or rssh-core if you prefer) module `prompt` abstracting master password input per spec:

Behavior:
- Use TTY hidden prompt by default (`rpassword`).
- ASKPASS only with SSH_ASKPASS and rules: if no TTY and DISPLAY set; or SSH_ASKPASS_REQUIRE=force; or SSH_ASKPASS_REQUIRE=prefer (even with TTY). SSH_ASKPASS_REQUIRE=never disables ASKPASS.
- Program is invoked with a single prompt arg; read stdout; trim trailing newline; empty output or nonzero exit => cancel.

TDD:
- Introduce a trait `Prompter` with impls `TTYPrompter`, `AskpassPrompter`, and `Decision` logic reading env/tty presence (injectable).
- Tests simulate environment matrices and assert which prompter is chosen and returned values.
- No real TTY/spawn in tests; use mocks for subprocess.

Return the module and tests.
```

---

## Prompt 6 — `init --dir` command (strict policy)

```text
Implement `rssh-agent init [--dir <PATH>]` in rssh-cli using rssh-core config + fs_policy + prompt.

Rules to meet:
- Expand ~ and env vars; canonicalize to absolute realpath; create directory 0700 if missing, else strict check 0700 and same UID.
- If directory contains any config.json or sha256-*.json => error AlreadyInitialized.
- Prompt for master password (TTY/ASKPASS rules); enforce UTF-8, len 8..1024, non-empty/non-whitespace.
- Write config.json (0600) atomically with sentinel AEAD("ok").
- Exit 0 on success; map errors to exit codes per table.

Tests:
- Tempdir happy path, verify perms and JSON fields exist.
- Failure when random file exists named sha256-foo.json.
- Failure when directory has bad perms (chmod 0755).

Return CLI code, integration tests using assert_cmd, and minimal glue in rssh-cli main.
```

---

## Prompt 7 — Keyfile envelope & fingerprint policy

```text
Implement keyfile format rssh-keyfile/v1 and SHA-256 fingerprint policy.

In rssh-core:
- Define `KeyPayload { type: Ed25519|Rsa, description, secret_openssh_b64, cert_openssh_b64?, created, updated }`.
- Define `KeyFile { version, kdf{...}, aead{...}, ciphertext_b64 }` with (de)serialization.
- `write_keyfile(fp_hex, payload, master_password)` => writes `<storage>/sha256-<fp_hex>.json` atomically.
- `read_keyfile(fp_hex, master_password)` => reads and decrypts payload.
- `calc_fingerprint_hex(pubkey)` returns lowercase hex SHA-256 without separators.
- On load from disk, recompute from `secret_openssh_b64` public part; if mismatch filename => FingerprintMismatch.

Tests:
- Roundtrip write/read with deterministic RNG (inject rng).
- Mismatch case returns FingerprintMismatch.
- Description validation: UTF-8, no NUL/CR/LF, len 1..256.

Return code & tests.
```

---

## Prompt 8 — openssh-key-v1 encode/decode & bcrypt policy

```text
Implement conversion helpers using the `ssh-key` crate:
- Parse and serialize `openssh-key-v1` for Ed25519 and RSA.
- Internal passphrase policy: bcrypt kdfname; salt 16 bytes; rounds default 16; allowed 14–22; empty passphrase forbidden.

Tests:
- Known vector: generate Ed25519 key, set passphrase, serialize, parse roundtrip.
- RSA 2048/3072 ok; <2048 => RsaTooSmall; >8192 => RsaTooLarge (errors).

Return code & tests in rssh-core.
```

---

## Prompt 9 — MemKey & RAM store with lock/unlock

```text
Implement in rssh-core:
- MemKey derivation using Argon2id with domain separation ("rssh-agent:v1:mem") and random mem_salt generated at daemon start (in RAM only).
- RAM store storing AEAD-encrypted key materials by fingerprint; limit 1024; ephemeral decrypt for sign/manage then zeroize.
- Anti-bruteforce: per-unlock tries 3 with backoff 1s,2s,4s; after 3 consecutive failures, global 60s cooldown.

Expose:
- `RamStore::new()`, `load_from_disk(fp, payload_bytes, key_pass?)`, `unload(fp)`, `list()`, `is_locked()`, `lock()`, `unlock(master_password)`.

Tests:
- Locked state rejects list/sign/load; unlock success flips state.
- Load >1024 returns TooManyKeys.
- Anti-bruteforce: wrong passwords trigger cooldown measured via injectable Clock.

Return module & tests.
```

---

## Prompt 10 — SSH-agent framing, socket, ACL, empty behavior

```text
In rssh-proto and rssh-daemon:
- Implement SSH-agent length-prefixed codec (u32 big-endian) with 1 MiB cap.
- Implement UnixListener on `/tmp/ssh-XXXX/agent.<pid>` or `--socket` path.
- Enforce ACL: accept only SO_PEERCRED same UID; else drop connection.
- Implement minimal handlers:
  - Locked by default.
  - `SSH_AGENTC_UNLOCK` checks master password using RamStore (wire up prompt module).
  - All others return FAILURE while locked.
  - `REQUEST_IDENTITIES` returns empty list when unlocked & no keys.

CLI:
- `daemon` prints env snippet for -s|-c|-f (auto-detect from $SHELL) and background by default; add `--foreground`.

Tests:
- Integration: start daemon in temp `/tmp` namespace, connect, send bogus frame → failure; unlock with test master → ok; `REQUEST_IDENTITIES` empty.
- ACL test: mock peer creds if possible; otherwise unit-test the decision function.

Return code & tests.
```

---

## Prompt 11 — Add/remove/list identities (constraints)

```text
Implement OpenSSH messages:
- `ADD_IDENTITY (17)` for ed25519/rsa; reject duplicates (return FAILURE already_loaded).
- `ADD_ID_CONSTRAINED (25)` recognizing only confirm and lifetime (0 = none; max 30 days); unknown constraints => FAILURE.
- Persist constraints in RAM only; survive lock/unlock but not restart.
- `REQUEST_IDENTITIES`: insertion order, comment = current description (mutable later).
- `REMOVE_IDENTITY`, `REMOVE_ALL_IDENTITIES` semantics per spec.

Tests:
- Add two keys; list shows 2 in order.
- Constrained add sets confirm and lifetime (check expiration with fake Clock).
- Remove exact match; remove all clears.

Return code & tests.
```

---

## Prompt 12 — Signing & algorithms policy

```text
Implement `SSH_AGENTC_SIGN_REQUEST`:
- Ed25519 -> ssh-ed25519.
- RSA: support rsa-sha2-256 and rsa-sha2-512; default when no flags or both flags present => rsa-sha2-512; reject ssh-rsa (SHA-1).
- While locked, return FAILURE.

Tests:
- Positive sign for ed25519; RSA with flag combos (none, both, explicit 256/512).
- Negative: request ssh-rsa => FAILURE.

Return code & tests.
```

---

## Prompt 13 — Confirm prompt (TTY/ASKPASS) + 15-min cache

```text
Implement confirm-on-sign (`ssh-add -c`) in rssh-daemon:
- Prompt shows: fingerprint SHA256, type, description, cert presence; client info (uid,pid,exe/comm); "Forwarded: unknown".
- Actions: Allow once; Allow 15 min; Deny; timeout 30s => Deny.
- Cache key: (fp + peer_uid + pid + process_start_time + exe_path), TTL 15 min; cleared on lock and process exit.

Tests (with fake prompter and fake procinfo):
- When confirm required, cache absent: prompt appears and selection affects subsequent sign.
- If no TTY and no ASKPASS: immediate FAILURE (no wait).
- Cache applies only to same pid/exe; different pid prompts again.

Return code & tests.
```

---

## Prompt 14 — `stop`, signals, hardening

```text
Implement:
- `stop` CLI sending `control.shutdown` extension; daemon gracefully finishes in-flight ops with 5s timeout.
- Signal handling: INT/TERM => graceful; HUP => lock; ignore PIPE/CHLD.
- Hardening at start: mlockall, PR_SET_DUMPABLE=0, RLIMIT_CORE=0, PR_SET_NO_NEW_PRIVS=1; MADV_DONTDUMP on sensitive buffers. Fail to start if mlockall fails.

Tests:
- Simulate in-flight sign (sleeping op) and verify stop waits then exits.
- Unit tests for hardening wrappers (inject failure -> startup error).

Return code & tests.
```

---

## Prompt 15 — Extensions: CBOR envelope + `manage.list`

```text
Implement `SSH2_AGENTC_EXTENSION` for namespace `rssh-agent@local`:
- Always return protocol success with CBOR body `{ok:true,...}` or `{ok:false,error{code,msg}}`.
- Reject malformed CBOR or oversize (over 8 MiB for list; 1 MiB otherwise) with protocol FAILURE.
- Implement `manage.list` returning the structure defined in the spec; supports up to 8 MiB response.

Tests:
- Send list when locked => need_master_unlock error; after unlock => ok with keys (fields populated).
- Oversize guard: attempt to inject >8 MiB response; ensure safe error.

Return code & tests.
```

---

## Prompt 16 — Extensions: load/unload/import/set\_desc/change\_pass/update\_cert/create

```text
Implement remaining manage.* ops per spec (errors exactly as named):
- load (optionally key pass), unload, import (auto-save current RAM cert if present), set_desc (validates 1..256, no NUL/CR/LF), change_pass (old->new), update_cert (match pubkey), create (ed25519|rsa, rounds policy; default bits 3072; on success, if unlocked, also load into RAM).
- Ensure mux with RAM store and disk IO is atomic and respects last-writer-wins.
- Reject in locked state with need_master_unlock across all ops.

Tests (use temp storage):
- Happy paths for each operation; description visible immediately in REQUEST_IDENTITIES.
- change_pass requires correct old pass if set; update_cert rejects mismatched key.
- import on external RAM key creates file; if file exists => already_exists.

Return code & tests.
```

---

## Prompt 17 — TUI (feature `tui`), list view & navigation

```text
Implement rssh-tui minimal:
- Table columns exactly: `>  TYPE  FINGERPRINT  SRC  DISK  CERT  CONSTR  TTL  DESCRIPTION` with the iconography and truncation rules.
- Navigation: arrows/j/k; Enter opens action menu; hotkeys l/u/i/d/p/c; '/' search; s sort; r refresh; q quit.
- Always prompts master password on entry (even if unlocked) and performs unlock; after exit, agent remains unlocked.

Tests:
- For TUI, provide a thin integration test guarded by `--features tui` that boots a fake extension server (mock) and verifies basic key listing via a headless test (snapshot the rendered frame).
- Ensure building with `--no-default-features` (no TUI) still compiles.

Return code & tests.
```

---

## Prompt 18 — TUI actions & constraints dialog

```text
Wire TUI actions to extensions:
- Implement actions: load/unload/import/change description/change password/update cert/delete from disk.
- After load/create, show a small dialog to set confirm checkbox and lifetime seconds (optional); these constraints apply in RAM only.
- Display TTL countdown and 'c' flag in CONSTR column.

Tests:
- Mock extension server; drive key load -> set confirm+ttl; verify follow-up list reflects constraints.
- Delete from disk performs best-effort secure delete (simulate via virtual fs and ensure function calls happen).

Return code & tests.
```

---

## Prompt 19 — Daemon CLI polish: env output, socket policy, collisions

```text
Finish CLI polish:
- `daemon` prints only `SSH_AUTH_SOCK` for -s|-c|-f; auto-detect shell style from $SHELL; background by default; --foreground keeps stderr.
- If env SSH_AUTH_SOCK points to a live agent (any), exit with AlreadyRunning (code 4). If dead, ignore and proceed.
- `--socket <PATH>`: use exactly that path (parent dir must exist); if alive => AlreadyInUse; if dead => remove and bind.
- Respect `--log-level`, `--json`, `--journald`, `--quiet`.

Tests:
- Spawn dummy socket to simulate live agent -> collision error.
- Verify printed snippets across styles, and that no SSH_AGENT_PID is printed/altered.

Return code & tests.
```

---

## Prompt 20 — Certificates, identities, and prompts

```text
Implement certificate handling:
- On REQUEST_IDENTITIES, include cert if present (even if expired/not-yet-valid); ssh decides usage.
- On `manage.update_cert`, validate cert matches pubkey; parse principals and valid_after/before for display.
- In confirm prompt, show "CERT: present" and label "Expired" or "Not yet valid" as appropriate.

Tests:
- Add a key with cert; identities include cert; expired cert still returned.
- update_cert with mismatched pubkey => bad_cert_format/mismatch.

Return code & tests.
```

---

## Prompt 21 — Resource limits & timeouts

```text
Enforce runtime limits:
- Message size caps: 1 MiB default; 8 MiB for manage.list.
- Max 64 concurrent clients; backlog 128.
- IO timeouts: read 10s; write 10s; idle 60s -> close.
- Per-key signing concurrency: at most 1 in parallel (queue per key).
- Lifetimes: timers tick in real time even while locked; upon expiry, keys auto-unload; lock clears confirm cache but not lifetimes.

Tests:
- Simulate two concurrent sign requests for same key -> second waits until first completes.
- Lifetime expires across lock; confirm cache cleared on lock.

Return code & tests.
```

---

## Prompt 22 — Completions, man, logging defaults, E2E happy path

```text
Final polish:
- Add `rssh-agent completion <bash|zsh|fish>` and `rssh-agent man` producing roff from clap.
- Default logging: foreground=info; background (journald) = warn.
- End-to-end test:
  - Create temp storage; `init`; start daemon foreground with tmp socket; add ed25519 via ssh-add; sign once with confirm -> prompter returns Allow once; sign again -> prompt again; lock -> all ops fail; unlock -> sign works.
- Ensure all exit codes map correctly.

Return code & tests.

At the end, output a short README snippet with usage examples.
```

---

## Notes to the LLM (applies to all prompts)

* Always write tests first, then code.
* Avoid global singletons: inject traits for Clock, RNG, ProcInfo, Filesystem; in production use real implementations; in tests use fakes.
* Use `zeroize` for secret buffers; avoid accidental `Debug` printing of secrets.
* Use `nix` crate or libc for `mlockall`, `prctl`, `SO_PEERCRED`.
* Respect all spec’d error names/messages; they must be stable for TUI and tests.
* Keep public APIs small and well-documented (`///` rustdoc).
