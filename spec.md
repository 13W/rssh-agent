# rssh-agent v0.1.0 — Technical Specification (Linux)

> **Status:** frozen for v0.1.0
> **Scope:** Linux, OpenSSH ≥ 8, Debian-based (Ubuntu ≥ 22.04, Debian 12).
> **License:** Dual MIT/Apache-2.0.
> **Language:** Rust 2021 (MSRV 1.74).
> **Targets:** `x86_64-unknown-linux-gnu`, `aarch64-unknown-linux-gnu`. Optional: `x86_64-unknown-linux-musl`, `aarch64-unknown-linux-musl`.

This document is **normative** for rssh-agent v0.1.0. It describes CLI, daemon behavior, protocol compatibility with OpenSSH, custom extension protocol, key storage formats, security model, TUI, logging, limits, and exit codes.

---

## 1. Overview & Goals

* A drop-in compatible SSH agent daemon that supports core OpenSSH agent messages and `ssh-add` behavior (including `-c`/`-t` constraints), and adds a **management TUI** and **on-disk encrypted key vault**.
* **Security first**: hardening, encrypted RAM-at-rest (keys in RAM stay AEAD-encrypted under a master-derived MemKey), strict file permissions, strict ACL on the socket.
* **Predictable UX**:

  * `eval $(rssh-agent daemon ...)` exports **only** `SSH_AUTH_SOCK` (no `SSH_AGENT_PID`).
  * `init` **must** be run first to set the master password and create config; otherwise **no command** may run (daemon refuses to start).
  * `manage` is **administrative**: it **always** re-prompts for the master password (even if already unlocked) and performs a global unlock.

---

## 2. Compatibility Matrix

### 2.1 Supported Platforms

* Distros: Debian-based only: **Ubuntu 22.04+/24.04+**, **Debian 12+**.
* OpenSSH client tools: **≥ 8.0** (`ssh`, `ssh-add`).

### 2.2 Supported Key Types (v1)

* **Ed25519**, **RSA** (2048–8192 bits).

  * Reject RSA < 2048 → error `rsa_too_small`.
  * Accept RSA 2048 with a **warning**; recommend 3072+.
  * Reject RSA > 8192 → error `rsa_too_large`.
* **ECDSA, DSA, FIDO/sk-**\*: **not supported in v1**.

### 2.3 Supported Agent Messages (OpenSSH)

* `SSH_AGENTC_REQUEST_IDENTITIES (11)`
* `SSH_AGENTC_SIGN_REQUEST (13)`
* `SSH_AGENTC_ADD_IDENTITY (17)`
* `SSH_AGENTC_REMOVE_IDENTITY (18)`
* `SSH_AGENTC_REMOVE_ALL_IDENTITIES (19)`
* `SSH_AGENTC_LOCK (22)`
* `SSH_AGENTC_UNLOCK (23)`
* `SSH_AGENTC_ADD_ID_CONSTRAINED (25)` with **confirm** and **lifetime** only
  (unknown constraints → FAILURE).
* **Not supported**: PKCS#11 smartcard ops (`ADD_SMARTCARD_KEY (20)`, `REMOVE_SMARTCARD_KEY (21)`) → **FAILURE** (`unsupported: pkcs11` in logs).

### 2.4 Locked State Semantics

* While locked, **all** requests except `UNLOCK` → `SSH_AGENT_FAILURE`.
  `REQUEST_IDENTITIES` also returns **FAILURE**.

---

## 3. Security & Cryptography

### 3.1 Master Password Lifecycle

* Set **only** by `rssh-agent init` (interactive prompt; no env var).
  If master password not set → **all commands fail**, daemon **must not start**.
* Policy: UTF-8; spaces preserved; length **8..1024**; not empty/whitespace-only; no composition rules.

### 3.2 Key Derivation & Encryption

* **KDF:** Argon2id (`m=256 MiB`, `t=3`, `p=1` recommended; `m=128–256` allowed).
* **AEAD:** XChaCha20-Poly1305.
* **Salts & IVs:** random per object; store alongside ciphertext. **Do not** use fingerprint as IV.
* **Domain separation:** `"rssh-agent:v1:mem"` (RAM) vs `"rssh-agent:v1:disk"` (files).

### 3.3 In-RAM Key Handling (Unlocked)

* **Ephemeral-at-rest**: loaded keys are stored in RAM **encrypted** under a MemKey (derived from master+ephemeral salt).
* On every sign/manage operation, the private key is decrypted into a **temporary buffer**, used, then **zeroized** immediately.
* **Lock**: zeroizes MemKey/derivatives so existing RAM ciphertexts become indecipherable.
* **Unlock**: re-derives MemKey; previously loaded keys (still present as RAM ciphertexts) become usable again.
* After **start**: RAM is **empty** (no keys loaded).

### 3.4 Hardening (strict)

* Must succeed or daemon **refuses to start**:

  * `mlockall(MCL_CURRENT|MCL_FUTURE)`
  * `RLIMIT_CORE=0`, `PR_SET_DUMPABLE=0`, `PR_SET_NO_NEW_PRIVS=1`
  * Mark sensitive buffers with `MADV_DONTDUMP`.
* All secrets implement `zeroize`.

### 3.5 Anti-bruteforce (master password)

* Up to **3 attempts** per invocation; backoff: **1s → 2s → 4s**.
* After 3 consecutive failures: **global 60s delay** for this agent (UID-scoped).
* `--pass-fd` is **single-attempt** (no interactive retries).

---

## 4. Files, Storage & Formats

### 4.1 Storage Directory

* Default: `~/.ssh/rssh-agent/`.
* Config location: **inside storage**: `<storage_dir>/config.json` (0600).
* `init --dir <PATH>`: expand `~`/envvars, **canonicalize** (realpath), ensure directory exists (0700, same UID).
* If directory contains any `config.json` or `sha256-*.json` → **already\_initialized** (no repair mode in v0.1.0).

### 4.2 Config Format (`rssh-config/v1`)

```json
{
  "version": "rssh-config/v1",
  "sentinel": {
    "kdf": { "name": "argon2id", "mib": 256, "t": 3, "p": 1, "salt_b64": "<...>" },
    "aead": { "name": "xchacha20poly1305", "nonce_b64": "<...>" },
    "ciphertext_b64": "<...>"             // AEAD("ok")
  },
  "settings": {
    "storage_dir": "/abs/path/.ssh/rssh-agent",
    "fingerprint_ui": "sha256",
    "allow_rsa_sha1": false
  }
}
```

### 4.3 Key File Format (`rssh-keyfile/v1`)

**File name:** `sha256-<hex>.json` (hex of **SHA-256** of public key, **no separators**).
**Directory perms:** 0700; **file perms:** 0600; no symlinks/hardlinks.

**Outer (unencrypted) envelope:**

```json
{
  "version": "rssh-keyfile/v1",
  "kdf":  { "name": "argon2id", "mib": 256, "t": 3, "p": 1, "salt_b64": "<...>" },
  "aead": { "name": "xchacha20poly1305", "nonce_b64": "<...>" },
  "ciphertext_b64": "<base64_of_encrypted_payload>"
}
```

**Decrypted payload:**

```json
{
  "type": "ed25519" | "rsa",
  "description": "laptop@host",                  // UTF-8, 1..256, no NUL/CR/LF
  "secret_openssh_b64": "<base64(openssh-key-v1)>", // may have its own passphrase
  "cert_openssh_b64": "<base64(ssh-*-cert-v01@openssh.com) or omitted>",
  "created": "2025-08-12T12:34:56Z",
  "updated": "2025-08-12T12:34:56Z"
}
```

**Notes:**

* The **entire payload** is AEAD-encrypted under the **master password**.
* Internal **OpenSSH private key** format:

  * `kdfname="bcrypt"`, `salt` 16 bytes, `rounds` default **16**, allowed **14–22**.
  * **Empty passphrase is forbidden**. Either set a passphrase or none.
* **Certificate validation on import/update**:

  * Must match the public key; else error `bad_cert_format/mismatch`.
  * TUI shows validity interval and principals; still returned to clients even if expired/not yet valid (ssh decides what to do).

### 4.4 File I/O & Atomicity

* Create/replace via: write to `tmp`, `fsync(file)`, `rename()`, `fsync(dir)`.
* Open with `O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC`; chmod to 0600 (ignore umask).
* **Last-writer-wins** if multiple agents edit the same file concurrently.
* On load, recompute fingerprint; if **mismatch** with filename → error `fingerprint_mismatch` (do not rename).

### 4.5 Deletion from Disk (TUI action)

* “Best-effort secure delete”: overwrite file with zeros, `fsync(file)`, rename to random name, `fsync(dir)`, then `unlink`.
  (No guarantees on SSD/journaling; show a warning.)

---

## 5. Daemon, Socket, and Processes

### 5.1 Launch Modes & `eval` Output

* `rssh-agent daemon` **forks to background** by default. `--foreground|-F` keeps in the foreground (logs to stderr).
* **Shell snippet** (quiet; **only** `SSH_AUTH_SOCK`):

  * `-s` (sh/bash/zsh): `SSH_AUTH_SOCK="<path>"; export SSH_AUTH_SOCK;`
  * `-c` (csh/tcsh): `setenv SSH_AUTH_SOCK "<path>";`
  * `-f` (fish): `set -gx SSH_AUTH_SOCK "<path>";`
* Default shell style: **auto-detect by `$SHELL`** (`fish`→`-f`, `csh/tcsh`→`-c`, else `-s`).
* **Do not** print `SSH_AGENT_PID`; **do not** unset a pre-existing `SSH_AGENT_PID`.

### 5.2 Socket Location & Policy

* **Path style:** OpenSSH-like in `/tmp`: `/tmp/ssh-<random>/agent.<pid>`, dir **0700**, socket **0600**.
* `--socket <PATH>`: create socket **exactly at PATH** (parent dir must exist). If the path is alive → `already_in_use`; if dead → remove and create anew.
* If env `SSH_AUTH_SOCK` **points to a live agent** (any) → `already_running` and **exit**. If dead → ignore and continue.
* **ACL:** accept only clients with **same UID** via `SO_PEERCRED`. Root has **no** special rights.

### 5.3 Signals

* `SIGTERM`/`SIGINT`: graceful shutdown — zeroize secrets, close connections, delete socket dir, exit 0.
* `SIGHUP`: perform **lock** (same as `rssh-agent lock`).
* Ignore `SIGPIPE`/`SIGCHLD`.
* Panic hook: zeroize + best-effort socket cleanup.

### 5.4 Graceful Stop

* `rssh-agent stop`: send extension `control.shutdown`; wait in the daemon up to **5s** for in-flight ops; stop accepting new requests; on timeout, cancel and exit.

---

## 6. Protocols

### 6.1 Transport Framing

* Unix domain socket; standard SSH agent **length-prefixed** framing (uint32 BE length, payload).

### 6.2 OpenSSH Behavior

#### 6.2.1 `REQUEST_IDENTITIES`

* Returns keys **in insertion order** (order of load/add).
* `comment` field is the **current description** (updated live via TUI).
* While locked → **FAILURE**.

#### 6.2.2 `ADD_IDENTITY` / `ADD_ID_CONSTRAINED`

* Support Ed25519 and RSA only.
* `ADD_ID_CONSTRAINED` supports only:

  * `confirm` (requires prompt before each sign),
  * `lifetime` (seconds; `0` = none; max **30 days** → else **FAILURE**).
* Unknown constraints → **FAILURE**.
* Duplicate loads (same public key) → **FAILURE** with `already_loaded`.

#### 6.2.3 `SIGN_REQUEST`

* Ed25519 → `ssh-ed25519`.
* RSA → accept only `rsa-sha2-256` and `rsa-sha2-512`:

  * **Default** if no flags or both flags: **`rsa-sha2-512`**.
  * Legacy **`ssh-rsa` (SHA-1)** is **rejected** → **FAILURE**.
* If key has `confirm`, show prompt (see §7); if prompt cannot be shown (no TTY, no `SSH_ASKPASS`) → **immediate FAILURE** (`confirm_unavailable` in logs).
* Forwarding is **allowed**, but forwarded detection is **not attempted**; prompt shows `Forwarded: unknown`.

#### 6.2.4 Remove

* `REMOVE_IDENTITY`: exact public key match; not found → **FAILURE**.
* `REMOVE_ALL_IDENTITIES`: unload all from RAM (**RAM only**; disk untouched). Clears lifetimes and confirm caches.

#### 6.2.5 Lock/Unlock

* `LOCK`: zeroize MemKey; keys remain as RAM ciphertexts; all ops fail until unlock.
* `UNLOCK`: restore MemKey on correct master password; wrong password → failure with backoff/lockout.

### 6.3 Custom Extensions (CBOR over `SSH2_AGENTC_EXTENSION`)

* **Namespace:** `rssh-agent@local`.
* **Encoding:** **CBOR** (`ciborium`).
* **Top-level response:** always a protocol **success** with CBOR payload:

  * Success: `{ "ok": true, ... }`
  * Error: `{ "ok": false, "error": { "code": "<slug>", "msg": "<human text>" } }`
* **Exceptions:** malformed CBOR or oversize → agent answers **`SSH_AGENT_FAILURE`**.

#### 6.3.1 `manage.list`

* Request: `{ "op": "manage.list" }`
* Response:

  ```cbor
  {
    "ok": true,
    "keys": [
      {
        "fp_sha256_hex": "...",
        "type": "ed25519" | "rsa",
        "format": "ssh-ed25519" | "rsa-sha2-256" | "rsa-sha2-512",
        "description": "…",
        "source": "internal" | "external",
        "loaded": true | false,
        "has_disk": true | false,
        "has_cert": true | false,
        "constraints": { "confirm": bool, "lifetime_expires_at": "2025-08-13T12:34:56Z" | null },
        "created": "2025-08-12T…Z" | null,
        "updated": "2025-08-12T…Z" | null
      }
    ]
  }
  ```
* Size limit for this op only: **8 MiB**. Others: **1 MiB**.

#### 6.3.2 `manage.load`

Loads a key from disk to RAM (may require the key’s own passphrase).

```cbor
{ "op": "manage.load", "fp_sha256_hex": "...", "key_pass_b64": null | "<base64>" }
```

Errors: `need_key_password`, `bad_key_password`, `not_found`, `already_loaded`, `need_master_unlock`.

#### 6.3.3 `manage.unload`

```cbor
{ "op": "manage.unload", "fp_sha256_hex": "..." }
```

Errors: `not_loaded`, `not_found`, `need_master_unlock`.

#### 6.3.4 `manage.import`

Import a RAM-only (external) key into our store.

```cbor
{
  "op": "manage.import",
  "fp_sha256_hex": "...",
  "description": "…",            // optional override
  "set_key_password": true | false,
  "new_key_pass_b64": null | "<base64>"
}
```

Rules:

* On import, if a cert is currently attached in RAM → **auto-save** into `cert_openssh_b64`.
  Errors: `not_external`, `already_exists`, `need_new_key_password`.

#### 6.3.5 `manage.set_desc`

```cbor
{ "op": "manage.set_desc", "fp_sha256_hex": "...", "description": "…" }
```

#### 6.3.6 `manage.change_pass`

Change **internal** `openssh-key-v1` passphrase (disk entry required).

```cbor
{
  "op": "manage.change_pass",
  "fp_sha256_hex": "...",
  "old_pass_b64": null | "<base64>",
  "new_pass_b64": "<base64>"
}
```

Errors: `no_disk_entry`, `bad_old_pass`.

#### 6.3.7 `manage.update_cert`

```cbor
{ "op": "manage.update_cert", "fp_sha256_hex": "...", "cert_openssh_b64": "<base64>" }
```

Errors: `bad_cert_format/mismatch`.

#### 6.3.8 `manage.create`

Create a new key on disk and (if unlocked) load to RAM.

```cbor
{
  "op": "manage.create",
  "type": "ed25519" | "rsa",
  "bits": 3072,
  "rounds": 16,
  "description": "…",
  "set_key_password": true | false,
  "new_key_pass_b64": null | "<base64>"
}
```

Response: `{ "ok": true, "fp_sha256_hex": "…" }`.

#### 6.3.9 `control.shutdown`

```cbor
{ "op": "control.shutdown" }
```

---

## 7. User Interaction & UX

### 7.1 `ssh-add -c` Confirmation Prompt

* Always shown for keys with **confirm** constraint.
* **Information shown** (TTY/GUI):

  * Key fingerprint (`SHA256:<base64>`), type, description.
  * Whether a cert is attached (and **Expired/Not yet valid** marker).
  * Client info: peer UID, PID, `comm`/`exe`.
  * **Forwarded:** `unknown` (we do not attempt detection in v1).
* **Actions:** `Allow once`, `Allow 15 min`, `Deny`.
  Timeout **30 s** → **Deny**.
* The **15 min cache** is bound to `(fp + peer_uid + pid + process_start_time + exe_path)` and:

  * applies to all signings by that process for that key,
  * cleared on **lock** and process exit,
  * lives **in RAM only** (not persisted).

### 7.2 ASKPASS (for unlock/manage prompts)

* Use **`SSH_ASKPASS`** only (no `RSSH_ASKPASS`).
* When:

  * if **no TTY** and `DISPLAY` is set, or
  * if `SSH_ASKPASS_REQUIRE=force`, or
  * if `SSH_ASKPASS_REQUIRE=prefer` even when TTY is present.
* If `SSH_ASKPASS_REQUIRE=never` → never use ASKPASS.
* Program is invoked with **one** prompt argument; password is read from stdout (trim trailing `\n`, preserve internal spaces). Non-zero exit or empty string → cancel.

### 7.3 `manage` TUI

* **Always** prompts for master password (even if agent already unlocked) and **performs unlock**. After exit, agent remains **unlocked**.
* **Table columns**:

  ```
  >  TYPE  FINGERPRINT              SRC   DISK  CERT  CONSTR  TTL   DESCRIPTION
  ```

  * `TYPE`: `ed25519`/`rsa`/`ed25519-cert`/`rsa-cert`
  * `FINGERPRINT`: `SHA256:AbCd…XyZ1` (base64, shortened to \~12–14 chars after prefix)
  * `SRC`: `internal` / `external`
  * `DISK`: `☑` (exists on disk and loaded), `☐` (on disk, not loaded), `–` (no disk entry)
  * `CERT`: `✓` if present
  * `CONSTR`: `c` for confirm, `-` none
  * `TTL`: remaining (e.g., `14m`, `2h`, `∞`)
  * `DESCRIPTION`: full comment (UI truncation only)
* **Navigation:** arrows/`j`/`k`; `Enter` opens actions; hotkeys `l` (load), `u` (unload), `i` (import), `d` (change desc), `p` (change pass), `c` (update cert), `/` search, `s` sort, `r` refresh, `q` quit.
* **Actions** (per selected key):

  * `load`: from disk to RAM; may prompt for the key’s passphrase.
  * `unload`: RAM only.
  * `import`: save an external RAM key to disk (auto-save current cert).
  * `change description`
  * `change password` (only if on disk)
  * `update cert`
  * `delete from disk` (best-effort secure delete)
* **Create key** (from TUI):

  * Defaults: type **ed25519**; RSA bits default **3072** (min 2048); `rounds` 16.
  * Ask whether to set an **internal** passphrase (OpenSSH); default: **offer** to set (user may opt out).
  * After creation: save to disk and **load to RAM** if agent unlocked.
* **Constraints dialog on load/create**: prompt for `confirm` and `lifetime (secs)`; stored **in RAM only** (survive lock/unlock, cleared on restart).

---

## 8. CLI

### 8.1 Command Grammar

```
rssh-agent [GLOBAL FLAGS] <command> [options]

Commands:
  init [--dir <PATH>]
  daemon [-s|-c|-f] [--socket <PATH>] [--foreground|-F]
  lock
  unlock [--pass-fd N]
  stop [--socket <PATH>]
  manage
  completion <bash|zsh|fish>
  man
```

> **Note:** `manage` has **no** `--dir`. All file operations go through the running daemon.

### 8.2 Global Flags

* `--socket <PATH>`: explicit socket path (client commands); for `daemon` — where to create the socket.
* `--dir <PATH>`: **only** for `init` and `daemon`.
  Priority (effective storage dir for the daemon): `--dir` → `RSSH_STORAGE_DIR` → `config.json` → default.
* `--foreground, -F` (daemon only)
* Logging:

  * `--log-level <off|error|warn|info|debug|trace>`
  * `--json` (stderr JSON logs)
  * `--journald` (duplicate to journald when backgrounded)
  * `--quiet, -q` (errors only)
* `--version`, `--help`

### 8.3 Command Details

#### `init [--dir <PATH>]`

* Creates storage directory and **config.json** with sentinel AEAD("ok").
* Sets the **master password** via interactive prompt (TTY/ASKPASS per §7.2); **required**.
* Fails if the directory is already initialized or contains any key files.

#### `daemon [-s|-c|-f] [--socket <PATH>] [--foreground|-F]`

* Requires prior `init`; refuses to start otherwise.
* Creates socket (default `/tmp/ssh-<rand>/agent.<pid>` or `--socket <PATH>`).
  If env `SSH_AUTH_SOCK` is alive → **already\_running** and exit.
* Prints only `SSH_AUTH_SOCK` snippet (auto-detect shell if not specified).
* Background by default; foreground keeps logs to stderr.
* **Socket ACL**: owner-only; accept connections from **same UID** only.

#### `lock`

* Zeroize MemKey; agent becomes locked.

#### `unlock [--pass-fd N]`

* Prompts for master password (TTY/ASKPASS rules) or reads from FD (single attempt).
* On success, re-derives MemKey.

#### `stop [--socket <PATH>]`

* Sends `control.shutdown` to the specified/current agent; graceful 5s.

#### `manage`

* Always re-prompts for master password, performs unlock, opens TUI (see §7.3).
* Exits leaving the agent **unlocked**.

#### `completion <bash|zsh|fish>`, `man`

* Print shell completion to stdout; print `rssh-agent(1)` man page to stdout.

### 8.4 Exit Codes (recommended set)

* `0` — success
* `2` — bad arguments / bad environment
* `3` — `no_socket` (cannot connect)
* `4` — `already_running` / `already_in_use`
* `5` — `locked` / `need_master_unlock`
* `6` — wrong master password
* `7` — `not_initialized`
* `8` — `unsupported` / `not_implemented`
* `9` — timeout / I/O error
* `10` — access denied (ACL/permissions)
* `11` — resource limits (message too large, too many keys, etc.)
* Others → `1`

---

## 9. Limits & Resource Management

* **Message size:** default **1 MiB**; **`manage.list`** up to **8 MiB**.
* **Concurrent clients:** max **64**; socket backlog **128**.
* **Timeouts:** read **10s**, write **10s**, idle **60s**.
* **Loaded keys in RAM:** max **1024** (strict).
* **Per-key signing concurrency:** at most **1** in parallel (queue per key).

---

## 10. Logging

* Default levels:

  * **Foreground**: `info`
  * **Background**: `warn` (only visible if `--journald`)
* Formats:

  * human-readable `key=value` to stderr (default),
  * JSON to stderr with `--json`,
  * optional journald duplication with `--journald`.
* Privacy: never log secrets or raw payloads; log fingerprints, PIDs, exe paths, paths, and error codes where useful.

---

## 11. Internationalization

* UI/logs/prompts in **English** by default, locale auto-detection via `$LANG`, fallback **English**.

---

## 12. Developer Notes (Rust)

### 12.1 Crate Layout (Cargo workspace)

```
crates/
  rssh-core    # crypto, storage, RAM manager, constraints
  rssh-proto   # SSH wire + extensions (CBOR)
  rssh-daemon  # server/IPC, socket, ACL, signals
  rssh-cli     # single binary `rssh-agent` (subcommands)
  rssh-tui     # TUI (optional)
```

* Feature `tui` (enabled by default) pulls in `rssh-tui`; build without TUI using `--no-default-features`.

### 12.2 Major Dependencies

* Async/IPC: `tokio`
* CLI/serde/logging: `clap`, `serde`, `tracing`
* CBOR: `ciborium`
* Crypto: `argon2`, `chacha20poly1305`, `rand_chacha`, `zeroize`
* SSH keys/formats: `ssh-key` (OpenSSH `openssh-key-v1`, certs)
* TUI: `ratatui`, `crossterm`
* Hidden input: `rpassword`

---

## 13. Behavior Details & Edge Cases

* **Duplicates** (same public key) on add/load → **FAILURE: already\_loaded** (do not merge/override constraints).
* **Constraints**:

  * RAM-only (persist across lock/unlock, cleared on restart).
  * TUI `load/create` prompts to set `confirm` and `lifetime`.
* **Lifetimes** (`ssh-add -t`):

  * Timers run in **real time** even while locked; keys expire automatically; “Allow 15 min” cache is cleared on lock.
* **Forwarding**: allowed; prompts work; forwarded detection **not attempted** (display `Forwarded: unknown`).
* **Unlock vs Manage**:

  * `unlock` enables SSH operations.
  * `manage` is **administrative**: always asks master password (even if unlocked) and then unlocks globally.
* **Description (comment)**:

  * Import: keep incoming comment; if empty, default `$USER@$(hostname)`.
  * Create: default `$USER@$(hostname)`.
  * Validation: UTF-8, 1..256, no NUL/CR/LF; spaces preserved.
  * Changing description updates **RAM immediately** and the disk file if present.
* **REQUEST\_IDENTITIES order**: by **insertion**; comment from current RAM state.
* **PKCS#11**: unsupported (return FAILURE).
* **Info extension**: **not** implemented (`--version` only).

---

## 14. Examples

### 14.1 First-time Setup

```bash
$ rssh-agent init --dir ~/.ssh/rssh-agent
# prompts for master password, creates config.json

$ eval "$(rssh-agent daemon)"    # auto-detects shell and prints SSH_AUTH_SOCK only
```

### 14.2 Using with OpenSSH

```bash
$ ssh-add ~/.ssh/id_ed25519
Identity added: id_ed25519 (user@host)

$ ssh -o IdentitiesOnly=yes user@server
# if key had -c confirm, rssh-agent shows a prompt on first signature
```

### 14.3 Lock / Unlock

```bash
$ rssh-agent lock
$ rssh-agent unlock
# prompts for master password (TTY/ASKPASS rules apply)
```

### 14.4 TUI Manage

```bash
$ rssh-agent manage
# always prompts master password (administrative), unlocks globally, shows table
```

### 14.5 Extension `manage.load` (CBOR pseudo)

```cbor
{ "op": "manage.load", "fp_sha256_hex": "9b0a...e3", "key_pass_b64": null }
→ { "ok": false, "error": { "code": "need_key_password", "msg": "Key is encrypted" } }
```

### 14.6 Key File Payload (example)

```json
{
  "type": "ed25519",
  "description": "work-laptop",
  "secret_openssh_b64": "b3BlbnNzaC1rZXktdjEAAAAABGJjcnlwdAAAB...==",
  "cert_openssh_b64": "c3NoLWVkMjU1MTktY2VydC12MDFAb3BlbnNzaC5jb20AAA...==",
  "created": "2025-08-12T12:34:56Z",
  "updated": "2025-08-12T12:34:56Z"
}
```

---

## 15. Testing & CI (v0.1.0)

* **Baseline (now):** build for glibc+musl (x86\_64/aarch64), `clippy -Dwarnings`, unit tests, a few integration tests with `ssh-add`/`ssh`, file/permissions checks.
* **Future (v1.1 goal):** property tests (`proptest`), fuzzing (`cargo-fuzz`) for wire/CBOR and keyfile parser, negative cases (malformed frames, 1 MiB limits), ASan/UBSan, coverage, distro matrix (Ubuntu 22.04/24.04, Debian 12).

---

## 16. Non-Goals (v0.1.0)

* ECDSA, FIDO/U2F, PKCS#11.
* Windows/macOS/FreeBSD.
* Systemd socket activation.
* Persistent constraints in key files (constraints are RAM-only).
* Repair/wipe modes for `init`.

---

## 17. Error Codes (Extension `error.code` shortlist)

* `need_master_unlock`, `locked`
* `not_initialized`
* `not_found`, `already_exists`, `already_loaded`, `not_loaded`, `not_external`
* `need_key_password`, `bad_key_password`, `bad_cert_format`, `mismatch`
* `fingerprint_mismatch`
* `io_error`, `internal`
* `too_many_keys`
* `unsupported`, `not_implemented`

---

## 18. Build & Install

### 18.1 From Source

```bash
# Install Rust (>=1.74) and target(s) as needed
$ cargo build --release            # builds with TUI
$ cargo build --release --no-default-features   # without TUI
```

### 18.2 Runtime Requirements

* OpenSSH client ≥ 8.0 (`ssh`, `ssh-add`).
* Sufficient `RLIMIT_MEMLOCK` for `mlockall`.
* Linux with `/proc` (for PIDs) — no forwarded-detection logic used in v1.

---

## 19. Security Checklist

* [x] Socket perms 0600; dir 0700; SO\_PEERCRED UID==owner
* [x] Strict hardening; refuse to start if `mlockall` fails
* [x] Keys encrypted at rest in RAM; MemKey zeroized on lock/exit
* [x] File writes are atomic with fsyncs; no symlinks/hardlinks
* [x] Master password anti-bruteforce with global cooldown
* [x] `ssh-rsa` SHA-1 signatures disabled

---

## 20. Open Questions (future versions)

* Support ECDSA / FIDO, and policy around agent forwarding trust signals.
* Optional per-key autoload flags.
* Read-only shared storage mode; conflict resolution beyond last-writer-wins.
* Systemd socket activation and journald-by-default integration.

---

**End of rssh-agent v0.1.0 specification.**
