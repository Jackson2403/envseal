# 🔐 EnvSync

A blazing-fast CLI that securely manages and syncs `.env` files across a
development team — **without ever storing secrets in the cloud**. It detects
missing environment variables between `env.example` and local setups, and uses
**local X25519 keys** to encrypt secrets for exactly the teammates allowed to
see them.

> Kill the "it works on my machine" error. Audit what's missing, share only
> what's needed, and keep secrets on your own machines.

<p align="center">
  <img alt="Go" src="https://img.shields.io/github/go-mod/go-version/Jackson2403/envsync?logo=go&logoColor=white&label=Go" />
  <img alt="CI" src="https://img.shields.io/github/actions/workflow/status/Jackson2403/envsync/ci.yml?branch=main&label=CI" />
  <img alt="Release" src="https://img.shields.io/github/v/release/Jackson2403/envsync?include_prereleases&label=Release" />
  <img alt="Downloads" src="https://img.shields.io/github/downloads/Jackson2403/envsync/total" />
  <img alt="License" src="https://img.shields.io/github/license/Jackson2403/envsync" />
</p>

---

## Highlights

- 🔎 **Audit** — `envsync check` reports missing, unexpected, and
  dangerously-committed variables at a glance.
- 🔐 **Hybrid crypto** — AES-256-GCM payload wrapped in X25519 ECDH keys
  (forward secrecy, per-recipient encryption).
- 🚫 **Zero cloud** — bundles are plain files you send out-of-band (AirDrop,
  USB, encrypted chat, shared drive).
- 🧑‍🤝‍🧑 **Per-member keys** — every developer has their own key; a departing
  member can be rotated out.
- 🧹 **Scaffold** — auto-generate `.env.example` from env vars referenced in
  Go, Node, Python, Ruby, Rust, and shell code.
- ⚙️ **Single static binary** — cross-compiled for Linux, macOS, and Windows.

---

## Install

Requires **Go 1.24+**.

```bash
# Build into ./bin (see Makefile for cross-platform targets)
make build

# Or install into your GOPATH/bin
go install github.com/Jackson2403/envsync/cmd/envsync@latest
```

The binary needs no runtime dependencies.

---

## Quick start

```bash
# 1. Each developer generates a keypair + project config
envsync init                       # writes ~/.envsync + .envsync.toml

# 2. Share your PUBLIC key with the team (it's safe to commit)
envsync init | grep 'public key'   # give teammates this base64 string
envsync team add alice@acme.com --pubkey <alice's base64>

# 3. Detect what teammates are missing
envsync check
```

### Sharing a secret environment

```bash
# Alice: encrypt .env.staging only for Bob
envsync share --file .env.staging --env staging --to bob@acme.com --output ./out

# Bob: receives STAGING.envsync.enc out-of-band, then decrypts
envsync sync ./out/STAGING.envsync.enc          # writes .env.staging
envsync sync --merge .env.staging.envsync.enc   # merge, don't overwrite
```

### Removing a departing teammate

```bash
envsync team remove bob@acme.com          # drop their key
envsync team list
envsync rotate ./out/STAGING.envsync.enc  # re-encrypt for remaining members
```

---

## Commands

| Command | Description |
|---------|-------------|
| `envsync init`             | Generate your identity keypair + `.envsync.toml` |
| `envsync check`            | Audit `.env` vs `.env.example` (table or JSON) |
| `envsync share`            | Encrypt an env file for specific teammates |
| `envsync sync`             | Decrypt a received bundle (replace or merge) |
| `envsync rotate`           | Re-encrypt a bundle for the current team set |
| `envsync generate`         | Scaffold `.env.example` from code references |
| `envsync team add\|remove\|list` | Manage team members' public keys |
| `envsync hook install\|uninstall` | Install/remove the pre-commit `.env` guard |
| `envsync history show\|verify`   | Inspect the signed, local audit log |
| `envsync p2p share\|sync`        | Encrypted machine-to-machine exchange |
| `envsync completion <shell>`     | Generate shell completions |
| `envsync man`              | Print the man page (roff) |
---

## How the encryption works

```
 Alice (shares)                        Bob (receives)
 1. Reads .env.staging locally
 2. Generates a random AES-256 session key
 3. Seals payload with AES-256-GCM
 4. For each recipient:
      - creates an ephemeral X25519 keypair
      - derives a shared secret (ECDH)
      - wraps the session key
 5. Writes STAGING.envsync.enc   →  6. reads the bundle
                                     7. ECDH with Bob's private key
                                        → recovers session key
                                     8. decrypts payload
                                     9. writes .env.staging
```

- Each recipient gets an **independent shared secret** (ephemeral keys), so one
  compromised recipient does not compromise the others' ciphertext.
- The `.enc` bundle contains **no plaintext** — verified by an integration test
  that greps the bundle for the original secret.
- Plaintext never touches any server; only public keys and ciphertext ever
  leave a machine.

**Design notes**
- Key exchange: `X25519` (Curve25519 ECDH) via the standard library
  `crypto/ecdh`.
- Cipher: `AES-256-GCM` with a fresh 12-byte nonce per encryption.
- Your private key lives in `~/.envsync/identity.key` (0600 perms).
- Team public keys live in `.envsync/team-keys/` and **are safe to commit** —
  they are public by design.

---

## Configuration (`.envsync.toml`)

Created by `envsync init`. See
[`.envsync.example.toml`](.envsync.example.toml).

```toml
[project]
name = "my-app"

[envs]
files   = ["local", "staging", "production"]
example = ".env.example"

[team]
keys_dir = ".envsync/team-keys"

[crypto]
algorithm = "x25519-aes256gcm"

[check]
dangerous_patterns = ["password", "secret", "token", "api_key", ...]
```

---

## Development

```bash
make build        # compile ./bin/envsync
make test         # run unit tests
make test-race    # tests with the race detector
make vet          # static checks
make cross        # cross-compile for linux/darwin/windows on amd64+arm64
```

### End-to-end test

```bash
# Simulates two developers with isolated identities.
powershell -File scripts\e2e.ps1
```

The e2e test exercises: init → check → team add → share → sync → check →
merge, and asserts the plaintext never leaks into the encrypted bundle.

### Architecture

```
cmd/envsync/main.go        entry point
internal/cli/              cobra command tree (init/check/share/sync/rotate,
                           generate, team, hook, history, p2p, completion, man)
internal/config/           .envsync.toml, team keys, local identity
internal/parser/           order/comment-aware .env reader & writer
internal/diff/             missing/extra/dangerous analysis
internal/crypto/           X25519 + AES-256-GCM envelopes, SSH identity
                           derivation, Ed25519 audit signing
internal/audit/            signed, local-only history log
internal/transport/        file bundle I/O + TLS P2P transport
scripts/e2e.ps1            two-developer integration test
.github/workflows/ci.yml   cross-platform test + release build
```

---

## Guard rails & advanced features

### Bootstrap identity from your SSH key
Skip generating a brand-new keypair — derive EnvSync's identity from a key you
already have:

```bash
envsync init --ssh                    # uses ~/.ssh/id_ed25519
envsync init --ssh --ssh-key ~/.ssh/deploy   # or any SSH private key
envsync init --ssh --passphrase "..."        # for encrypted keys
```

### Pre-commit guard (`envsync hook`)
Stop accidents *before* they reach history. Install a Git pre-commit hook that
blocks commits of `.env` files (other than `.env.example`/`.env.test`) and lines
that look like `NAME=<value>` secrets in any staged file:

```bash
envsync hook install      # writes .git/hooks/pre-commit
envsync hook uninstall    # removes it
git commit --no-verify    # explicitly override a block
```

### Local audit log (`envsync history`)
Every `share`, `sync`, and `rotate` appends a **signed, timestamped** entry
under `~/.envsync/history` — kept locally, never synced. Trace who gave you a
secret and when, and verify nobody tampered with the log:

```bash
envsync history show                     # table of all entries
envsync history show --since 7d          # last 7 days
envsync history verify                   # re-verify every signature
```

### Direct peer-to-peer exchange (`envsync p2p`)
No files, no cloud — encrypt and stream a bundle directly to a teammate over
TLS. The pairing code is used to derive the server certificate, so both ends
are cryptographically pinned to the code (a man-in-the-middle must know it):

```bash
# Alice, who already added Bob to the team:
envsync p2p share --file .env.staging --env staging --to bob@example.com

# Bob, on his machine (same LAN or reachable), typing Alice's code:
envsync p2p sync --addr 192.168.0.193:55810 --code XVM7-VZUL-63
```

> The pairing code is the shared secret. Share it out-of-band (e.g. verbally, a
> message) just like you would a password.

---

## Roadmap

- [x] SSH-key import (use an existing developer SSH key to bootstrap keys)
- [x] Peer-to-peer transport for direct machine-to-machine sync
- [x] Secret history / audit log (local only)
- [x] Pre-commit guardrail for `.env` leak prevention
- [x] Shell completion + man page packaging

Future ideas: a hosted relay for machines behind NAT, YubiKey/TPM-backed
identity, and signing the Envelope itself (so recipients can verify an
authentic sender, not just a matching key).

## License

[MIT](LICENSE)

## Security

Found a vulnerability or want the full threat model? See
[`SECURITY.md`](SECURITY.md) — or report privately via
[GitHub Security Advisories](https://github.com/Jackson2403/envsync/security/advisories/new).

