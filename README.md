# 🔐 EnvSeal

A blazing-fast CLI that securely manages and syncs `.env` files across a
development team — **without ever storing secrets in the cloud**. It detects
missing environment variables between `env.example` and local setups, and uses
**local X25519 keys** to encrypt secrets for exactly the teammates allowed to
see them.

> Kill the "it works on my machine" error. Audit what's missing, share only
> what's needed, and keep secrets on your own machines.

<p align="center">
  <img alt="Go" src="https://img.shields.io/github/go-mod/go-version/Jackson2403/envseal?logo=go&logoColor=white&label=Go" />
  <img alt="CI" src="https://img.shields.io/github/actions/workflow/status/Jackson2403/envseal/ci.yml?branch=main&label=CI" />
  <img alt="Release" src="https://img.shields.io/github/v/release/Jackson2403/envseal?include_prereleases&label=Release" />
  <img alt="Downloads" src="https://img.shields.io/github/downloads/Jackson2403/envseal/total" />
  <img alt="License" src="https://img.shields.io/github/license/Jackson2403/envseal" />
</p>

---

## Highlights

- 🔎 **Audit** — `envseal check` reports missing, unexpected, and
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
go install github.com/Jackson2403/envseal/cmd/envseal@latest
```

The binary needs no runtime dependencies.

---

## Quick start

```bash
# 1. Each developer generates a keypair + project config
envseal init                       # writes ~/.envseal + .envseal.toml

# 2. Share your PUBLIC key with the team (it's safe to commit)
envseal init | grep 'public key'   # give teammates this base64 string
envseal team add alice@acme.com --pubkey <alice's base64>

# 3. Detect what teammates are missing
envseal check
```

### Sharing a secret environment

```bash
# Alice: encrypt .env.staging only for Bob
envseal share --file .env.staging --env staging --to bob@acme.com --output ./out

# Bob: receives STAGING.envseal.enc out-of-band, then decrypts
envseal sync ./out/STAGING.envseal.enc          # writes .env.staging
envseal sync --merge .env.staging.envseal.enc   # merge, don't overwrite
```

### Removing a departing teammate

```bash
envseal team remove bob@acme.com          # drop their key
envseal team list
envseal rotate ./out/STAGING.envseal.enc  # re-encrypt for remaining members
```

---

## Commands

| Command | Description |
|---------|-------------|
| `envseal init`             | Generate your identity keypair + `.envseal.toml` |
| `envseal check`            | Audit `.env` vs `.env.example` (table or JSON) |
| `envseal share`            | Encrypt an env file for specific teammates |
| `envseal sync`             | Decrypt a received bundle (replace or merge) |
| `envseal rotate`           | Re-encrypt a bundle for the current team set |
| `envseal generate`         | Scaffold `.env.example` from code references |
| `envseal team add\|remove\|list` | Manage team members' public keys |
| `envseal hook install\|uninstall` | Install/remove the pre-commit `.env` guard |
| `envseal history show\|verify`   | Inspect the signed, local audit log |
| `envseal p2p share\|sync`        | Encrypted machine-to-machine exchange |
| `envseal completion <shell>`     | Generate shell completions |
| `envseal man`              | Print the man page (roff) |
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
 5. Writes STAGING.envseal.enc   →  6. reads the bundle
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
- Your private key lives in `~/.envseal/identity.key` (0600 perms).
- Team public keys live in `.envseal/team-keys/` and **are safe to commit** —
  they are public by design.

---

## Configuration (`.envseal.toml`)

Created by `envseal init`. See
[`.envseal.example.toml`](.envseal.example.toml).

```toml
[project]
name = "my-app"

[envs]
files   = ["local", "staging", "production"]
example = ".env.example"

[team]
keys_dir = ".envseal/team-keys"

[crypto]
algorithm = "x25519-aes256gcm"

[check]
dangerous_patterns = ["password", "secret", "token", "api_key", ...]
```

---

## Development

```bash
make build        # compile ./bin/envseal
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
cmd/envseal/main.go        entry point
internal/cli/              cobra command tree (init/check/share/sync/rotate,
                           generate, team, hook, history, p2p, completion, man)
internal/config/           .envseal.toml, team keys, local identity
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
Skip generating a brand-new keypair — derive EnvSeal's identity from a key you
already have:

```bash
envseal init --ssh                    # uses ~/.ssh/id_ed25519
envseal init --ssh --ssh-key ~/.ssh/deploy   # or any SSH private key
envseal init --ssh --passphrase "..."        # for encrypted keys
```

### Pre-commit guard (`envseal hook`)
Stop accidents *before* they reach history. Install a Git pre-commit hook that
blocks commits of `.env` files (other than `.env.example`/`.env.test`) and lines
that look like `NAME=<value>` secrets in any staged file:

```bash
envseal hook install      # writes .git/hooks/pre-commit
envseal hook uninstall    # removes it
git commit --no-verify    # explicitly override a block
```

### Local audit log (`envseal history`)
Every `share`, `sync`, and `rotate` appends a **signed, timestamped** entry
under `~/.envseal/history` — kept locally, never synced. Trace who gave you a
secret and when, and verify nobody tampered with the log:

```bash
envseal history show                     # table of all entries
envseal history show --since 7d          # last 7 days
envseal history verify                   # re-verify every signature
```

### Direct peer-to-peer exchange (`envseal p2p`)
No files, no cloud — encrypt and stream a bundle directly to a teammate over
TLS. The pairing code is used to derive the server certificate, so both ends
are cryptographically pinned to the code (a man-in-the-middle must know it):

```bash
# Alice, who already added Bob to the team:
envseal p2p share --file .env.staging --env staging --to bob@example.com

# Bob, on his machine (same LAN or reachable), typing Alice's code:
envseal p2p sync --addr 192.168.0.193:55810 --code XVM7-VZUL-63
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

---

## FAQ

**Is my secret ever stored in the cloud?**
No. Only public keys and ciphertext exist in a bundle or on the wire. The
decrypted `.env` is written locally; the encrypted bundle and any pairing data
are designed to be exchanged out-of-band.

**Why use both X25519 and AES-256-GCM?**
Encrypting the payload directly with a fast symmetric cipher (AES-256-GCM)
would need the same key shared by everyone. Instead we use a random per-envelope
session key sealed separately for each recipient with X25519 ECDH — so each
recipient gets their own wrapped copy and forward secrecy from ephemeral keys.

**How do I bootstrap my team quickly?**
Each developer runs `envseal init`. Share only the printed **public key**
(base64) — it is safe to commit — and register it with
`envseal team add <email> --pubkey <base64>`. No cloud, no central server.

**Can I use my existing SSH key?**
Yes. `envseal init --ssh` derives your EnvSeal identity from
`~/.ssh/id_ed25519` (or `--ssh-key <path>`), so there's no new key to manage.

**What if a teammate leaves?**
`envseal team remove <email>` drops their public key, then `envseal rotate`
re-encrypts a bundle for the remaining members. Discard any bundle already
distributed to the departing member.

**Will `sync` clobber my local tweaks?**
Not if you use `--merge`. `envseal sync --merge` overlays only incoming keys and
preserves your existing entries and comments. Without `--merge`, the whole file
is replaced.

**How do I stop someone committing `.env` by accident?**
`envseal hook install` writes a `pre-commit` hook that blocks `.env` files
(other than `.env.example`/`.env.test`) and secret-looking lines in any staged
file. `git commit --no-verify` overrides it in an emergency.

**Is my local history tamper-proof?**
`share`/`sync`/`rotate` append Ed25519-signed entries. Run
`envseal history verify` to detect any modification.

**How do I install it?**
Grab the matching binary from the
[Releases](https://github.com/Jackson2403/envseal/releases) page, or
`go install github.com/Jackson2403/envseal/cmd/envseal@latest`.

---

## Contributing

Contributions are welcome! Read [`CONTRIBUTING.md`](CONTRIBUTING.md) for setup,
coding conventions, and the PR checklist.

## License

[MIT](LICENSE)

## Security

Found a vulnerability or want the full threat model? See
[`SECURITY.md`](SECURITY.md) — or report privately via
[GitHub Security Advisories](https://github.com/Jackson2403/envseal/security/advisories/new).

