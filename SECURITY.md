# Security Policy

EnvSeal is designed to keep secrets **off your cloud** — a departing member's
key rotation, per-recipient encryption, and a zero-plaintext bundle format. We
take vulnerabilities here seriously.

## Supported Versions

| Version | Supported          |
|---------|--------------------|
| 0.1.x   | ✅ The latest release |

Only the latest tagged release is actively maintained. Please upgrade before
reporting an issue from an older tag.

## Reporting a Vulnerability

**Do not open a public issue for a security vulnerability.** Report it privately
via GitHub's built-in **private vulnerability reporting**:

1. Go to <https://github.com/Jackson2403/envseal/security/advisories/new>
2. Fill in a title and a clear, minimal description of the issue.
3. Include, where possible: affected command(s)/flags, a reproducible example,
   and the suspected impact.

You'll get an acknowledgment within a few business days. We'll coordinate a fix
and a coordinated disclosure date before public release.

If you can't use the advisory flow, DM the maintainer directly — but keep
sensitive details out of public channels.

### What we'd love reported

- Any path where **plaintext secret material** could appear in a bundle, log,
  audit trail, or network stream.
- Key-generation or key-derivation weaknesses (e.g., the X25519 identity,
  SSH-key derivation, or the Ed25519 audit signing).
- Encryption misuse: nonce reuse, missing authenticated data, envelope version
  mishandling, or downgrade paths.
- Issues in the P2P transport: certificate pinning, pairing-code handling, or
  ~~man-in-the-middle~~ weaknesses.
- The `history` audit log: signature bypass or log tampering that goes
  undetected by `envseal history verify`.
- Any accidental `.env` commit vector that the `envseal hook` guard misses.

## Security Model (TL;DR)

- **Hybrid encryption** — secrets are sealed with AES-256-GCM under a random
  session key; that key is wrapped per recipient via X25519 ECDH using an
  ephemeral keypair (forward secrecy). One compromised recipient does not
  compromise the others' ciphertext.
- **Zero plaintext** — `.envseal.enc` bundles and the P2P stream carry only
  public keys and ciphertext. A documented integration test asserts no
  plaintext leaks into a bundle.
- **Local keys** — the identity private key lives in `~/.envseal/identity.key`
  (0600 perms); team **public** keys are safe to commit. Set `ENVSEAL_HOME` to
  relocate the identity directory.
- **Audit log** — `share`/`sync`/`rotate` append Ed25519-signed, timestamped
  entries locally; `envseal history verify` detects tampering.
- **"Bring your own SSH key"** — `envseal init --ssh` derives the identity from
  an existing SSH private key, so there is no new key material to protect.

## Deployment & Hygiene Recommendations

- Never commit real `.env` files — install the guard with `envseal hook install`.
- Rotate a member's access by removing their key and running
  `envseal rotate`; discard previously distributed bundles for that member.
- Share bundle files and P2P pairing codes **out-of-band** (encrypted chat,
  verbal, USB) — never alongside the ciphertext on an unsecured channel.
- Prefer `--dry-run` on `sync`/`share` when auditing behavior.

## License

This repository is [MIT licensed](LICENSE); security guidance does not change
that license.
