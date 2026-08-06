# Contributing to EnvSync

Thanks for helping out! EnvSync is a small, security-focused CLI, so we value
clear, reviewable changes that keep the blast radius small. Reading this guide
(few minutes) is the best way to get a change merged.

## Ground rules

- **Security first.** This tool is about keeping secrets safe. If a change could
  weaken confidentiality, integrity, or the zero-plaintext guarantee, call it
  out explicitly in the PR description.
- **Small, focused PRs.** One logical change per pull request. Don't mix refactors
  with features.
- **Minimal blast radius.** Modify only the files required. Don't reformat
  unrelated code or dependencies-unless they're part of the change.
- **No secrets in code.** Never commit tokens, keys, or `.env` files. Install the
  guard and use it.
- **Match the existing style.** `gofmt`, conventional commit-ish messages, and
  the established file/package layout in `README.md → Architecture`.

## Getting started

Requirements: **Go 1.24+** and `git`.

```bash
# Fork & clone, then:
make build        # compile ./bin/envsync
make test         # run unit tests
make vet          # static analysis
make cross        # cross-compile all platforms into ./dist
```

The two-developer integration test:

```powershell
powershell -File scripts\e2e.ps1
```

## Where to start

- Issues tagged `good first issue`
- The **Roadmap** in `README.md` ("Future ideas")
- Clear, boring bug fixes and test-coverage gaps

## Coding conventions

- Run `gofmt` (we enforce it in CI for every package).
- Keep `go vet ./...` clean.
- Write a focused unit test for new behaviour. Sensitive crypto/transport logic
  should have round-trip, tamper, and negative-case tests.
- Prefer stdlib `crypto`/`net` and existing dependencies over adding new ones.
- Export only what other packages need; keep helpers lowercase otherwise.

## Commit & PR checklist

- `gofmt -l .` is empty for your changed files.
- `go build ./...`, `go vet ./...`, `go test ./... -count=1` all pass locally.
- Add/update unit tests for behaviour changes.
- PR title is a short summary; description explains the *why* and any security
  implications.

## Testing on CI

Pushes to `main` and PRs run `test` on Ubuntu, macOS, and Windows. Note: the
race detector is skipped on macOS due to a `dyld` incompatibility on the arm64
runners — don't be surprised by that; Linux/Windows cover the `-race` path.

## Dependencies

`go.mod` is intentionally minimal (cobra, toml, color, tablewriter, x/crypto,
go-md2man). Before adding a dependency:

1. Is it justified over stdlib or an existing dep?
2. Does it cross-compile for all six targets (`make cross`)?
3. Does it bring cgo? (We build with `CGO_ENABLED=0`.)

## Security reports

Please don't file public issues for vulnerabilities. See
[`SECURITY.md`](SECURITY.md) for the private reporting process.

## Getting help

Open a discussion or tag a maintainer on your PR for design feedback before
writing a lot of code if you're unsure about scope.
