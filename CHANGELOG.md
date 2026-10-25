# Changelog

## 0.1.0

The first release.

- `credenshare auth login | status | logout`: an API key kept in the system keychain, or
  `CREDENSHARE_API_KEY` for CI.
- `credenshare share`: fields encrypted on this machine; values from a hidden prompt, stdin or
  a file; expiry, view limit, timed view, passcode and custody.
- `credenshare request` and `credenshare receive`: a secure request whose key stays in the
  keychain, and its submissions decrypted here; `--wait` and `--field` for scripts.
- `credenshare list`, `show`, `expire`, `request delete` and `stats`.
- `credenshare generate`: a password, passphrase or PIN, offline.
- `credenshare self-check`: the SDK's conformance vectors, run against this binary.
- `--json` on every command, and stable exit codes.
