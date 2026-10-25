# Changelog

## 0.2.0

- `credenshare audit CODE`: a share's access log, newest first, with `--since`, `--until`,
  `--limit` and `--all`. Link previews, mail scanners and scripts are named from the user
  agent, as the app's Access History names them. Needs a key with the new `audit:read` scope.
- `credenshare list --status expired`: shares that have ended, and requests that have closed.
- `credenshare capabilities`: the key's scopes and rate limit, its plan's limits and features,
  and the team's sharing policy for a team key.
- `auth login` and `auth status` check a key with the capabilities read, so a key with any
  scope checks cleanly; `auth status` names the plan.

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
