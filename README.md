# CredenShare CLI

`credenshare` creates and manages CredenShare shares and secure requests from a terminal or a
script. Content is encrypted on your machine, with the same encryption the web app uses, before
anything is sent: CredenShare stores ciphertext and cannot read it.

```sh
echo "$DEPLOY_TOKEN" | credenshare share --field "Deploy token" --expires 24h --views 1
credenshare request --field "Database password:password" --title "Staging DB"
export DB_PASS=$(credenshare receive AbC123 --wait --field "Database password")
```

It needs an API key, which Business and Enterprise plans can create in the app's account
settings, on the Developer tab.

## Install

Download the archive for your platform from the
[releases](https://github.com/CredenShare/credenshare-cli/releases), check it against
`SHA256SUMS`, and put the binary on your `PATH`. For macOS on Apple silicon:

```sh
curl -LO https://github.com/CredenShare/credenshare-cli/releases/download/v0.1.0/credenshare_0.1.0_darwin_arm64.tar.gz
curl -LO https://github.com/CredenShare/credenshare-cli/releases/download/v0.1.0/SHA256SUMS
shasum -a 256 -c SHA256SUMS --ignore-missing
tar -xzf credenshare_0.1.0_darwin_arm64.tar.gz
sudo mv credenshare /usr/local/bin/
credenshare self-check
```

Archives exist for macOS (`darwin_amd64`, `darwin_arm64`), Linux (`linux_amd64`,
`linux_arm64`) and Windows (`windows_amd64`, `windows_arm64`, as `.zip`).

`credenshare self-check` runs the published conformance vectors against the encryption in the
binary you installed. Run it once before trusting the build with a secret.

**The binaries are not code-signed yet.** On macOS, a binary downloaded through a browser is
quarantined and refuses to start; remove the flag with
`xattr -d com.apple.quarantine ./credenshare`. Downloading with `curl`, as above, does not set
it. On Windows, if a downloaded `credenshare.exe` is blocked, run `Unblock-File .\credenshare.exe`
in PowerShell.

With Go 1.24 or later you can also build it yourself:

```sh
go install github.com/CredenShare/credenshare-cli/cmd/credenshare@latest
```

## Sign in

```sh
credenshare auth login
```

asks for the API key at a hidden prompt, checks it against the API, and stores it in the
system keychain: the macOS Keychain, the Windows Credential Manager, or the Secret Service on
Linux. `credenshare auth status` shows which key is in use, by its id, and checks it;
`credenshare auth logout` removes it.

For CI, and on machines with no keychain, set `CREDENSHARE_API_KEY` instead. It takes
precedence over the keychain.

## Commands

| Command | What it does |
|---|---|
| `credenshare share` | Encrypts fields here, creates a share and prints its link. Values come from a hidden prompt, stdin or a file. Takes an expiry, a view limit, a timed view, a passcode, custody, and `--notify` to email you when it is viewed, refused, expired or deleted. |
| `credenshare request` | Creates a secure request: a link someone fills in to send you secrets. What they submit is sealed to a key made on this machine and kept in your keychain. |
| `credenshare receive CODE` | Fetches a request's submissions and decrypts them here. `--wait` waits for the first one; `--field NAME` prints one value, for scripts. |
| `credenshare list [shares\|requests]` | Short codes and expiry times. Never content. `--status expired` lists the shares that have ended and the requests that have closed. |
| `credenshare show CODE` | A share's or a request's details, never its content. |
| `credenshare audit CODE` | A share's access log, newest first: when, from which IP address and platform, and by which client, with link previews and mail scanners named as the app names them. Needs a key with the `audit:read` scope; the plan's access-log retention applies. |
| `credenshare expire CODE` | Expires a share now. |
| `credenshare request delete CODE` | Closes a request; run again on a closed request to delete it and its submissions. |
| `credenshare stats` | Share counts and the last 14 days of views. |
| `credenshare capabilities` | What the key may do: its scopes and rate limit, the plan behind it, its limits and features, and the team's sharing policy for a team key. |
| `credenshare generate` | A password, passphrase or PIN, generated offline. |
| `credenshare self-check` | The conformance vectors, against this binary. |

`credenshare help <command>` lists a command's flags. Every command takes `--json` for output a
script can parse: one JSON document on stdout, and on failure an `error` object with the exit
code, the HTTP status, the API's error code and the request id.

### Exit codes

| Code | Meaning |
|---|---|
| 0 | Done |
| 1 | Usage, or a problem on this machine (a file, the keychain) |
| 2 | Not signed in, or the key was refused |
| 3 | No such share or request, or nothing arrived in time |
| 4 | Refused by the plan, the key's scopes or the team's sharing policy |
| 5 | The network or the server |

## How secrets are handled

- **Values are never command-line arguments.** Arguments end up in shell history and process
  lists, so there is no flag that takes a secret: values come from a hidden prompt, from stdin,
  or from a file you name. A passcode is typed twice at a hidden prompt or read from a file.
- **The API key lives in the keychain** or in `CREDENSHARE_API_KEY`, and is not written to a
  file. Output shows its id, never the secret. A key's third part, its custody secret, is used
  on this machine and is not sent.
- **A request's key stays here.** It is kept in the keychain under the request's code, and
  `receive` uses it to open submissions locally. On a machine with no keychain,
  `--access-link-file PATH` writes it, as the request's access link, to a new file instead
  (on macOS and Linux, readable only by you; on Windows, the folder's permissions apply). Keep
  that file secret: it reads every submission.
- **Output carries only what you asked for**: a share's link (which holds its key, so send it
  privately), a collect link (which lets someone submit and never read), or a value you
  received.
- **No telemetry.** The only requests made are to the CredenShare API, and they identify the
  CLI version in the `User-Agent`.
- **Titles and descriptions are visible to CredenShare.** They are metadata, not encrypted
  content, so keep secrets in fields.

A team key acts inside its team, so the team's sharing policy applies: a share or request it
refuses exits with code 4 and the policy's reason, such as "It requires a passcode."

Opening a share from the terminal is not possible, by design: the API has no way to read a
share, because a key would skip the protections of the recipient page. Open links in a browser.

## Configuration

| Variable | Default | |
|---|---|---|
| `CREDENSHARE_API_KEY` | | An API key; overrides the keychain |
| `CREDENSHARE_API_URL` | `https://api.credenshare.io/v1` | Another API address |
| `CREDENSHARE_LINK_ORIGIN` | `https://crs.sh` | Where printed links point |

Keys and request keys are stored per API address, so keys for two environments can be kept
side by side.

## Building and testing

```sh
go test ./...
go build -o credenshare ./cmd/credenshare
```

The tests drive every command against an in-process fake of the API, with a fake terminal and
keychain, and check what reaches the server: ciphertext, verifiers and public keys, never a
value, a passcode, a key or a request's seed.

## Licence

Apache 2.0; see [LICENSE](LICENSE) and [NOTICE](NOTICE). The passphrase word list is the
EFF's, under CC BY 3.0 US.
