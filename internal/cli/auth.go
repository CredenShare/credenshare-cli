package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
)

var authCommand = command{
	name:    "auth",
	summary: "Sign in with an API key, check it, or sign out",
	help:    authHelp,
	run:     runAuth,
}

const authHelp = `Usage:
  credenshare auth login     store an API key in the system keychain
  credenshare auth status    show which key is in use, and check it
  credenshare auth logout    remove the stored key

login asks for the key at a hidden prompt, or reads it from stdin when stdin is not a
terminal:

  credenshare auth login < key.txt

The key is never accepted as an argument, because arguments are kept in shell history and
shown in process lists. API keys are created in the app's account settings, on the
Developer tab.

Keys are stored per API address (CREDENSHARE_API_URL). CREDENSHARE_API_KEY, when set, is used
instead of the keychain.
`

func runAuth(ctx context.Context, a *App, out *output, args []string) error {
	if len(args) == 0 {
		return usagef("auth", "auth needs login, status or logout")
	}
	switch args[0] {
	case "login":
		return authLogin(ctx, a, out, args[1:])
	case "status":
		return authStatus(ctx, a, out, args[1:])
	case "logout":
		return authLogout(a, out, args[1:])
	case "-h", "--help", "help":
		fmt.Fprint(out.stdout, authHelp)
		return nil
	}
	return usagef("auth", "auth has no %q; use login, status or logout", args[0])
}

func noArguments(name, help string, out *output, args []string) error {
	positional, err := parseArgs(newFlagSet(name), name, help, out, args)
	if err != nil {
		return err
	}
	if len(positional) > 0 {
		return usagef(name, "unexpected argument %q", positional[0])
	}
	return nil
}

// maxSecretInput bounds what is read from stdin for a key or a passcode.
const maxSecretInput = 64 << 10

func authLogin(ctx context.Context, a *App, out *output, args []string) error {
	if err := noArguments("auth", authHelp, out, args); err != nil {
		return err
	}

	var key string
	if a.Terminal.StdinIsTerminal() {
		value, err := a.Terminal.ReadSecret(ctx, "API key: ")
		if err != nil {
			return err
		}
		key = value
	} else {
		raw, err := io.ReadAll(io.LimitReader(a.Stdin, maxSecretInput))
		if err != nil {
			return fmt.Errorf("reading the key from stdin: %w", err)
		}
		key = string(raw)
	}
	key = strings.TrimSpace(key)
	if key == "" {
		return usagef("auth", "no key was given")
	}

	client, err := a.clientFor(key)
	if err != nil {
		return err
	}
	// Checked before it is stored, so a typo is found now rather than on the first share.
	plan, err := checkKey(ctx, client)
	if err != nil {
		return err
	}

	if err := a.Keyring.Set(apiKeyAccount(a.apiURL()), key); err != nil {
		return fmt.Errorf("%w (%v); set %s instead", errKeychain, err, envAPIKey)
	}

	credential := client.Credential
	err = out.emit(map[string]any{
		"signed_in": true,
		"key_id":    credential.KeyID,
		"api_url":   a.apiURL(),
		"stored_in": sourceKeychain,
		"plan":      plan,
	}, func(o *output) {
		fmt.Fprintf(o.stdout, "Signed in with key %s. The key is in your keychain.\n", credential.KeyID)
	})
	if strings.TrimSpace(a.Getenv(envAPIKey)) != "" {
		out.note("Note: %s is set in this shell, and it is used instead of the keychain.", envAPIKey)
	}
	return err
}

func authStatus(ctx context.Context, a *App, out *output, args []string) error {
	if err := noArguments("auth", authHelp, out, args); err != nil {
		return err
	}
	key, source, err := a.credential()
	if err != nil {
		return err
	}
	client, err := a.clientFor(key)
	if err != nil {
		return fmt.Errorf("the API key in the %s: %w", source, err)
	}

	check := "accepted"
	plan, checkErr := checkKey(ctx, client)
	if checkErr != nil {
		check = "refused"
		if exitCodeFor(checkErr) != exitAuth {
			check = "not checked"
		}
	}

	status := map[string]any{
		"signed_in": true,
		"key_id":    client.Credential.KeyID,
		"source":    source,
		"api_url":   a.apiURL(),
		"check":     check,
		"plan":      plan,
	}
	if checkErr != nil {
		status["error"] = describe(checkErr)
	}
	if err := out.emit(status, func(o *output) {
		from := "the keychain"
		if source == sourceEnvironment {
			from = envAPIKey
		}
		fmt.Fprintf(o.stdout, "Key %s, from %s\nAPI: %s\nCheck: %s\n",
			client.Credential.KeyID, from, a.apiURL(), check)
		if plan != "" {
			fmt.Fprintf(o.stdout, "Plan: %s\n", plan)
		}
	}); err != nil {
		return err
	}
	if checkErr != nil {
		fmt.Fprintln(a.Stderr, "credenshare: "+describe(checkErr))
		return silentExit(exitCodeFor(checkErr))
	}
	return nil
}

func authLogout(a *App, out *output, args []string) error {
	if err := noArguments("auth", authHelp, out, args); err != nil {
		return err
	}
	err := a.Keyring.Delete(apiKeyAccount(a.apiURL()))
	removed := err == nil
	if err != nil && !errors.Is(err, errSecretNotFound) {
		return fmt.Errorf("%w (%v)", errKeychain, err)
	}
	if err := out.emit(map[string]any{
		"signed_out": true, "removed": removed, "api_url": a.apiURL(),
	}, func(o *output) {
		if removed {
			fmt.Fprintln(o.stdout, "Signed out. The key was removed from your keychain.")
		} else {
			fmt.Fprintln(o.stdout, "No key was stored for "+a.apiURL()+".")
		}
	}); err != nil {
		return err
	}
	if strings.TrimSpace(a.Getenv(envAPIKey)) != "" {
		out.note("%s is still set in this shell, so commands still have a key.", envAPIKey)
	}
	return nil
}
