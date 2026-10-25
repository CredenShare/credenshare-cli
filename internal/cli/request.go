package cli

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"time"

	credenshare "github.com/CredenShare/credenshare-sdk-go"
)

var requestCommand = command{
	name:    "request",
	summary: "Create a secure request (a link someone fills in), or delete one",
	help:    requestHelp,
	run:     runRequest,
}

const requestHelp = `Usage:
  credenshare request --field ITEM [--field ITEM…] [flags]
  credenshare request delete CODE [--yes]

A secure request is a link you send to someone so they can send you secrets. What they
submit is sealed to a key made on this machine, which stays in your keychain; read it with
` + "`credenshare receive CODE`" + `. The printed link lets them submit, never read, so it is safe to
paste into a ticket or a chat.

  credenshare request --field "Database password:password" --title "Staging DB" --expires 7d

Flags:
  --field ITEM[:TYPE]        a field to ask for; repeatable, at least one. Without a
                             TYPE it is plain text, as in the app; :password masks
                             what the person types
  --title TEXT               the request's name (default "Secure request"); visible to
                             CredenShare
  --description TEXT         shown on the form; also visible to CredenShare
  --expires WHEN             30m, 24h, 7d, 2w, or a time (default 30 days)
  --max-submissions N        how many people can submit
  --views N                  how many times the form can be opened
  --require-login            submitters must sign in
  --require-mfa              submitters must sign in with two-factor authentication
  --allow-domain DOMAIN      only submitters with an email at DOMAIN; repeatable
  --allow-ip ADDRESS         only from this IP address or range; repeatable
  --passcode                 ask for a passcode submitters must enter (typed twice)
  --passcode-file PATH       read the passcode from a file
  --access-link-file PATH    keep the request's key in a new file instead of the keychain,
                             as its access link (for machines with no keychain). Keep the
                             file secret: it reads every submission.

delete closes an open request (no new submissions; the ones received are kept). Run it again
on a closed request to delete it and its submissions for good.
`

func runRequest(ctx context.Context, a *App, out *output, args []string) error {
	if len(args) > 0 {
		switch args[0] {
		case "delete":
			return requestDelete(ctx, a, out, args[1:])
		case "create":
			args = args[1:]
		}
	}

	var specs []fieldSpec
	fs := newFlagSet("request")
	fs.Var(fieldFlag{&specs}, "field", "")
	title := fs.String("title", "Secure request", "")
	description := fs.String("description", "", "")
	expires := fs.String("expires", "", "")
	maxSubmissions := fs.Int("max-submissions", 0, "")
	views := fs.Int("views", 0, "")
	requireLogin := fs.Bool("require-login", false, "")
	requireMFA := fs.Bool("require-mfa", false, "")
	var domains, ips stringList
	fs.Var(&domains, "allow-domain", "")
	fs.Var(&ips, "allow-ip", "")
	askPasscode := fs.Bool("passcode", false, "")
	passcodeFile := fs.String("passcode-file", "", "")
	accessLinkFile := fs.String("access-link-file", "", "")

	positional, err := parseArgs(fs, "request", requestHelp, out, args)
	if err != nil {
		return err
	}
	if len(positional) > 0 {
		return usagef("request", "unexpected argument %q", positional[0])
	}
	if len(specs) == 0 {
		return usagef("request", "a request needs at least one --field")
	}

	params := credenshare.CreateRequestParams{
		Title:            *title,
		Description:      *description,
		RequiresLogin:    *requireLogin || *requireMFA,
		RequiresMfa:      *requireMFA,
		RestrictedDomain: domains,
		IPWhitelist:      ips,
	}
	for _, spec := range specs {
		params.Fields = append(params.Fields, credenshare.RequestField{Item: spec.label, Type: spec.typ})
	}
	if *expires != "" {
		if params.ExpiredAt, err = expiryAt(*expires, a.Now()); err != nil {
			return usagef("request", "%v", err)
		}
	}
	if flagWasSet(fs, "max-submissions") {
		if *maxSubmissions < 1 {
			return usagef("request", "--max-submissions must be at least 1")
		}
		params.MaxSubmission = *maxSubmissions
	}
	if flagWasSet(fs, "views") {
		if *views < 1 {
			return usagef("request", "--views must be at least 1")
		}
		params.AccessCountsLeft = *views
	}
	if *askPasscode && *passcodeFile != "" {
		return usagef("request", "use --passcode or --passcode-file, not both")
	}
	if params.Passcode, err = readPasscode(ctx, a, "request", *askPasscode, *passcodeFile); err != nil {
		return err
	}

	client, err := a.client()
	if err != nil {
		return err
	}

	// The request's key has to be kept before the request exists: a request whose key is
	// lost can be filled in by anyone and read by no one. So the keychain is tried first,
	// and the access-link file is created (empty, private) first, and either failing stops
	// here with nothing created.
	apiURL := a.apiURL()
	useKeychain := *accessLinkFile == ""
	if useKeychain {
		if err := probeKeychain(a.Keyring, apiURL); err != nil {
			return fmt.Errorf("%w (%v). Pass --access-link-file PATH to keep the request's key "+
				"in a file instead", errKeychain, err)
		}
	}
	var linkFile *os.File
	if *accessLinkFile != "" {
		if linkFile, err = os.OpenFile(*accessLinkFile, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600); err != nil {
			return fmt.Errorf("creating the access-link file: %w", err)
		}
		defer linkFile.Close()
	}

	if params.Seed, err = credenshare.NewSeed(); err != nil {
		return err
	}
	created, err := client.CreateRequest(ctx, params)
	if err != nil {
		if linkFile != nil && !errors.Is(err, credenshare.ErrDeliveryUnknown) {
			_ = linkFile.Close()
			_ = os.Remove(*accessLinkFile)
		}
		return err
	}

	stored := sourceKeychain
	if linkFile != nil {
		stored = "file"
		if _, err := fmt.Fprintln(linkFile, created.AccessLink); err != nil {
			return fmt.Errorf("request %s was created, but writing its access link failed: %w",
				created.ShortCode, err)
		}
		if err := linkFile.Close(); err != nil {
			return fmt.Errorf("request %s was created, but writing its access link failed: %w",
				created.ShortCode, err)
		}
	} else if err := a.Keyring.Set(seedAccount(apiURL, created.ShortCode), encodeSeed(created.Seed)); err != nil {
		// The keychain worked a moment ago. The key is shown rather than lost, on the one
		// stream a script does not capture.
		fmt.Fprintf(a.Stderr, "credenshare: request %s was created, but its key could not be kept "+
			"in the keychain (%v). Its access link, which reads every submission, is:\n%s\n",
			created.ShortCode, err, created.AccessLink)
		return silentExit(exitUsage)
	}

	result := map[string]any{
		"short_code":   created.ShortCode,
		"collect_link": created.CollectLink,
		"expired_at":   created.ExpiredAt,
		"public_key":   created.PublicKey,
		"key_stored":   stored,
	}
	if linkFile != nil {
		result["access_link_file"] = *accessLinkFile
	}
	if err := out.emit(result, func(o *output) {
		fmt.Fprintln(o.stdout, created.CollectLink)
	}); err != nil {
		return err
	}
	where := "Its key is in your keychain"
	if linkFile != nil {
		where = "Its access link is in " + *accessLinkFile + "; keep that file secret"
	}
	out.note("Request %s created. Send the link to whoever will fill it in: it lets them submit, "+
		"never read. %s. Read submissions with: credenshare receive %s",
		created.ShortCode, where, created.ShortCode)
	return nil
}

// probeKeychain writes and removes a throwaway entry, so a machine with no keychain is found
// out before a request is created rather than after.
func probeKeychain(k Keyring, apiURL string) error {
	nonce := make([]byte, 6)
	if _, err := rand.Read(nonce); err != nil {
		return err
	}
	account := seedAccount(apiURL, "probe-"+hex.EncodeToString(nonce))
	if err := k.Set(account, "probe"); err != nil {
		return err
	}
	return k.Delete(account)
}

func requestDelete(ctx context.Context, a *App, out *output, args []string) error {
	fs := newFlagSet("request")
	yes := fs.Bool("yes", false, "")
	positional, err := parseArgs(fs, "request", requestHelp, out, args)
	if err != nil {
		return err
	}
	if len(positional) != 1 {
		return usagef("request", "request delete needs one request code")
	}
	code, err := shortCode("request", positional[0])
	if err != nil {
		return err
	}

	client, err := a.client()
	if err != nil {
		return err
	}
	if !*yes {
		question := fmt.Sprintf("Close request %s? No one can submit to it afterwards; what was "+
			"received is kept.", code)
		// The API closes an open request and deletes a closed one, so say which this is.
		if summary, err := client.GetRequest(ctx, code); err == nil && closedBy(summary, a.Now()) {
			question = fmt.Sprintf("Request %s is closed. Delete it and its submissions for good?", code)
		}
		if err := confirm(ctx, a, "request", question); err != nil {
			return err
		}
	}

	deletion, err := client.DeleteRequest(ctx, code)
	if err != nil {
		return err
	}
	if deletion.Outcome == "deleted" {
		// Nothing left to read, so the key goes too.
		if err := a.Keyring.Delete(seedAccount(a.apiURL(), deletion.ShortCode)); err != nil &&
			!errors.Is(err, errSecretNotFound) {
			out.note("The request's key could not be removed from the keychain: %v", err)
		}
	}
	return out.emit(map[string]any{
		"short_code": deletion.ShortCode,
		"outcome":    deletion.Outcome,
	}, func(o *output) {
		switch deletion.Outcome {
		case "expired":
			fmt.Fprintf(o.stdout, "Request %s is closed. Its submissions are kept; run `credenshare "+
				"request delete %s` again to delete it and them.\n", deletion.ShortCode, deletion.ShortCode)
		case "deleted":
			fmt.Fprintf(o.stdout, "Request %s and its submissions are deleted.\n", deletion.ShortCode)
		default:
			fmt.Fprintf(o.stdout, "The API did not say what it did to request %s; check with "+
				"`credenshare show %s` before running this again.\n", deletion.ShortCode, deletion.ShortCode)
		}
	})
}

// closedBy reports whether a request has stopped taking submissions.
func closedBy(summary *credenshare.RequestSummary, now time.Time) bool {
	if summary.ExpiredAt == nil {
		return false
	}
	at, err := time.Parse(time.RFC3339, *summary.ExpiredAt)
	return err == nil && !at.After(now)
}
