package cli

import (
	"context"
	"fmt"

	credenshare "github.com/CredenShare/credenshare-sdk-go"
)

var shareCommand = command{
	name:    "share",
	summary: "Encrypt fields here and create a share; prints its link",
	help:    shareHelp,
	run:     runShare,
}

const shareHelp = `Usage: credenshare share [flags]

Encrypts the fields on this machine, creates a share, and prints its link. The link carries
the key; anyone holding it can open the share, and CredenShare cannot.

Values never go on the command line. Each comes from a hidden prompt, from stdin, or from a
file:

  credenshare share --field "Database password"
  echo "$TOKEN" | credenshare share --field "Deploy token" --expires 24h --views 1
  credenshare share --file "Private key=./key.pem" --title "Staging key"

With no --field or --file, one field named "Secret" is read from stdin or asked for.

Flags:
  --field LABEL[:TYPE]       a field whose value is asked for (or read from stdin when it
                             is the only one and stdin is a pipe); repeatable
  --file LABEL[:TYPE]=PATH   a field read from a file, or from stdin with PATH "-";
                             repeatable
  --title TEXT               the share's name (default "Secure share"); visible to
                             CredenShare, so keep secrets out of it
  --description TEXT         also visible to CredenShare
  --expires WHEN             30m, 24h, 7d, 2w, or a time like 2026-12-31T23:00:00Z
  --views N                  how many times it can be opened
  --timed-view DURATION      how long the content stays visible once opened (5s to 24h)
  --passcode                 ask for a passcode the recipient must enter (typed twice)
  --passcode-file PATH       read the passcode from a file
  --custody                  also make it readable from your dashboard (needs a key
                             created with custody)

TYPE is one of text, password, date, multiline, markdown, source_code, url, qr. Without one,
a single line is a password and several lines are multiline text.

A team's sharing policy applies to a team key. A share it refuses exits with code 4 and the
policy's reason.
`

func runShare(ctx context.Context, a *App, out *output, args []string) error {
	var specs []fieldSpec
	fs := newFlagSet("share")
	fs.Var(fieldFlag{&specs}, "field", "")
	fs.Var(fileFlag{&specs}, "file", "")
	title := fs.String("title", "Secure share", "")
	description := fs.String("description", "", "")
	expires := fs.String("expires", "", "")
	views := fs.Int("views", 0, "")
	timedView := fs.String("timed-view", "", "")
	askPasscode := fs.Bool("passcode", false, "")
	passcodeFile := fs.String("passcode-file", "", "")
	custody := fs.Bool("custody", false, "")

	positional, err := parseArgs(fs, "share", shareHelp, out, args)
	if err != nil {
		return err
	}
	if len(positional) > 0 {
		return usagef("share", "unexpected argument %q: values are never taken as arguments; "+
			"use --field (asked for, or stdin) or --file", positional[0])
	}

	params := credenshare.CreateParams{
		Title:       *title,
		Description: *description,
		Custody:     *custody,
	}
	if *expires != "" {
		if params.ExpiredAt, err = expiryAt(*expires, a.Now()); err != nil {
			return usagef("share", "%v", err)
		}
	}
	if flagWasSet(fs, "views") {
		if *views < 1 {
			return usagef("share", "--views must be at least 1")
		}
		params.AccessCountsLeft = *views
	}
	if *timedView != "" {
		d, err := parseDuration(*timedView)
		if err != nil || d.Seconds() < 5 || d.Seconds() > 86400 {
			return usagef("share", "--timed-view is between 5s and 24h")
		}
		params.TimedView = int(d.Seconds())
	}

	if *askPasscode && *passcodeFile != "" {
		return usagef("share", "use --passcode or --passcode-file, not both")
	}
	// The file first: a bad path is better found before anything is typed.
	if params.Passcode, err = readPasscode(ctx, a, "share", false, *passcodeFile); err != nil {
		return err
	}
	if len(specs) == 0 {
		specs = []fieldSpec{{label: "Secret"}}
	}
	if params.Fields, err = readFields(ctx, a, "share", specs); err != nil {
		return err
	}
	if *askPasscode {
		if params.Passcode, err = readPasscode(ctx, a, "share", true, ""); err != nil {
			return err
		}
	}

	client, err := a.client()
	if err != nil {
		return err
	}
	share, err := client.CreateShare(ctx, params)
	if err != nil {
		return err
	}

	err = out.emit(map[string]any{
		"short_code": share.ShortCode,
		"link":       share.Link,
		"expired_at": share.ExpiredAt,
		"custody":    share.Custody,
	}, func(o *output) {
		fmt.Fprintln(o.stdout, share.Link)
	})
	if err != nil {
		return err
	}
	expiry := "with no expiry"
	if share.ExpiredAt != nil {
		expiry = "until " + *share.ExpiredAt
	}
	out.note("Share %s created, %s. Anyone with the link can open it; send it privately.",
		share.ShortCode, expiry)
	if share.Custody == "failed" {
		out.note("Custody was not stored, so the share is readable only through its link.")
	}
	return nil
}
