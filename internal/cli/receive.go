package cli

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	credenshare "github.com/CredenShare/credenshare-sdk-go"
)

var receiveCommand = command{
	name:    "receive",
	summary: "Read and decrypt what was submitted to a secure request",
	help:    receiveHelp,
	run:     runReceive,
}

const receiveHelp = `Usage: credenshare receive CODE [flags]

Fetches the submissions to a request and decrypts them here, with the key kept when the
request was created. CredenShare only ever holds them sealed.

  credenshare receive AbC123
  export DB_PASS=$(credenshare receive AbC123 --wait --field "Database password")

Flags:
  --wait                     wait until at least one submission has arrived
  --timeout DURATION         how long --wait waits (default 10m)
  --field NAME               print only this field's value, from the newest submission
  --access-link-file PATH    read the key from a request's access link in a file, or from
                             stdin with "-", instead of the keychain. Requests created on
                             another machine need this.
`

func runReceive(ctx context.Context, a *App, out *output, args []string) error {
	fs := newFlagSet("receive")
	wait := fs.Bool("wait", false, "")
	timeoutText := fs.String("timeout", "10m", "")
	intervalText := fs.String("interval", "5s", "")
	fieldName := fs.String("field", "", "")
	accessLinkFile := fs.String("access-link-file", "", "")
	positional, err := parseArgs(fs, "receive", receiveHelp, out, args)
	if err != nil {
		return err
	}
	timeout, err := parseDuration(*timeoutText)
	if err != nil || timeout <= 0 {
		return usagef("receive", "--timeout is a duration like 10m or 1h")
	}
	interval, err := parseDuration(*intervalText)
	if err != nil || interval < 2*time.Second {
		return usagef("receive", "--interval is at least 2s")
	}

	code, seed, err := receiveKey(a, positional, *accessLinkFile)
	if err != nil {
		return err
	}
	client, err := a.client()
	if err != nil {
		return err
	}

	deadline := a.Now().Add(timeout)
	var page *credenshare.SubmissionPage
	for waited := false; ; waited = true {
		page, err = client.ListSubmissions(ctx, code)
		var apiErr *credenshare.APIError
		switch {
		case err == nil && (len(page.Submissions) > 0 || !*wait):
		case err == nil, *wait && errors.Is(err, credenshare.ErrRateLimited):
			if !a.Now().Before(deadline) {
				return &notFoundError{fmt.Sprintf("nothing was submitted to %s within %s", code, timeout)}
			}
			if !waited {
				out.note("Waiting for a submission to %s (up to %s)…", code, timeout)
			}
			pause := interval
			if errors.As(err, &apiErr) && apiErr.RetryAfter > 0 {
				pause = time.Duration(apiErr.RetryAfter) * time.Second
			}
			if err := a.Sleep(ctx, pause); err != nil {
				return err
			}
			continue
		default:
			return err
		}
		break
	}

	type received struct {
		CreatedAt string              `json:"created_at"`
		Fields    []credenshare.Field `json:"fields"`
	}
	submissions := make([]received, 0, len(page.Submissions))
	for i, submission := range page.Submissions {
		fields, err := submission.Decrypt(seed)
		if err != nil {
			return fmt.Errorf("submission %d to %s could not be opened with this key; is it the "+
				"key for this request? (%w)", i+1, code, err)
		}
		submissions = append(submissions, received{CreatedAt: submission.CreatedAt, Fields: fields})
	}
	sort.SliceStable(submissions, func(i, j int) bool {
		return earlier(submissions[i].CreatedAt, submissions[j].CreatedAt)
	})
	if page.SkippedNotEndToEndEncrypted > 0 {
		out.note("%d older submission(s) were not end-to-end encrypted, so the API does not "+
			"return them; they are in the app.", page.SkippedNotEndToEndEncrypted)
	}

	if *fieldName != "" {
		if len(submissions) == 0 {
			return &notFoundError{fmt.Sprintf("nothing has been submitted to %s yet", code)}
		}
		newest := submissions[len(submissions)-1]
		field, ok := findField(newest.Fields, *fieldName)
		if !ok {
			names := make([]string, len(newest.Fields))
			for i, f := range newest.Fields {
				names[i] = fmt.Sprintf("%q", f.Key)
			}
			return &notFoundError{fmt.Sprintf("the newest submission has no field %q; it has %s",
				*fieldName, strings.Join(names, ", "))}
		}
		return out.emit(map[string]any{
			"short_code": code, "created_at": newest.CreatedAt, "key": field.Key, "value": field.Value,
		}, func(o *output) {
			fmt.Fprintln(o.stdout, field.Value)
		})
	}

	return out.emit(map[string]any{
		"short_code":  code,
		"submissions": submissions,
	}, func(o *output) {
		if len(submissions) == 0 {
			o.note("Nothing has been submitted to %s yet.", code)
			return
		}
		for i, s := range submissions {
			if i > 0 {
				fmt.Fprintln(o.stdout)
			}
			fmt.Fprintf(o.stdout, "Submission %d of %d, received %s\n", i+1, len(submissions), s.CreatedAt)
			for _, f := range s.Fields {
				printField(o, f)
			}
		}
	})
}

// receiveKey finds the request's code and seed: from an access link when one is given,
// otherwise from the keychain entry made when the request was created here.
func receiveKey(a *App, positional []string, accessLinkFile string) (string, []byte, error) {
	if len(positional) > 1 {
		return "", nil, usagef("receive", "receive takes one request code")
	}
	if accessLinkFile != "" {
		var (
			text string
			err  error
		)
		if accessLinkFile == "-" {
			text, err = readLimited(a.Stdin, "stdin")
		} else {
			var raw []byte
			raw, err = os.ReadFile(accessLinkFile)
			text = string(raw)
		}
		if err != nil {
			return "", nil, fmt.Errorf("reading the access link: %w", err)
		}
		code, seed, err := parseAccessLink(text)
		if err != nil {
			return "", nil, usagef("receive", "%v", err)
		}
		if len(positional) == 1 && positional[0] != code {
			return "", nil, usagef("receive", "the access link is for request %s, not %s", code, positional[0])
		}
		return code, seed, nil
	}
	if len(positional) == 0 {
		return "", nil, usagef("receive", "receive needs a request code")
	}
	code, err := shortCode("receive", positional[0])
	if err != nil {
		return "", nil, err
	}
	stored, err := a.Keyring.Get(seedAccount(a.apiURL(), code))
	if errors.Is(err, errSecretNotFound) {
		return "", nil, &notFoundError{fmt.Sprintf("this keychain has no key for request %s. A request "+
			"made in the app or on another machine needs its access link: --access-link-file", code)}
	}
	if err != nil {
		return "", nil, fmt.Errorf("%w (%v); use --access-link-file", errKeychain, err)
	}
	seed, err := decodeSeed(stored)
	if err != nil {
		return "", nil, err
	}
	return code, seed, nil
}

func findField(fields []credenshare.Field, name string) (credenshare.Field, bool) {
	for _, f := range fields {
		if f.Key == name {
			return f, true
		}
	}
	for _, f := range fields {
		if strings.EqualFold(f.Key, name) {
			return f, true
		}
	}
	return credenshare.Field{}, false
}

func printField(o *output, f credenshare.Field) {
	value := strings.TrimRight(f.Value, "\r\n")
	if !strings.Contains(value, "\n") {
		fmt.Fprintf(o.stdout, "  %s: %s\n", f.Key, value)
		return
	}
	fmt.Fprintf(o.stdout, "  %s:\n", f.Key)
	for _, line := range strings.Split(value, "\n") {
		fmt.Fprintf(o.stdout, "    %s\n", strings.TrimRight(line, "\r"))
	}
}

// earlier orders the API's timestamps, parsing them when it can.
func earlier(a, b string) bool {
	ta, errA := time.Parse(time.RFC3339Nano, a)
	tb, errB := time.Parse(time.RFC3339Nano, b)
	if errA == nil && errB == nil {
		return ta.Before(tb)
	}
	return a < b
}
