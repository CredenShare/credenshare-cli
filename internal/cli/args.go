package cli

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"regexp"
	"strconv"
	"strings"
	"time"
)

func newFlagSet(name string) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	// Errors are reported once, by Run, in the same shape as every other error.
	fs.SetOutput(io.Discard)
	fs.Usage = func() {}
	return fs
}

// parseArgs parses flags wherever they appear, so `receive CODE --wait` works as well as
// `receive --wait CODE`. The standard library stops at the first positional argument; this
// keeps going. Everything after a bare "--" is positional.
func parseArgs(fs *flag.FlagSet, name, help string, out *output, args []string) ([]string, error) {
	var rest []string
	for i, arg := range args {
		if arg == "--" {
			rest = args[i+1:]
			args = args[:i]
			break
		}
	}
	var positional []string
	for {
		if err := fs.Parse(args); err != nil {
			if errors.Is(err, flag.ErrHelp) {
				fmt.Fprint(out.stdout, help)
				return nil, errHelpShown
			}
			return nil, usagef(name, "%v", err)
		}
		args = fs.Args()
		if len(args) == 0 {
			break
		}
		positional = append(positional, args[0])
		args = args[1:]
	}
	return append(positional, rest...), nil
}

// shortCodePattern is what a share's or request's short code looks like.
var shortCodePattern = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)

// shortCode checks a code argument before it becomes part of a URL path: an empty one would
// address the collection instead of an item, and a slash another endpoint.
func shortCode(cmd, text string) (string, error) {
	code := strings.TrimSpace(text)
	if !shortCodePattern.MatchString(code) {
		return "", usagef(cmd, "%q is not a short code", text)
	}
	return code, nil
}

// stringList is a repeatable string flag.
type stringList []string

func (l *stringList) String() string { return strings.Join(*l, ",") }

func (l *stringList) Set(value string) error {
	*l = append(*l, value)
	return nil
}

// parseDuration accepts what Go does, plus d for days and w for weeks, which is how people
// write expiries.
func parseDuration(text string) (time.Duration, error) {
	text = strings.TrimSpace(text)
	if text == "" {
		return 0, fmt.Errorf("empty duration")
	}
	unit := text[len(text)-1]
	if unit == 'd' || unit == 'w' {
		count, err := strconv.Atoi(text[:len(text)-1])
		if err != nil {
			return 0, fmt.Errorf("%q is not a duration like 30m, 24h, 7d or 2w", text)
		}
		day := 24 * time.Hour
		if unit == 'w' {
			day *= 7
		}
		return time.Duration(count) * day, nil
	}
	d, err := time.ParseDuration(text)
	if err != nil {
		return 0, fmt.Errorf("%q is not a duration like 30m, 24h, 7d or 2w", text)
	}
	return d, nil
}

// expiryAt turns --expires into the API's timestamp: a duration from now, or an RFC 3339 time.
func expiryAt(text string, now time.Time) (string, error) {
	if at, err := time.Parse(time.RFC3339, strings.TrimSpace(text)); err == nil {
		if !at.After(now) {
			return "", fmt.Errorf("--expires %s is in the past", text)
		}
		return at.UTC().Format(time.RFC3339), nil
	}
	d, err := parseDuration(text)
	if err != nil {
		return "", fmt.Errorf("--expires: %w, or a time like 2026-12-31T23:00:00Z", err)
	}
	if d <= 0 {
		return "", fmt.Errorf("--expires must be in the future")
	}
	return now.Add(d).UTC().Format(time.RFC3339), nil
}

// flagWasSet reports whether a flag was given, so a default can be told apart from a value.
func flagWasSet(fs *flag.FlagSet, name string) bool {
	set := false
	fs.Visit(func(f *flag.Flag) {
		if f.Name == name {
			set = true
		}
	})
	return set
}
