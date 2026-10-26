package cli

import (
	"context"
	"flag"
	"fmt"
	"math"

	credenshare "github.com/CredenShare/credenshare-sdk-go"
)

var generateCommand = command{
	name:    "generate",
	summary: "Generate a password, passphrase or PIN, offline",
	help:    generateHelp,
	run:     runGenerate,
}

const generateHelp = `Usage: credenshare generate [password|passphrase|pin] [flags]

Generates a secret on this machine, with nothing sent anywhere, the same way the app's
generator does. Prints it on stdout, and its strength on stderr when that is a terminal.

  credenshare generate
  credenshare generate passphrase --words 6 --separator space
  credenshare generate pin --length 8
  credenshare generate | credenshare share --field "Wi-Fi password"

password (the default):
  --length N         8 to 128 (default 20)
  --no-uppercase     leave out A-Z
  --no-lowercase     leave out a-z
  --no-numbers       leave out 0-9
  --no-symbols       leave out symbols
  --exclude CHARS    leave out these characters

passphrase, from the EFF long word list (7,776 words, 12.9 bits each):
  --words N          3 to 12 (default 5)
  --separator S      hyphen, space, period, underscore or none (default hyphen)
  --capitalize       capitalise each word
  --number           add one digit to one word

pin:
  --length N         4 to 12 (default 6)
`

var modeFlags = map[string][]string{
	"password":   {"length", "no-uppercase", "no-lowercase", "no-numbers", "no-symbols", "exclude"},
	"passphrase": {"words", "separator", "capitalize", "number"},
	"pin":        {"length"},
}

// runGenerate is the SDK's generator (the app's three modes, unbiased, with nothing sent anywhere) behind the
// command's flags. One implementation, in the SDK, so the CLI and every Go caller draw and score alike.
func runGenerate(_ context.Context, a *App, out *output, args []string) error {
	fs := newFlagSet("generate")
	length := fs.Int("length", 0, "")
	noUpper := fs.Bool("no-uppercase", false, "")
	noLower := fs.Bool("no-lowercase", false, "")
	noNumbers := fs.Bool("no-numbers", false, "")
	noSymbols := fs.Bool("no-symbols", false, "")
	exclude := fs.String("exclude", "", "")
	words := fs.Int("words", 5, "")
	separator := fs.String("separator", "hyphen", "")
	capitalize := fs.Bool("capitalize", false, "")
	withNumber := fs.Bool("number", false, "")
	positional, err := parseArgs(fs, "generate", generateHelp, out, args)
	if err != nil {
		return err
	}

	mode := "password"
	if len(positional) == 1 {
		mode = positional[0]
	}
	allowed, known := modeFlags[mode]
	if len(positional) > 1 || !known {
		return usagef("generate", "generate makes a password, a passphrase or a pin")
	}
	var stray string
	fs.Visit(func(f *flag.Flag) {
		for _, name := range allowed {
			if f.Name == name {
				return
			}
		}
		stray = f.Name
	})
	if stray != "" {
		return usagef("generate", "--%s does not apply to a %s", stray, mode)
	}

	var g credenshare.Generated
	switch mode {
	case "password":
		n := 20
		if flagWasSet(fs, "length") {
			n = *length
		}
		// Checked here as well as in the SDK, which reads 0 as "the default" and would let --length 0 through.
		if n < 8 || n > 128 {
			return usagef("generate", "a password is 8 to 128 characters")
		}
		g, err = credenshare.GeneratePassword(credenshare.PasswordOptions{
			Length: n, NoUppercase: *noUpper, NoLowercase: *noLower, NoNumbers: *noNumbers,
			NoSymbols: *noSymbols, Exclude: *exclude,
		})
	case "passphrase":
		if *words < 3 || *words > 12 {
			return usagef("generate", "a passphrase is 3 to 12 words")
		}
		g, err = credenshare.GeneratePassphrase(credenshare.PassphraseOptions{
			Words: *words, Separator: *separator, Capitalize: *capitalize, IncludeNumber: *withNumber,
		})
	case "pin":
		n := 6
		if flagWasSet(fs, "length") {
			n = *length
		}
		if n < 4 || n > 12 {
			return usagef("generate", "a PIN is 4 to 12 digits")
		}
		g, err = credenshare.GeneratePIN(n)
	}
	if err != nil {
		// The options the SDK refuses (no characters left, an unknown separator) are the caller's to fix.
		return usagef("generate", "%v", err)
	}

	if err := out.emit(map[string]any{
		"kind": mode, "value": g.Value, "bits": math.Round(g.Bits*10) / 10, "strength": g.Strength,
	}, func(o *output) {
		fmt.Fprintln(o.stdout, g.Value)
	}); err != nil {
		return err
	}
	if a.Terminal.StderrIsTerminal() {
		out.note("%d bits, %s", int(math.Round(g.Bits)), g.Strength)
	}
	return nil
}

var selfCheckCommand = command{
	name:    "self-check",
	summary: "Check this build's encryption against the published test vectors",
	help:    selfCheckHelp,
	run:     runSelfCheck,
}

const selfCheckHelp = `Usage: credenshare self-check

Runs the SDK's conformance vectors: the encryption in this binary must produce and read
exactly what the specification says, byte for byte. Offline. Run it once after installing,
before trusting the build with a secret.
`

func runSelfCheck(_ context.Context, _ *App, out *output, args []string) error {
	if err := noArguments("self-check", selfCheckHelp, out, args); err != nil {
		return err
	}
	passed, failures, err := credenshare.RunConformance(false, func(string) {})
	if err != nil {
		return err
	}
	names := make([]string, len(failures))
	for i, f := range failures {
		names[i] = f.Name
	}
	if err := out.emit(map[string]any{
		"passed": passed, "failed": len(failures), "failures": names,
	}, func(o *output) {
		if len(failures) == 0 {
			fmt.Fprintf(o.stdout, "All %d checks passed.\n", passed)
			return
		}
		fmt.Fprintf(o.stdout, "%d passed, %d FAILED:\n", passed, len(failures))
		for _, f := range failures {
			fmt.Fprintf(o.stdout, "  %s: %s\n", f.Name, f.Reason)
		}
	}); err != nil {
		return err
	}
	if len(failures) > 0 {
		return silentExit(exitUsage)
	}
	return nil
}
