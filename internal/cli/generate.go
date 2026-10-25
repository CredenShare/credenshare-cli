package cli

import (
	"context"
	"crypto/rand"
	_ "embed"
	"flag"
	"fmt"
	"math"
	"math/big"
	"strings"
	"sync"
	"unicode"

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

// The character sets of the app's generator, symbols included, so the two produce the same
// kind of password and report the same strength for it.
const (
	upperChars  = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	lowerChars  = "abcdefghijklmnopqrstuvwxyz"
	digitChars  = "0123456789"
	symbolChars = "!@#$%^&*()_+-=[]{}|;:,.<>?`\"~/\\'"
)

var separators = map[string]string{
	"hyphen": "-", "space": " ", "period": ".", "underscore": "_", "none": "",
}

var modeFlags = map[string][]string{
	"password":   {"length", "no-uppercase", "no-lowercase", "no-numbers", "no-symbols", "exclude"},
	"passphrase": {"words", "separator", "capitalize", "number"},
	"pin":        {"length"},
}

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

	var value string
	var bits float64
	switch mode {
	case "password":
		n := 20
		if flagWasSet(fs, "length") {
			n = *length
		}
		if n < 8 || n > 128 {
			return usagef("generate", "a password is 8 to 128 characters")
		}
		pool := passwordPool(!*noUpper, !*noLower, !*noNumbers, !*noSymbols, *exclude)
		if pool == "" {
			return usagef("generate", "those options leave no characters to choose from")
		}
		if value, err = randomString(pool, n); err != nil {
			return err
		}
		bits = float64(n) * math.Log2(float64(len(pool)))
	case "passphrase":
		if *words < 3 || *words > 12 {
			return usagef("generate", "a passphrase is 3 to 12 words")
		}
		join, ok := separators[*separator]
		if !ok {
			return usagef("generate", "--separator is hyphen, space, period, underscore or none")
		}
		if value, err = passphrase(wordList(), *words, join, *capitalize, *withNumber); err != nil {
			return err
		}
		bits = passphraseBits(len(wordList()), *words, *withNumber)
	case "pin":
		n := 6
		if flagWasSet(fs, "length") {
			n = *length
		}
		if n < 4 || n > 12 {
			return usagef("generate", "a PIN is 4 to 12 digits")
		}
		if value, err = randomString(digitChars, n); err != nil {
			return err
		}
		bits = float64(n) * math.Log2(10)
	}

	strength := strengthOf(bits)
	if err := out.emit(map[string]any{
		"kind": mode, "value": value, "bits": math.Round(bits*10) / 10, "strength": strength,
	}, func(o *output) {
		fmt.Fprintln(o.stdout, value)
	}); err != nil {
		return err
	}
	if a.Terminal.StderrIsTerminal() {
		out.note("%d bits, %s", int(math.Round(bits)), strength)
	}
	return nil
}

func passwordPool(upper, lower, digits, symbols bool, exclude string) string {
	var pool strings.Builder
	for _, set := range []struct {
		on    bool
		chars string
	}{{upper, upperChars}, {lower, lowerChars}, {digits, digitChars}, {symbols, symbolChars}} {
		if !set.on {
			continue
		}
		for _, c := range set.chars {
			if !strings.ContainsRune(exclude, c) {
				pool.WriteRune(c)
			}
		}
	}
	return pool.String()
}

// randomIndex draws uniformly from [0, n). crypto/rand.Int rejection-samples, so there is no
// modulo bias: 2^32 mod 94 is not 0, and a plain % would favour the first characters.
func randomIndex(n int) (int, error) {
	v, err := rand.Int(rand.Reader, big.NewInt(int64(n)))
	if err != nil {
		return 0, fmt.Errorf("reading randomness: %w", err)
	}
	return int(v.Int64()), nil
}

func randomString(pool string, n int) (string, error) {
	chars := []rune(pool)
	var b strings.Builder
	for i := 0; i < n; i++ {
		j, err := randomIndex(len(chars))
		if err != nil {
			return "", err
		}
		b.WriteRune(chars[j])
	}
	return b.String(), nil
}

func passphrase(list []string, n int, separator string, capitalize, withNumber bool) (string, error) {
	picked := make([]string, n)
	for i := range picked {
		j, err := randomIndex(len(list))
		if err != nil {
			return "", err
		}
		word := list[j]
		if capitalize {
			runes := []rune(word)
			runes[0] = unicode.ToUpper(runes[0])
			word = string(runes)
		}
		picked[i] = word
	}
	if withNumber {
		where, err := randomIndex(n)
		if err != nil {
			return "", err
		}
		digit, err := randomIndex(10)
		if err != nil {
			return "", err
		}
		picked[where] += fmt.Sprint(digit)
	}
	return strings.Join(picked, separator), nil
}

// passphraseBits counts each word as log2 of the list; the digit adds log2(10) and its
// position log2(words). Capitals add nothing, since every word gets one.
func passphraseBits(listSize, n int, withNumber bool) float64 {
	bits := float64(n) * math.Log2(float64(listSize))
	if withNumber {
		bits += math.Log2(10) + math.Log2(float64(n))
	}
	return bits
}

// strengthOf is the app generator's label for a number of bits.
func strengthOf(bits float64) string {
	switch {
	case bits < 40:
		return "Weak"
	case bits < 60:
		return "Fair"
	case bits < 80:
		return "Strong"
	}
	return "Very Strong"
}

// The EFF long word list, byte-for-byte as the EFF publishes it (dice numbers, a tab, the
// word). By the Electronic Frontier Foundation, licensed under CC BY 3.0 US; see NOTICE.
//
//go:embed eff_large_wordlist.txt
var effLargeWordList string

var wordList = sync.OnceValue(func() []string {
	lines := strings.Split(strings.TrimSpace(effLargeWordList), "\n")
	list := make([]string, 0, len(lines))
	for _, line := range lines {
		if _, word, ok := strings.Cut(strings.TrimSpace(line), "\t"); ok {
			list = append(list, word)
		}
	}
	return list
})

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
