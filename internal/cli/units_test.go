package cli

import (
	"math"
	"strings"
	"testing"
	"time"
	"unicode"
)

func TestParseArgsTakesFlagsAnywhere(t *testing.T) {
	out := &output{stdout: &strings.Builder{}, stderr: &strings.Builder{}}
	fs := newFlagSet("x")
	wait := fs.Bool("wait", false, "")
	field := fs.String("field", "", "")
	positional, err := parseArgs(fs, "x", "", out, []string{"CODE", "--wait", "--field", "A", "--", "--literal"})
	if err != nil {
		t.Fatal(err)
	}
	if !*wait || *field != "A" || strings.Join(positional, " ") != "CODE --literal" {
		t.Fatalf("wait %v field %q positional %v", *wait, *field, positional)
	}
}

func TestTakeJSONFlag(t *testing.T) {
	args, found := takeJSONFlag([]string{"list", "--json", "--", "--json"})
	if !found || strings.Join(args, " ") != "list -- --json" {
		t.Fatalf("%v %v", args, found)
	}
}

func TestDurationsAndExpiry(t *testing.T) {
	now := time.Date(2026, 10, 25, 12, 0, 0, 0, time.UTC)
	for text, want := range map[string]string{
		"30m":                       "2026-10-25T12:30:00Z",
		"24h":                       "2026-10-26T12:00:00Z",
		"7d":                        "2026-11-01T12:00:00Z",
		"2w":                        "2026-11-08T12:00:00Z",
		"2026-12-31T23:00:00Z":      "2026-12-31T23:00:00Z",
		"2026-12-31T18:00:00-05:00": "2026-12-31T23:00:00Z",
	} {
		got, err := expiryAt(text, now)
		if err != nil || got != want {
			t.Errorf("expiryAt(%q) = %q, %v; want %q", text, got, err, want)
		}
	}
	for _, bad := range []string{"", "soon", "7.5d", "-1d", "0s", "2020-01-01T00:00:00Z", "d"} {
		if _, err := expiryAt(bad, now); err == nil {
			t.Errorf("expiryAt(%q) accepted", bad)
		}
	}
}

func TestSplitType(t *testing.T) {
	for spec, want := range map[string][2]string{
		"Password":              {"Password", ""},
		"Private key:multiline": {"Private key", "multiline"},
		"Note: staging":         {"Note: staging", ""},
		"Site:url":              {"Site", "url"},
		" Spaced : password ":   {"Spaced", "password"},
	} {
		label, typ := splitType(spec)
		if label != want[0] || typ != want[1] {
			t.Errorf("splitType(%q) = %q, %q", spec, label, typ)
		}
	}
}

func TestFieldTypeGuess(t *testing.T) {
	if fieldType("", "one line\n") != "password" || fieldType("", "a\nb") != "multiline" ||
		fieldType("qr", "a\nb") != "qr" {
		t.Fatal("wrong guess")
	}
}

func TestParseAccessLink(t *testing.T) {
	seed := make([]byte, 32)
	seed[0] = 7
	code, got, err := parseAccessLink("https://crs.sh/r/AbC123#1" + encodeSeed(seed) + "\n")
	if err != nil || code != "AbC123" || got[0] != 7 {
		t.Fatalf("%q %v %v", code, got, err)
	}
	for _, bad := range []string{
		"https://crs.sh/AbC123#1" + encodeSeed(seed),
		"https://crs.sh/r/AbC123",
		"https://crs.sh/r/#1" + encodeSeed(seed),
		"https://crs.sh/r/AbC123#1short",
	} {
		if _, _, err := parseAccessLink(bad); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
}

func TestGenerate(t *testing.T) {
	h := newHarness(t)

	h.mustRun("", "generate", "--json")
	got := h.jsonOut()
	value := got["value"].(string)
	if len([]rune(value)) != 20 || got["strength"] != "Very Strong" || got["bits"] != 131.1 {
		t.Fatalf("password %v", got)
	}

	h.mustRun("", "generate", "--length", "64", "--no-symbols", "--no-uppercase", "--exclude", "0123456789")
	value = strings.TrimSpace(h.stdout.String())
	for _, r := range value {
		if !unicode.IsLower(r) {
			t.Fatalf("%q has %q", value, r)
		}
	}

	h.mustRun("", "generate", "passphrase", "--words", "6", "--separator", "space", "--number", "--json")
	got = h.jsonOut()
	words := strings.Split(got["value"].(string), " ")
	digits := 0
	for _, r := range got["value"].(string) {
		if unicode.IsDigit(r) {
			digits++
		}
	}
	wantBits := 6*math.Log2(7776) + math.Log2(10) + math.Log2(6)
	if len(words) != 6 || digits != 1 || got["bits"] != math.Round(wantBits*10)/10 {
		t.Fatalf("passphrase %v", got)
	}

	h.mustRun("", "generate", "pin", "--length", "8")
	pin := strings.TrimSpace(h.stdout.String())
	if len(pin) != 8 || strings.Trim(pin, "0123456789") != "" {
		t.Fatalf("pin %q", pin)
	}

	for _, bad := range [][]string{
		{"generate", "pin", "--words", "4"},
		{"generate", "--length", "7"},
		{"generate", "passphrase", "--words", "13"},
		{"generate", "--no-uppercase", "--no-lowercase", "--no-numbers", "--no-symbols"},
		{"generate", "token"},
	} {
		if code := h.run("", bad...); code != exitUsage {
			t.Errorf("%v exited %d", bad, code)
		}
	}
	if h.api.calls != 0 {
		t.Fatal("generate used the network")
	}
}
