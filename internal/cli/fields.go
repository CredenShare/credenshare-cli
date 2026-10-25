package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"unicode/utf8"

	credenshare "github.com/CredenShare/credenshare-sdk-go"
)

// maxValueBytes bounds one field read from a file or stdin. The API has its own, lower,
// limits per plan; this only stops a mistaken path from reading a disk image into memory.
const maxValueBytes = 10 << 20

// A fieldSpec is one field to collect: its label, its type, and where its value comes from.
type fieldSpec struct {
	label string
	typ   string // empty: inferred from the value
	path  string // "" prompts (or reads stdin); "-" is stdin; anything else is a file
}

// splitType takes a trailing ":type" off a label, but only for a type the recipient view
// knows, so a label such as "Note: staging" stays whole.
func splitType(spec string) (label, typ string) {
	if i := strings.LastIndex(spec, ":"); i >= 0 {
		candidate := strings.TrimSpace(spec[i+1:])
		for _, known := range credenshare.FieldTypes {
			if candidate == known {
				return strings.TrimSpace(spec[:i]), candidate
			}
		}
	}
	return strings.TrimSpace(spec), ""
}

// fieldFlag is --field LABEL[:TYPE]: a value to be asked for, or read from stdin.
type fieldFlag struct{ specs *[]fieldSpec }

func (f fieldFlag) String() string { return "" }

func (f fieldFlag) Set(value string) error {
	label, typ := splitType(value)
	if label == "" {
		return fmt.Errorf("a field needs a label")
	}
	*f.specs = append(*f.specs, fieldSpec{label: label, typ: typ})
	return nil
}

// fileFlag is --file LABEL[:TYPE]=PATH: a value read from a file, or from stdin with "-".
type fileFlag struct{ specs *[]fieldSpec }

func (f fileFlag) String() string { return "" }

func (f fileFlag) Set(value string) error {
	i := strings.Index(value, "=")
	if i < 0 {
		return fmt.Errorf("--file is LABEL=PATH, as in --file \"Private key=./key.pem\"")
	}
	label, typ := splitType(value[:i])
	path := strings.TrimSpace(value[i+1:])
	if label == "" || path == "" {
		return fmt.Errorf("--file is LABEL=PATH, as in --file \"Private key=./key.pem\"")
	}
	*f.specs = append(*f.specs, fieldSpec{label: label, typ: typ, path: path})
	return nil
}

// readFields collects every value. At most one field may come from stdin: a single --field
// when stdin is a pipe, or a --file whose path is "-". The others are asked for at the
// terminal, hidden.
func readFields(ctx context.Context, a *App, cmd string, specs []fieldSpec) ([]credenshare.Field, error) {
	stdinPiped := !a.Terminal.StdinIsTerminal()
	stdinUsers := 0
	for i := range specs {
		if specs[i].path == "-" {
			stdinUsers++
		}
	}
	prompts := len(specs) - countFiles(specs)
	if stdinPiped && stdinUsers == 0 && prompts == 1 {
		for i := range specs {
			if specs[i].path == "" {
				specs[i].path = "-"
				stdinUsers++
			}
		}
	}
	if stdinUsers > 1 {
		return nil, usagef(cmd, "only one value can come from stdin; give the others with --file")
	}

	fields := make([]credenshare.Field, 0, len(specs))
	for _, spec := range specs {
		value, err := readValue(ctx, a, cmd, spec)
		if err != nil {
			return nil, err
		}
		if value == "" {
			return nil, usagef(cmd, "the value for %q is empty", spec.label)
		}
		if !utf8.ValidString(value) {
			return nil, usagef(cmd, "the value for %q is not text; a share holds text fields, so "+
				"encode a binary file first (base64 key.der)", spec.label)
		}
		fields = append(fields, credenshare.Field{
			Key: spec.label, Value: value, Type: fieldType(spec.typ, value),
		})
	}
	return fields, nil
}

func countFiles(specs []fieldSpec) int {
	n := 0
	for _, spec := range specs {
		if spec.path != "" {
			n++
		}
	}
	return n
}

func readValue(ctx context.Context, a *App, cmd string, spec fieldSpec) (string, error) {
	switch spec.path {
	case "":
		value, err := a.Terminal.ReadSecret(ctx, spec.label+": ")
		if errors.Is(err, errNoTerminal) {
			return "", usagef(cmd, "there is no terminal to ask for %q on; pipe it on stdin or use --file", spec.label)
		}
		return value, err
	case "-":
		value, err := readLimited(a.Stdin, "stdin")
		if err != nil {
			return "", err
		}
		// `echo secret | credenshare share` should share "secret", not "secret\n".
		value = strings.TrimSuffix(value, "\n")
		return strings.TrimSuffix(value, "\r"), nil
	}
	file, err := os.Open(spec.path)
	if err != nil {
		return "", fmt.Errorf("reading %q for %q: %w", spec.path, spec.label, err)
	}
	defer file.Close()
	return readLimited(file, spec.path)
}

func readLimited(r io.Reader, name string) (string, error) {
	raw, err := io.ReadAll(io.LimitReader(r, maxValueBytes+1))
	if err != nil {
		return "", fmt.Errorf("reading %s: %w", name, err)
	}
	if len(raw) > maxValueBytes {
		return "", fmt.Errorf("%s is larger than %d MiB", name, maxValueBytes>>20)
	}
	return string(raw), nil
}

// fieldType is the given type, or a guess: several lines read best as multiline text, and a
// single line is treated as a password, which the recipient sees masked until they reveal it.
func fieldType(given, value string) string {
	if given != "" {
		return given
	}
	if strings.Contains(strings.TrimRight(value, "\r\n"), "\n") {
		return "multiline"
	}
	return "password"
}

// readPasscode reads --passcode-file when a path is given, or asks twice at the terminal when
// ask is set. The caller refuses both at once.
func readPasscode(ctx context.Context, a *App, cmd string, ask bool, path string) (string, error) {
	if path != "" {
		file, err := os.Open(path)
		if err != nil {
			return "", fmt.Errorf("reading the passcode file: %w", err)
		}
		defer file.Close()
		raw, err := io.ReadAll(io.LimitReader(file, maxSecretInput))
		if err != nil {
			return "", fmt.Errorf("reading the passcode file: %w", err)
		}
		passcode := strings.TrimRight(string(raw), "\r\n")
		if passcode == "" {
			return "", usagef(cmd, "the passcode file is empty")
		}
		return passcode, nil
	}
	if !ask {
		return "", nil
	}
	first, err := a.Terminal.ReadSecret(ctx, "Passcode: ")
	if errors.Is(err, errNoTerminal) {
		return "", usagef(cmd, "there is no terminal to ask for the passcode on; use --passcode-file")
	}
	if err != nil {
		return "", err
	}
	if first == "" {
		return "", usagef(cmd, "the passcode is empty")
	}
	second, err := a.Terminal.ReadSecret(ctx, "Passcode again: ")
	if err != nil {
		return "", err
	}
	if first != second {
		return "", usagef(cmd, "the two passcodes are different")
	}
	return first, nil
}
