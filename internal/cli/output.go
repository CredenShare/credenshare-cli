package cli

import (
	"encoding/json"
	"fmt"
	"io"
)

// output is where a command writes.
//
// The result goes to stdout and nothing else does, so `LINK=$(credenshare share …)` captures
// exactly the link. Notes for a person — what was created, what to do next — go to stderr,
// and only in text mode: with --json, stdout carries one JSON document and stderr stays quiet
// unless something fails.
type output struct {
	json   bool
	stdout io.Writer
	stderr io.Writer
}

// emit writes the result: v as JSON with --json, otherwise whatever text writes.
func (o *output) emit(v any, text func(*output)) error {
	if o.json {
		return o.writeJSON(v)
	}
	text(o)
	return nil
}

func (o *output) writeJSON(v any) error {
	encoder := json.NewEncoder(o.stdout)
	encoder.SetIndent("", "  ")
	// A secret containing <, > or & must come out as itself, not as <.
	encoder.SetEscapeHTML(false)
	return encoder.Encode(v)
}

// note tells the person at the terminal something. Silent with --json.
func (o *output) note(format string, args ...any) {
	if o.json {
		return
	}
	fmt.Fprintf(o.stderr, format+"\n", args...)
}
