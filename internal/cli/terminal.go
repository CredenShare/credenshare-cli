package cli

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"golang.org/x/term"
)

// A Terminal is the person at the keyboard.
//
// Prompts read from the controlling terminal rather than from stdin, so a value can be piped
// in while a passcode is still typed by hand.
type Terminal interface {
	StdinIsTerminal() bool
	StderrIsTerminal() bool
	// ReadSecret prompts and reads one line without echoing it.
	ReadSecret(ctx context.Context, prompt string) (string, error)
	// ReadLine prompts and reads one line, echoed.
	ReadLine(ctx context.Context, prompt string) (string, error)
}

var errNoTerminal = errors.New("there is no terminal to ask on")

type systemTerminal struct{}

func (systemTerminal) StdinIsTerminal() bool  { return term.IsTerminal(int(os.Stdin.Fd())) }
func (systemTerminal) StderrIsTerminal() bool { return term.IsTerminal(int(os.Stderr.Fd())) }

func (systemTerminal) ReadSecret(ctx context.Context, prompt string) (string, error) {
	in, out, closeTTY, err := openTTY()
	if err != nil {
		return "", errNoTerminal
	}
	defer closeTTY()
	fd := int(in.Fd())
	if !term.IsTerminal(fd) {
		return "", errNoTerminal
	}

	// ReadPassword turns echo off and restores it when it returns, but Ctrl+C would otherwise
	// end the process with echo still off and leave the shell typing blind.
	state, err := term.GetState(fd)
	if err != nil {
		return "", errNoTerminal
	}
	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-ctx.Done():
			_ = term.Restore(fd, state)
			fmt.Fprintln(out)
			os.Exit(exitInterrupted)
		case <-done:
		}
	}()

	fmt.Fprint(out, prompt)
	value, err := term.ReadPassword(fd)
	fmt.Fprintln(out)
	if err != nil {
		return "", fmt.Errorf("reading from the terminal: %w", err)
	}
	return string(value), nil
}

func (systemTerminal) ReadLine(_ context.Context, prompt string) (string, error) {
	in, out, closeTTY, err := openTTY()
	if err != nil {
		return "", errNoTerminal
	}
	defer closeTTY()
	if !term.IsTerminal(int(in.Fd())) {
		return "", errNoTerminal
	}
	fmt.Fprint(out, prompt)
	line, err := bufio.NewReader(in).ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return "", fmt.Errorf("reading from the terminal: %w", err)
	}
	return strings.TrimRight(line, "\r\n"), nil
}

// confirm asks a yes/no question, defaulting to no. Without a terminal it refuses and names
// the flag that answers it in advance, because a script must never hang on a prompt.
func confirm(ctx context.Context, a *App, cmd, question string) error {
	answer, err := a.Terminal.ReadLine(ctx, question+" [y/N] ")
	if errors.Is(err, errNoTerminal) {
		return usagef(cmd, "this cannot be undone, and there is no terminal to confirm it on; pass --yes")
	}
	if err != nil {
		return err
	}
	switch strings.ToLower(strings.TrimSpace(answer)) {
	case "y", "yes":
		return nil
	}
	return usagef("", "nothing was changed")
}
