package cli

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/url"
	"runtime"
	"strings"

	credenshare "github.com/CredenShare/credenshare-sdk-go"
)

// Exit codes. Stable: scripts branch on them.
const (
	exitOK          = 0
	exitUsage       = 1 // bad usage, or a problem on this machine (a file, the keychain)
	exitAuth        = 2 // not signed in, or the key was refused
	exitNotFound    = 3 // no such share or request, or nothing arrived in time
	exitRefused     = 4 // refused by the plan, the key's scopes, or the team's sharing policy
	exitServer      = 5 // the network or the server
	exitInterrupted = 130
)

type command struct {
	name    string
	summary string
	help    string
	run     func(ctx context.Context, a *App, out *output, args []string) error
}

func commands() []command {
	return []command{
		authCommand, shareCommand, requestCommand, receiveCommand, listCommand,
		showCommand, auditCommand, expireCommand, statsCommand, capabilitiesCommand,
		generateCommand, selfCheckCommand, versionCommand,
	}
}

func findCommand(name string) (command, bool) {
	for _, c := range commands() {
		if c.name == name {
			return c, true
		}
	}
	return command{}, false
}

// Run runs one invocation and returns its exit code.
func (a *App) Run(ctx context.Context, args []string) int {
	args, asJSON := takeJSONFlag(args)
	out := &output{json: asJSON, stdout: a.Stdout, stderr: a.Stderr}

	err := a.dispatch(ctx, out, args)
	if err == nil || errors.Is(err, errHelpShown) {
		return exitOK
	}
	var reported silentExit
	if errors.As(err, &reported) {
		return int(reported)
	}

	code := exitCodeFor(err)
	message := describe(err)
	fmt.Fprintln(a.Stderr, "credenshare: "+message)
	var usage *usageError
	if errors.As(err, &usage) && usage.command != "" {
		fmt.Fprintf(a.Stderr, "Run `credenshare %s --help` for its usage.\n", usage.command)
	}
	if asJSON {
		out.writeJSON(map[string]any{"error": jsonErrorFor(err, message, code)})
	}
	return code
}

func (a *App) dispatch(ctx context.Context, out *output, args []string) error {
	if len(args) == 0 {
		fmt.Fprint(out.stdout, topLevelHelp())
		return nil
	}
	switch args[0] {
	case "-h", "--help", "help":
		if len(args) > 1 {
			if c, ok := findCommand(args[1]); ok {
				fmt.Fprint(out.stdout, c.help)
				return nil
			}
			return usagef("", "no command named %q", args[1])
		}
		fmt.Fprint(out.stdout, topLevelHelp())
		return nil
	case "-v", "--version":
		return versionCommand.run(ctx, a, out, nil)
	}
	c, ok := findCommand(args[0])
	if !ok {
		return usagef("", "no command named %q; run `credenshare help` for the list", args[0])
	}
	return c.run(ctx, a, out, args[1:])
}

func topLevelHelp() string {
	var b strings.Builder
	b.WriteString("credenshare: create and manage CredenShare shares and secure requests.\n\n")
	b.WriteString("Content is encrypted on this machine before it is sent; CredenShare cannot read it.\n\n")
	b.WriteString("Usage:\n  credenshare <command> [flags]\n\nCommands:\n")
	for _, c := range commands() {
		fmt.Fprintf(&b, "  %-13s %s\n", c.name, c.summary)
	}
	b.WriteString(`
Every command takes --json for output a script can parse.

Environment:
  CREDENSHARE_API_KEY      an API key; overrides the keychain (for CI)
  CREDENSHARE_API_URL      another API address (default ` + credenshare.DefaultBaseURL + `)
  CREDENSHARE_LINK_ORIGIN  where links point (default: a team key's custom domain when its team has
                           one, otherwise ` + credenshare.DefaultLinkOrigin + `)

Exit codes:
  0  done
  1  usage, or a problem on this machine (a file, the keychain)
  2  not signed in, or the key was refused
  3  no such share or request, or nothing arrived in time
  4  refused by the plan, the key's scopes or the team's sharing policy
  5  the network or the server

Run ` + "`credenshare help <command>`" + ` for a command's flags.
`)
	return b.String()
}

const versionHelp = "Usage: credenshare version\n\nPrints this program's version and the SDK it was built with.\n"

var versionCommand = command{
	name:    "version",
	summary: "Print the version",
	help:    versionHelp,
	run: func(_ context.Context, _ *App, out *output, args []string) error {
		if err := noArguments("version", versionHelp, out, args); err != nil {
			return err
		}
		return out.emit(map[string]string{
			"version": version(),
			"sdk":     credenshare.Version,
			"go":      runtime.Version(),
			"os":      runtime.GOOS,
			"arch":    runtime.GOARCH,
		}, func(o *output) {
			fmt.Fprintf(o.stdout, "credenshare %s (sdk %s, %s, %s/%s)\n",
				version(), credenshare.Version, runtime.Version(), runtime.GOOS, runtime.GOARCH)
		})
	},
}

// takeJSONFlag removes --json from anywhere before a "--", so every command accepts it in any
// position without each one declaring it.
func takeJSONFlag(args []string) ([]string, bool) {
	kept := make([]string, 0, len(args))
	found := false
	for i, arg := range args {
		if arg == "--" {
			kept = append(kept, args[i:]...)
			break
		}
		if arg == "--json" || arg == "-json" {
			found = true
			continue
		}
		kept = append(kept, arg)
	}
	return kept, found
}

// Error kinds this package raises itself. The SDK's sentinels cover everything the API says.
type usageError struct {
	command string
	message string
}

func (e *usageError) Error() string { return e.message }

func usagef(command, format string, args ...any) error {
	return &usageError{command: command, message: fmt.Sprintf(format, args...)}
}

type authError struct{ err error }

func (e *authError) Error() string { return e.err.Error() }
func (e *authError) Unwrap() error { return e.err }

type notFoundError struct{ message string }

func (e *notFoundError) Error() string { return e.message }

// silentExit is an exit code whose reason has already been printed.
type silentExit int

func (e silentExit) Error() string { return fmt.Sprintf("exit %d", int(e)) }

var (
	errHelpShown = errors.New("help shown")
	errKeychain  = errors.New("the system keychain is not available")
)

func exitCodeFor(err error) int {
	var (
		usage    *usageError
		auth     *authError
		notFound *notFoundError
		apiErr   *credenshare.APIError
		urlErr   *url.Error
		opErr    *net.OpError
	)
	switch {
	case errors.Is(err, context.Canceled):
		return exitInterrupted
	case errors.As(err, &usage):
		return exitUsage
	case errors.As(err, &auth), errors.Is(err, errNotSignedIn),
		errors.Is(err, credenshare.ErrAuthentication):
		return exitAuth
	case errors.As(err, &notFound), errors.Is(err, credenshare.ErrNotFound):
		return exitNotFound
	case errors.Is(err, credenshare.ErrPermission), errors.Is(err, credenshare.ErrQuotaExceeded):
		return exitRefused
	case errors.Is(err, credenshare.ErrRateLimited),
		errors.Is(err, credenshare.ErrServiceUnavailable),
		errors.Is(err, credenshare.ErrDeliveryUnknown),
		errors.Is(err, context.DeadlineExceeded),
		// Not net.Error: syscall.Errno satisfies it, so "file exists" would read as a network
		// failure.
		errors.As(err, &urlErr), errors.As(err, &opErr):
		return exitServer
	case errors.As(err, &apiErr) && apiErr.Status >= 500:
		return exitServer
	}
	return exitUsage
}

// teamPolicyCode is the API's error code for a share or request the team's sharing policy
// refuses. Its message already says what the policy requires, so nothing is added to it.
const teamPolicyCode = 145

func describe(err error) string {
	message := err.Error()
	var apiErr *credenshare.APIError
	switch {
	case errors.Is(err, context.Canceled):
		return "interrupted"
	case errors.Is(err, credenshare.ErrDeliveryUnknown):
		return message + ". The request may have reached CredenShare: check with " +
			"`credenshare list` before trying again"
	case errors.Is(err, credenshare.ErrQuotaExceeded):
		return message + ". The plan's allowance is spent; expire old shares or change plan"
	case errors.As(err, &apiErr) && errors.Is(err, credenshare.ErrRateLimited) && apiErr.RetryAfter > 0:
		return fmt.Sprintf("%s. Try again in %d seconds", message, apiErr.RetryAfter)
	case errors.As(err, &apiErr) && errors.Is(err, credenshare.ErrPermission) &&
		apiErr.Code != teamPolicyCode:
		return message + ". API keys work on Business and Enterprise plans, and each " +
			"command needs its scope on the key (shares:write to share, requests:read to receive…)"
	case errors.Is(err, credenshare.ErrAuthentication):
		return message + ". The key is unknown, revoked or expired; create a new one in " +
			"the app and run `credenshare auth login`"
	}
	return message
}

func jsonErrorFor(err error, message string, code int) map[string]any {
	body := map[string]any{"message": message, "exit_code": code}
	var apiErr *credenshare.APIError
	if errors.As(err, &apiErr) {
		body["status"] = apiErr.Status
		if apiErr.Code != 0 {
			body["code"] = apiErr.Code
		}
		if apiErr.RequestID != "" {
			body["request_id"] = apiErr.RequestID
		}
		if apiErr.RetryAfter > 0 {
			body["retry_after"] = apiErr.RetryAfter
		}
	}
	return body
}
