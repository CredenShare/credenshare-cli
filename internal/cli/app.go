// Package cli is the credenshare command.
//
// Everything secret is encrypted by the Go SDK on this machine, exactly as the web app
// encrypts it, so what reaches the API is ciphertext. This package adds what a terminal needs
// around that: where the API key lives, how values get in without touching shell history, and
// output a script can rely on.
package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"runtime/debug"
	"strings"
	"time"

	credenshare "github.com/CredenShare/credenshare-sdk-go"
)

// Version is set at build time with -ldflags "-X .../internal/cli.Version=0.1.0".
var Version = "dev"

const (
	envAPIKey     = "CREDENSHARE_API_KEY"
	envAPIURL     = "CREDENSHARE_API_URL"
	envLinkOrigin = "CREDENSHARE_LINK_ORIGIN"

	sourceEnvironment = "environment"
	sourceKeychain    = "keychain"
)

// An App is one run of the command, with every outside dependency injectable so the tests can
// drive it without a terminal, a keychain or the network.
type App struct {
	Stdin  io.Reader
	Stdout io.Writer
	Stderr io.Writer

	Getenv   func(string) string
	Keyring  Keyring
	Terminal Terminal

	// HTTPClient is nil in production, which gives the SDK's default timeout.
	HTTPClient *http.Client

	Now   func() time.Time
	Sleep func(context.Context, time.Duration) error
}

// NewApp wires the real terminal, keychain and clock.
func NewApp() *App {
	return &App{
		Stdin:    os.Stdin,
		Stdout:   os.Stdout,
		Stderr:   os.Stderr,
		Getenv:   os.Getenv,
		Keyring:  systemKeyring{},
		Terminal: systemTerminal{},
		Now:      time.Now,
		Sleep:    sleepContext,
	}
}

func sleepContext(ctx context.Context, d time.Duration) error {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

// version is the build's version: the ldflags value for a release binary, the module version
// for `go install …@vX.Y.Z`, and "dev" for anything else.
func version() string {
	if Version != "dev" {
		return Version
	}
	if info, ok := debug.ReadBuildInfo(); ok {
		if v := info.Main.Version; v != "" && v != "(devel)" {
			return strings.TrimPrefix(v, "v")
		}
	}
	return Version
}

func (a *App) apiURL() string {
	if value := strings.TrimSpace(a.Getenv(envAPIURL)); value != "" {
		return strings.TrimRight(value, "/")
	}
	return credenshare.DefaultBaseURL
}

func (a *App) linkOrigin() string {
	if value := strings.TrimSpace(a.Getenv(envLinkOrigin)); value != "" {
		return strings.TrimRight(value, "/")
	}
	return credenshare.DefaultLinkOrigin
}

// errNotSignedIn is exit code 2 with the two ways out named.
var errNotSignedIn = errors.New(
	"not signed in: run `credenshare auth login`, or set " + envAPIKey,
)

// credential finds the API key: the environment first, so CI can override whatever a
// developer's keychain holds, then the keychain entry for this API address.
func (a *App) credential() (key, source string, err error) {
	if value := strings.TrimSpace(a.Getenv(envAPIKey)); value != "" {
		return value, sourceEnvironment, nil
	}
	value, err := a.Keyring.Get(apiKeyAccount(a.apiURL()))
	if errors.Is(err, errSecretNotFound) {
		return "", "", errNotSignedIn
	}
	if err != nil {
		return "", "", &authError{fmt.Errorf(
			"%w (%v); set %s instead", errKeychain, err, envAPIKey,
		)}
	}
	return value, sourceKeychain, nil
}

func (a *App) client() (*credenshare.Client, error) {
	key, source, err := a.credential()
	if err != nil {
		return nil, err
	}
	client, err := a.clientFor(key)
	if err != nil {
		return nil, fmt.Errorf("the API key in the %s: %w", source, err)
	}
	return client, nil
}

// clientFor builds an SDK client for a key. A key that is not in the credential format comes
// back as an authError, so it exits 2 like any other refused key.
func (a *App) clientFor(key string) (*credenshare.Client, error) {
	httpClient := &http.Client{Timeout: credenshare.DefaultTimeout}
	if a.HTTPClient != nil {
		copied := *a.HTTPClient
		httpClient = &copied
	}
	next := httpClient.Transport
	if next == nil {
		next = http.DefaultTransport
	}
	httpClient.Transport = userAgentTransport{next: next}

	client, err := credenshare.New(key, &credenshare.Options{
		BaseURL:    a.apiURL(),
		LinkOrigin: a.linkOrigin(),
		HTTPClient: httpClient,
	})
	if err != nil {
		return nil, &authError{fmt.Errorf(
			"this is not a CredenShare API key (they start with crs_sk_live_): %w", err,
		)}
	}
	return client, nil
}

// userAgentTransport adds this program to the SDK's User-Agent, so a support request can be
// matched to the CLI version that made it. Nothing else is added: no telemetry.
type userAgentTransport struct{ next http.RoundTripper }

func (t userAgentTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	request = request.Clone(request.Context())
	agent := strings.TrimSpace(request.Header.Get("User-Agent") + " credenshare-cli/" + version())
	request.Header.Set("User-Agent", agent)
	return t.next.RoundTrip(request)
}
