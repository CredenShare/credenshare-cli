package cli

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	credenshare "github.com/CredenShare/credenshare-sdk-go"
)

// openLink decrypts a share the way its recipient would: the key from the link's fragment,
// the ciphertext from what the server stored.
func openLink(t *testing.T, h *harness, link string, passcode *string) []credenshare.Field {
	t.Helper()
	parsed, err := url.Parse(strings.TrimSpace(link))
	if err != nil {
		t.Fatal(err)
	}
	if got := parsed.Scheme + "://" + parsed.Host; got != testLinkOrigin {
		t.Fatalf("link origin %q, want %q", got, testLinkOrigin)
	}
	key, err := credenshare.DecodeFragment(parsed.Fragment)
	if err != nil {
		t.Fatalf("link fragment: %v", err)
	}
	stored := h.api.shares[strings.Trim(parsed.Path, "/")]
	if stored == nil {
		t.Fatalf("no share stored for %s", link)
	}
	fields, err := credenshare.DecryptContent(key, stored["data"].(string), passcode)
	if err != nil {
		t.Fatalf("decrypting: %v", err)
	}
	return fields
}

func storedBody(t *testing.T, body map[string]any) string {
	t.Helper()
	raw, _ := json.Marshal(body)
	return string(raw)
}

func TestShareEncryptsAPromptedValueHere(t *testing.T) {
	h := newHarness(t)
	h.term.secrets = []string{"hunter2 <&> \"quoted\""}
	h.mustRun("", "share", "--field", "DB password", "--title", "Staging", "--expires", "7d", "--views", "2")

	lines := strings.Split(strings.TrimSpace(h.stdout.String()), "\n")
	if len(lines) != 1 {
		t.Fatalf("stdout should be the link alone, got %q", h.stdout.String())
	}
	fields := openLink(t, h, lines[0], nil)
	want := credenshare.Field{Key: "DB password", Value: "hunter2 <&> \"quoted\"", Type: "password"}
	if len(fields) != 1 || !fields[0].Equal(want) {
		t.Fatalf("fields %+v, want %+v", fields, want)
	}

	body := h.api.shares["SHR001"]
	if strings.Contains(storedBody(t, body), "hunter2") {
		t.Fatal("the plaintext reached the server")
	}
	if body["title"] != "Staging" || body["access_counts_left"] != float64(2) {
		t.Fatalf("body %v", body)
	}
	if body["expired_at"] != "2026-11-01T12:00:00Z" {
		t.Fatalf("expired_at %v", body["expired_at"])
	}
	if h.term.prompts[0] != "DB password: " {
		t.Fatalf("prompt %q", h.term.prompts[0])
	}
	h.assertNoSecrets()
}

func TestShareReadsOneValueFromStdin(t *testing.T) {
	h := newHarness(t)
	h.term.stdinTTY = false
	h.mustRun("s3cret\n", "share")
	fields := openLink(t, h, h.stdout.String(), nil)
	if len(fields) != 1 || fields[0].Key != "Secret" || fields[0].Value != "s3cret" {
		t.Fatalf("fields %+v", fields)
	}
	if len(h.term.prompts) != 0 {
		t.Fatalf("asked %v although stdin had the value", h.term.prompts)
	}
}

func TestShareFilesTypesAndPasscode(t *testing.T) {
	h := newHarness(t)
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "key.pem")
	if err := os.WriteFile(keyPath, []byte("-----BEGIN-----\nabc\n-----END-----\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	h.term.secrets = []string{"tok-123", "open sesame", "open sesame"}
	h.mustRun("", "share", "--file", "Private key="+keyPath, "--field", "Token:text", "--passcode", "--json")

	out := h.jsonOut()
	passcode := "open sesame"
	fields := openLink(t, h, out["link"].(string), &passcode)
	if len(fields) != 2 {
		t.Fatalf("fields %+v", fields)
	}
	if fields[0].Key != "Private key" || fields[0].Type != "multiline" ||
		fields[0].Value != "-----BEGIN-----\nabc\n-----END-----\n" {
		t.Fatalf("file field %+v", fields[0])
	}
	if fields[1].Key != "Token" || fields[1].Type != "text" || fields[1].Value != "tok-123" {
		t.Fatalf("prompted field %+v", fields[1])
	}
	body := h.api.shares[out["short_code"].(string)]
	if body["passcode_verifier"] == nil || strings.Contains(storedBody(t, body), "open sesame") {
		t.Fatalf("the passcode must travel as a verifier only: %v", body)
	}
	if _, err := credenshare.DecryptContent(
		mustFragmentKey(t, out["link"].(string)), body["data"].(string), nil,
	); err == nil {
		t.Fatal("the share opened without its passcode")
	}
}

func mustFragmentKey(t *testing.T, link string) []byte {
	t.Helper()
	parsed, _ := url.Parse(link)
	key, err := credenshare.DecodeFragment(parsed.Fragment)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func TestShareRefusesAValueOnTheCommandLine(t *testing.T) {
	h := newHarness(t)
	if code := h.run("", "share", "hunter2"); code != exitUsage {
		t.Fatalf("exit %d", code)
	}
	if code := h.run("", "share", "--value", "hunter2"); code != exitUsage {
		t.Fatalf("a --value flag must not exist; exit %d", code)
	}
	if h.api.calls != 0 {
		t.Fatal("something was sent")
	}
}

func TestShareMismatchedPasscodes(t *testing.T) {
	h := newHarness(t)
	h.term.secrets = []string{"v", "one", "two"}
	if code := h.run("", "share", "--passcode"); code != exitUsage {
		t.Fatalf("exit %d", code)
	}
	if !strings.Contains(h.stderr.String(), "different") || h.api.calls != 0 {
		t.Fatalf("stderr %q, calls %d", h.stderr.String(), h.api.calls)
	}
}

func TestShareWithNoTerminalAndNoStdinExplainsWhatToDo(t *testing.T) {
	h := newHarness(t)
	h.term.none = true
	if code := h.run("", "share", "--field", "A", "--field", "B"); code != exitUsage {
		t.Fatalf("exit %d", code)
	}
	if !strings.Contains(h.stderr.String(), "--file") {
		t.Fatalf("stderr %q", h.stderr.String())
	}
}

func TestTeamPolicyRefusalExitsFourWithItsReason(t *testing.T) {
	h := newHarness(t)
	reason := "This does not meet your team's sharing policy. It requires a passcode."
	h.api.override = func(w http.ResponseWriter, r *http.Request) bool {
		if r.Method == "POST" {
			writeJSON(w, 403, map[string]any{"success": false, "message": reason, "error_code": 145})
			return true
		}
		return false
	}
	h.term.secrets = []string{"v"}
	if code := h.run("", "share"); code != exitRefused {
		t.Fatalf("exit %d", code)
	}
	if !strings.Contains(h.stderr.String(), reason) || strings.Contains(h.stderr.String(), "Business") {
		t.Fatalf("stderr %q", h.stderr.String())
	}
}

func TestExitCodes(t *testing.T) {
	cases := []struct {
		name   string
		status int
		body   map[string]any
		want   int
	}{
		{"refused key", 401, map[string]any{"message": "Invalid API key"}, exitAuth},
		{"missing scope", 403, map[string]any{"message": "Missing scope", "error_code": 7}, exitRefused},
		{"quota", 403, map[string]any{"message": "Limit reached", "error_code": 61}, exitRefused},
		{"rate limit", 429, map[string]any{"message": "Slow down"}, exitServer},
		{"server", 500, map[string]any{"message": "Boom"}, exitServer},
		{"unavailable", 503, map[string]any{"message": "Try later"}, exitServer},
		{"bad input", 400, map[string]any{"message": "Validation failed", "error_code": 19}, exitUsage},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			h := newHarness(t)
			h.api.override = func(w http.ResponseWriter, _ *http.Request) bool {
				writeJSON(w, c.status, c.body)
				return true
			}
			if code := h.run("", "stats", "--json"); code != c.want {
				t.Fatalf("exit %d, want %d; stderr %s", code, c.want, h.stderr.String())
			}
			errBody := h.jsonOut()["error"].(map[string]any)
			if errBody["exit_code"] != float64(c.want) || errBody["status"] != float64(c.status) ||
				errBody["request_id"] != "req-test-1" {
				t.Fatalf("error JSON %v", errBody)
			}
		})
	}

	t.Run("not found", func(t *testing.T) {
		h := newHarness(t)
		if code := h.run("", "show", "NOPE"); code != exitNotFound {
			t.Fatalf("exit %d", code)
		}
	})
	t.Run("network", func(t *testing.T) {
		h := newHarness(t)
		h.api.server.Close()
		if code := h.run("", "stats"); code != exitServer {
			t.Fatalf("exit %d; stderr %s", code, h.stderr.String())
		}
	})
	t.Run("not signed in", func(t *testing.T) {
		h := newHarness(t)
		delete(h.env, envAPIKey)
		if code := h.run("", "stats"); code != exitAuth {
			t.Fatalf("exit %d", code)
		}
		if !strings.Contains(h.stderr.String(), "auth login") {
			t.Fatalf("stderr %q", h.stderr.String())
		}
	})
}

func TestAuthLoginStatusLogout(t *testing.T) {
	h := newHarness(t)
	delete(h.env, envAPIKey)
	h.term.secrets = []string{"  " + testKey + "\n"}
	h.mustRun("", "auth", "login")
	if h.keyring.entries[apiKeyAccount(h.api.url())] != testKey {
		t.Fatalf("keychain %v", h.keyring.entries)
	}
	if !strings.Contains(h.stdout.String(), "kid123") {
		t.Fatalf("stdout %q", h.stdout.String())
	}
	h.assertNoSecrets()

	h.mustRun("", "auth", "status", "--json")
	status := h.jsonOut()
	if status["key_id"] != "kid123" || status["source"] != "keychain" || status["check"] != "accepted" {
		t.Fatalf("status %v", status)
	}
	h.assertNoSecrets()

	h.mustRun("", "auth", "logout")
	if len(h.keyring.entries) != 0 {
		t.Fatalf("keychain %v", h.keyring.entries)
	}
	if code := h.run("", "auth", "status"); code != exitAuth {
		t.Fatalf("status after logout exited %d", code)
	}
}

func TestAuthLoginReadsAPipedKeyAndRefusesABadOne(t *testing.T) {
	h := newHarness(t)
	delete(h.env, envAPIKey)
	h.term.stdinTTY = false
	h.api.override = func(w http.ResponseWriter, _ *http.Request) bool {
		writeJSON(w, 401, map[string]any{"message": "Invalid API key"})
		return true
	}
	if code := h.run(testKey+"\n", "auth", "login"); code != exitAuth {
		t.Fatalf("exit %d", code)
	}
	if len(h.keyring.entries) != 0 {
		t.Fatal("a refused key was stored")
	}
	h.assertNoSecrets()

	if code := h.run("not-a-key", "auth", "login"); code != exitAuth {
		t.Fatalf("a malformed key exited %d", code)
	}
}

func TestEnvironmentKeyWinsOverTheKeychain(t *testing.T) {
	h := newHarness(t)
	h.keyring.entries[apiKeyAccount(h.api.url())] = "crs_sk_live_other.wrong"
	h.mustRun("", "auth", "status", "--json")
	if got := h.jsonOut()["source"]; got != "environment" {
		t.Fatalf("source %v", got)
	}
}

func TestKeysAreKeptPerAPIAddress(t *testing.T) {
	h := newHarness(t)
	delete(h.env, envAPIKey)
	h.keyring.entries[apiKeyAccount("https://elsewhere.example/v1")] = testKey
	if code := h.run("", "stats"); code != exitAuth {
		t.Fatalf("a key for another address was used; exit %d", code)
	}
}

func TestRequestThenReceive(t *testing.T) {
	h := newHarness(t)
	h.mustRun("", "request", "--field", "Password", "--field", "Notes:multiline",
		"--require-mfa", "--allow-domain", "example.com", "--max-submissions", "1")
	collect := strings.TrimSpace(h.stdout.String())
	if collect != testLinkOrigin+"/r/REQ001" {
		t.Fatalf("collect link %q", collect)
	}
	if strings.Contains(collect, "#") {
		t.Fatal("the collect link carries a key")
	}

	stored := h.keyring.entries[seedAccount(h.api.url(), "REQ001")]
	seed, err := decodeSeed(stored)
	if err != nil {
		t.Fatalf("seed in keychain: %v", err)
	}
	body := h.api.requests["REQ001"].body
	if strings.Contains(storedBody(t, body), stored) {
		t.Fatal("the seed reached the server")
	}
	pair, _ := credenshare.KeypairFromSeed(seed)
	if body["public_key"] != pair.PublicKeyB64URL {
		t.Fatal("the registered public key is not the stored seed's")
	}
	if body["requires_login"] != true || body["requires_mfa"] != true || body["max_submission"] != float64(1) {
		t.Fatalf("body %v", body)
	}

	h.mustRun("", "receive", "REQ001")
	if !strings.Contains(h.stderr.String(), "Nothing has been submitted") {
		t.Fatalf("stderr %q", h.stderr.String())
	}

	h.api.submit("REQ001", h.now.Add(time.Hour), []credenshare.Field{
		{Key: "Password", Value: "new-pass", Type: "password"},
		{Key: "Notes", Value: "line one\nline two", Type: "multiline"},
	})
	h.api.submit("REQ001", h.now, []credenshare.Field{{Key: "Password", Value: "old-pass", Type: "password"}})

	h.mustRun("", "receive", "REQ001")
	text := h.stdout.String()
	if !strings.Contains(text, "Submission 1 of 2") || !strings.Contains(text, "old-pass") ||
		!strings.Contains(text, "    line two") || strings.Index(text, "old-pass") > strings.Index(text, "new-pass") {
		t.Fatalf("receive printed:\n%s", text)
	}

	h.mustRun("", "receive", "--field", "password", "REQ001")
	if h.stdout.String() != "new-pass\n" {
		t.Fatalf("--field printed %q", h.stdout.String())
	}

	h.mustRun("", "receive", "REQ001", "--json")
	subs := h.jsonOut()["submissions"].([]any)
	first := subs[0].(map[string]any)["fields"].([]any)[0].(map[string]any)
	if len(subs) != 2 || first["value"] != "old-pass" || first["key"] != "Password" {
		t.Fatalf("json %v", subs)
	}

	if code := h.run("", "receive", "REQ001", "--field", "Missing"); code != exitNotFound {
		t.Fatalf("a missing field exited %d", code)
	}
}

func TestReceiveWaitTimesOut(t *testing.T) {
	h := newHarness(t)
	h.mustRun("", "request", "--field", "Password")
	if code := h.run("", "receive", "REQ001", "--wait", "--timeout", "12s"); code != exitNotFound {
		t.Fatalf("exit %d", code)
	}
	if len(h.sleeps) != 3 || h.sleeps[0] != 5*time.Second {
		t.Fatalf("sleeps %v", h.sleeps)
	}
}

func TestReceiveWaitReturnsTheFirstSubmission(t *testing.T) {
	h := newHarness(t)
	h.mustRun("", "request", "--field", "Password")
	h.onSleep = func() {
		if len(h.sleeps) == 2 {
			h.api.submit("REQ001", h.now, []credenshare.Field{{Key: "Password", Value: "pw", Type: "password"}})
		}
	}
	h.mustRun("", "receive", "REQ001", "--wait", "--field", "Password")
	if h.stdout.String() != "pw\n" || len(h.sleeps) != 2 {
		t.Fatalf("stdout %q after %d sleeps", h.stdout.String(), len(h.sleeps))
	}
}

func TestReceiveWithoutAStoredKey(t *testing.T) {
	h := newHarness(t)
	h.mustRun("", "request", "--field", "Password")
	h.keyring.entries = map[string]string{}
	if code := h.run("", "receive", "REQ001"); code != exitNotFound {
		t.Fatalf("exit %d", code)
	}
	if !strings.Contains(h.stderr.String(), "--access-link-file") {
		t.Fatalf("stderr %q", h.stderr.String())
	}
}

func TestRequestWithoutAKeychain(t *testing.T) {
	h := newHarness(t)
	h.keyring.fail = errors.New("no secret service")
	if code := h.run("", "request", "--field", "Password"); code != exitUsage {
		t.Fatalf("exit %d", code)
	}
	if len(h.api.requests) != 0 {
		t.Fatal("a request was created whose key could not be kept")
	}
	if !strings.Contains(h.stderr.String(), "--access-link-file") {
		t.Fatalf("stderr %q", h.stderr.String())
	}

	path := filepath.Join(t.TempDir(), "access-link")
	h.mustRun("", "request", "--field", "Password", "--access-link-file", path)
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(string(raw), testLinkOrigin+"/r/REQ001#1") {
		t.Fatalf("access-link file holds %q", raw)
	}
	if runtime.GOOS != "windows" {
		if info, _ := os.Stat(path); info.Mode().Perm() != 0o600 {
			t.Fatalf("access-link file mode %v", info.Mode().Perm())
		}
	}
	if strings.Contains(h.stdout.String()+h.stderr.String(), "#1") {
		t.Fatal("the access link was printed")
	}

	h.api.submit("REQ001", h.now, []credenshare.Field{{Key: "Password", Value: "pw", Type: "password"}})
	h.mustRun("", "receive", "--access-link-file", path, "--field", "Password")
	if h.stdout.String() != "pw\n" {
		t.Fatalf("stdout %q", h.stdout.String())
	}
	h.term.stdinTTY = false
	h.mustRun(string(raw), "receive", "REQ001", "--access-link-file", "-", "--field", "Password")
	if h.stdout.String() != "pw\n" {
		t.Fatalf("stdout %q", h.stdout.String())
	}

	if code := h.run("", "request", "--field", "Password", "--access-link-file", path); code != exitUsage {
		t.Fatalf("overwriting an access-link file exited %d: %s", code, h.stderr.String())
	}
}

func TestRequestDeleteClosesThenDeletes(t *testing.T) {
	h := newHarness(t)
	h.mustRun("", "request", "--field", "Password")
	account := seedAccount(h.api.url(), "REQ001")

	h.mustRun("", "request", "delete", "REQ001", "--yes", "--json")
	if got := h.jsonOut()["outcome"]; got != "expired" {
		t.Fatalf("first delete %v", got)
	}
	if _, ok := h.keyring.entries[account]; !ok {
		t.Fatal("the key went while the submissions are still kept")
	}

	h.now = h.now.Add(time.Minute)
	h.term.lines = []string{"y"}
	h.mustRun("", "request", "delete", "REQ001")
	if !strings.Contains(h.term.prompts[len(h.term.prompts)-1], "Delete it and its submissions") {
		t.Fatalf("prompt %q", h.term.prompts)
	}
	if _, ok := h.keyring.entries[account]; ok {
		t.Fatal("the key outlived its request")
	}
}

func TestExpireAsksFirst(t *testing.T) {
	h := newHarness(t)
	h.term.secrets = []string{"v"}
	h.mustRun("", "share")

	h.term.none = true
	if code := h.run("", "expire", "SHR001"); code != exitUsage {
		t.Fatalf("exit %d", code)
	}
	if !strings.Contains(h.stderr.String(), "--yes") || h.api.shares["SHR001"] == nil {
		t.Fatalf("expired without confirmation; stderr %q", h.stderr.String())
	}

	h.term.none = false
	h.term.lines = []string{"n"}
	if code := h.run("", "expire", "SHR001"); code != exitUsage || h.api.shares["SHR001"] == nil {
		t.Fatalf("a no expired it; exit %d", code)
	}

	h.mustRun("", "expire", "SHR001", "--yes")
	if h.api.shares["SHR001"] != nil {
		t.Fatal("not expired")
	}
}

func TestListShowAndStats(t *testing.T) {
	h := newHarness(t)
	for i := 0; i < 3; i++ {
		h.term.secrets = []string{"v"}
		h.mustRun("", "share")
	}

	h.mustRun("", "list", "--limit", "2")
	if !strings.Contains(h.stdout.String(), "SHR003") || strings.Contains(h.stdout.String(), "SHR001") ||
		!strings.Contains(h.stderr.String(), "--page 2") {
		t.Fatalf("stdout %q stderr %q", h.stdout.String(), h.stderr.String())
	}
	h.mustRun("", "list", "shares", "--all", "--json")
	if got := len(h.jsonOut()["shares"].([]any)); got != 3 {
		t.Fatalf("--all listed %d", got)
	}

	h.mustRun("", "show", "SHR002", "--json")
	if got := h.jsonOut(); got["kind"] != "share" || got["short_code"] != "SHR002" {
		t.Fatalf("show %v", got)
	}

	h.mustRun("", "request", "--field", "Password")
	h.mustRun("", "show", "REQ004", "--json")
	if got := h.jsonOut(); got["kind"] != "request" || got["key_in_keychain"] != true ||
		got["submissions"] != float64(0) {
		t.Fatalf("show %v", got)
	}

	h.mustRun("", "stats")
	if !strings.Contains(h.stdout.String(), "Active shares   4") ||
		!strings.Contains(h.stdout.String(), "Views, last 2 days: 7") {
		t.Fatalf("stats %q", h.stdout.String())
	}
}

func TestShortCodesAreCheckedBeforeAnyRequest(t *testing.T) {
	h := newHarness(t)
	for _, args := range [][]string{
		{"show", ""}, {"show", "../stats"}, {"expire", "a/b", "--yes"}, {"receive", " "},
		{"request", "delete", "x?y", "--yes"},
	} {
		if code := h.run("", args...); code != exitUsage {
			t.Errorf("%q exited %d", args, code)
		}
	}
	if h.api.calls != 0 {
		t.Fatalf("%d request(s) went out with a malformed code", h.api.calls)
	}
}

func TestUserAgentNamesTheCLI(t *testing.T) {
	h := newHarness(t)
	h.mustRun("", "stats")
	if ua := h.api.userAgents[0]; !strings.Contains(ua, "credenshare-go/") || !strings.Contains(ua, "credenshare-cli/") {
		t.Fatalf("User-Agent %q", ua)
	}
}

func TestHelpAndUnknownCommands(t *testing.T) {
	h := newHarness(t)
	h.mustRun("", "help")
	help := h.stdout.String()
	for _, c := range commands() {
		if !strings.Contains(help, "  "+c.name+" ") {
			t.Errorf("help does not list %s", c.name)
		}
		h.mustRun("", c.name, "--help")
		if !strings.Contains(h.stdout.String(), "Usage") {
			t.Errorf("%s --help printed %q", c.name, h.stdout.String())
		}
	}
	if code := h.run("", "nope"); code != exitUsage {
		t.Fatalf("exit %d", code)
	}
	if h.api.calls != 0 {
		t.Fatal("help made a network call")
	}
}

func TestSelfCheckPasses(t *testing.T) {
	h := newHarness(t)
	h.mustRun("", "self-check", "--json")
	if got := h.jsonOut(); got["failed"] != float64(0) || got["passed"].(float64) < 1 {
		t.Fatalf("self-check %v", got)
	}
}
