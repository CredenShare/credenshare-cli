package cli

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	credenshare "github.com/CredenShare/credenshare-sdk-go"
)

const (
	testKey    = "crs_sk_live_kid123.authsecret42.custodysecret42"
	testBearer = "Bearer crs_sk_live_kid123.authsecret42"
)

// fakeAPI is just enough of /v1 to drive every command, holding what a real server would:
// ciphertext, public keys and sealed submissions, never a key.
type fakeAPI struct {
	t      *testing.T
	server *httptest.Server

	mu                sync.Mutex
	calls             int
	shares            map[string]map[string]any
	shareOrder        []string
	requests          map[string]*fakeRequest
	nextID            int
	userAgents        []string
	override          func(w http.ResponseWriter, r *http.Request) bool
	clock             func() time.Time
	onListSubmissions func(code string)
}

type fakeRequest struct {
	body        map[string]any
	expiredAt   *string
	deleted     bool
	submissions []map[string]any
}

func newFakeAPI(t *testing.T, clock func() time.Time) *fakeAPI {
	api := &fakeAPI{
		t: t, shares: map[string]map[string]any{}, requests: map[string]*fakeRequest{}, clock: clock,
	}
	api.server = httptest.NewServer(http.HandlerFunc(api.handle))
	t.Cleanup(api.server.Close)
	return api
}

func (api *fakeAPI) url() string { return api.server.URL + "/v1" }

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Request-Id", "req-test-1")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func (api *fakeAPI) handle(w http.ResponseWriter, r *http.Request) {
	api.mu.Lock()
	defer api.mu.Unlock()
	api.calls++
	api.userAgents = append(api.userAgents, r.Header.Get("User-Agent"))

	if strings.Contains(r.Header.Get("Authorization"), "custodysecret42") {
		api.t.Errorf("the custody secret reached the server")
	}
	if api.override != nil && api.override(w, r) {
		return
	}
	if r.Header.Get("Authorization") != testBearer {
		writeJSON(w, 401, map[string]any{"message": "Invalid API key", "error_code": 3})
		return
	}

	var body map[string]any
	if r.Body != nil {
		raw, _ := io.ReadAll(r.Body)
		if len(raw) > 0 {
			if err := json.Unmarshal(raw, &body); err != nil {
				api.t.Errorf("request body is not JSON: %v", err)
			}
		}
	}
	if (r.Method == http.MethodPost) && r.Header.Get("Idempotency-Key") == "" {
		writeJSON(w, 400, map[string]any{"message": "Idempotency-Key is required"})
		return
	}

	parts := strings.Split(strings.Trim(strings.TrimPrefix(r.URL.Path, "/v1"), "/"), "/")
	switch {
	case r.Method == "GET" && parts[0] == "stats":
		writeJSON(w, 200, map[string]any{
			"shares": map[string]any{"active": 4, "expired": 9, "total_viewed": 31},
			"daily_views": []any{
				map[string]any{"date": "2026-10-24", "count": 2},
				map[string]any{"date": "2026-10-25", "count": 5},
			},
		})
	case r.Method == "POST" && parts[0] == "shares":
		api.nextID++
		code := fmt.Sprintf("SHR%03d", api.nextID)
		api.shares[code] = body
		api.shareOrder = append([]string{code}, api.shareOrder...)
		writeJSON(w, 201, map[string]any{"short_code": code, "expired_at": body["expired_at"], "custody": "none"})
	case r.Method == "GET" && parts[0] == "shares" && len(parts) == 1:
		limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
		page, _ := strconv.Atoi(r.URL.Query().Get("page"))
		rows := []any{}
		for i := (page - 1) * limit; i < len(api.shareOrder) && i < page*limit; i++ {
			code := api.shareOrder[i]
			rows = append(rows, map[string]any{"short_code": code, "expired_at": api.shares[code]["expired_at"]})
		}
		pages := (len(api.shareOrder) + limit - 1) / limit
		writeJSON(w, 200, map[string]any{"shares": rows, "pagination": map[string]any{
			"page": page, "limit": limit, "total": len(api.shareOrder), "total_pages": pages,
		}})
	case parts[0] == "shares" && len(parts) == 2:
		share, ok := api.shares[parts[1]]
		if !ok {
			writeJSON(w, 404, map[string]any{"message": "Share not found", "error_code": 4})
			return
		}
		if r.Method == "DELETE" {
			delete(api.shares, parts[1])
			writeJSON(w, 200, map[string]any{"success": true})
			return
		}
		writeJSON(w, 200, map[string]any{"short_code": parts[1], "expired_at": share["expired_at"]})
	case r.Method == "POST" && parts[0] == "requests":
		api.nextID++
		code := fmt.Sprintf("REQ%03d", api.nextID)
		req := &fakeRequest{body: body}
		if at, ok := body["expired_at"].(string); ok {
			req.expiredAt = &at
		} else {
			at := api.clock().Add(30 * 24 * time.Hour).UTC().Format(time.RFC3339)
			req.expiredAt = &at
		}
		api.requests[code] = req
		writeJSON(w, 201, map[string]any{"short_code": code, "expired_at": *req.expiredAt, "public_key": body["public_key"]})
	case r.Method == "GET" && parts[0] == "requests" && len(parts) == 1:
		rows := []any{}
		for code, req := range api.requests {
			rows = append(rows, map[string]any{"short_code": code, "expired_at": req.expiredAt})
		}
		writeJSON(w, 200, map[string]any{"requests": rows, "pagination": map[string]any{
			"page": 1, "limit": 25, "total": len(rows), "total_pages": 1,
		}})
	case parts[0] == "requests" && len(parts) >= 2:
		req, ok := api.requests[parts[1]]
		if !ok {
			writeJSON(w, 404, map[string]any{"message": "Request not found", "error_code": 4})
			return
		}
		switch {
		case len(parts) == 3 && parts[2] == "submissions" && r.Method == "GET":
			if api.onListSubmissions != nil {
				api.onListSubmissions(parts[1])
			}
			writeJSON(w, 200, map[string]any{
				"submissions": req.submissions, "count": len(req.submissions),
				"skipped_not_end_to_end_encrypted": 0,
			})
		case r.Method == "DELETE":
			now := api.clock().UTC().Format(time.RFC3339)
			if req.expiredAt != nil && *req.expiredAt <= now {
				req.deleted = true
				delete(api.requests, parts[1])
				writeJSON(w, 200, map[string]any{"short_code": parts[1], "outcome": "deleted"})
				return
			}
			req.expiredAt = &now
			writeJSON(w, 200, map[string]any{"short_code": parts[1], "outcome": "expired"})
		case r.Method == "GET":
			writeJSON(w, 200, map[string]any{
				"short_code": parts[1], "expired_at": req.expiredAt, "public_key": req.body["public_key"],
			})
		}
	default:
		writeJSON(w, 404, map[string]any{"message": "no route " + r.Method + " " + r.URL.Path})
	}
}

// submit seals fields to a request's public key, the way the browser form does.
func (api *fakeAPI) submit(code string, at time.Time, fields []credenshare.Field) {
	api.mu.Lock()
	defer api.mu.Unlock()
	api.submitLocked(code, at, fields)
}

func (api *fakeAPI) submitLocked(code string, at time.Time, fields []credenshare.Field) {
	req := api.requests[code]
	raw, err := base64.RawURLEncoding.DecodeString(req.body["public_key"].(string))
	if err != nil {
		api.t.Fatalf("public key: %v", err)
	}
	payload, _ := json.Marshal(fields)
	blob, err := credenshare.WrapToPublicKey(payload, raw)
	if err != nil {
		api.t.Fatalf("sealing: %v", err)
	}
	req.submissions = append(req.submissions, map[string]any{
		"short_code": code, "created_at": at.UTC().Format(time.RFC3339),
		"data": blob, "encryption_type": "e2ee-aes256-gcm",
	})
}

type memKeyring struct {
	entries map[string]string
	fail    error
}

func (k *memKeyring) Get(account string) (string, error) {
	if k.fail != nil {
		return "", k.fail
	}
	v, ok := k.entries[account]
	if !ok {
		return "", errSecretNotFound
	}
	return v, nil
}

func (k *memKeyring) Set(account, secret string) error {
	if k.fail != nil {
		return k.fail
	}
	k.entries[account] = secret
	return nil
}

func (k *memKeyring) Delete(account string) error {
	if k.fail != nil {
		return k.fail
	}
	if _, ok := k.entries[account]; !ok {
		return errSecretNotFound
	}
	delete(k.entries, account)
	return nil
}

type fakeTerminal struct {
	stdinTTY, stderrTTY bool
	none                bool // no controlling terminal at all
	secrets             []string
	lines               []string
	prompts             []string
}

func (f *fakeTerminal) StdinIsTerminal() bool  { return f.stdinTTY }
func (f *fakeTerminal) StderrIsTerminal() bool { return f.stderrTTY }

func (f *fakeTerminal) ReadSecret(_ context.Context, prompt string) (string, error) {
	f.prompts = append(f.prompts, prompt)
	if f.none || len(f.secrets) == 0 {
		return "", errNoTerminal
	}
	v := f.secrets[0]
	f.secrets = f.secrets[1:]
	return v, nil
}

func (f *fakeTerminal) ReadLine(_ context.Context, prompt string) (string, error) {
	f.prompts = append(f.prompts, prompt)
	if f.none || len(f.lines) == 0 {
		return "", errNoTerminal
	}
	v := f.lines[0]
	f.lines = f.lines[1:]
	return v, nil
}

type harness struct {
	t       *testing.T
	api     *fakeAPI
	app     *App
	keyring *memKeyring
	term    *fakeTerminal
	env     map[string]string
	now     time.Time
	stdout  bytes.Buffer
	stderr  bytes.Buffer
	sleeps  []time.Duration
	onSleep func()
}

const testLinkOrigin = "https://links.example"

func newHarness(t *testing.T) *harness {
	h := &harness{
		t:       t,
		keyring: &memKeyring{entries: map[string]string{}},
		term:    &fakeTerminal{stdinTTY: true},
		now:     time.Date(2026, 10, 25, 12, 0, 0, 0, time.UTC),
	}
	h.api = newFakeAPI(t, func() time.Time { return h.now })
	h.env = map[string]string{
		envAPIURL: h.api.url(), envLinkOrigin: testLinkOrigin, envAPIKey: testKey,
	}
	return h
}

// run runs one invocation with stdin as given, and returns its exit code.
func (h *harness) run(stdin string, args ...string) int {
	h.t.Helper()
	h.stdout.Reset()
	h.stderr.Reset()
	h.app = &App{
		Stdin:    strings.NewReader(stdin),
		Stdout:   &h.stdout,
		Stderr:   &h.stderr,
		Getenv:   func(k string) string { return h.env[k] },
		Keyring:  h.keyring,
		Terminal: h.term,
		Now:      func() time.Time { return h.now },
		Sleep: func(ctx context.Context, d time.Duration) error {
			h.sleeps = append(h.sleeps, d)
			h.now = h.now.Add(d)
			if h.onSleep != nil {
				h.onSleep()
			}
			return ctx.Err()
		},
	}
	return h.app.Run(context.Background(), args)
}

func (h *harness) mustRun(stdin string, args ...string) {
	h.t.Helper()
	if code := h.run(stdin, args...); code != 0 {
		h.t.Fatalf("%v exited %d\nstdout: %s\nstderr: %s", args, code, h.stdout.String(), h.stderr.String())
	}
}

func (h *harness) jsonOut() map[string]any {
	h.t.Helper()
	var v map[string]any
	if err := json.Unmarshal(h.stdout.Bytes(), &v); err != nil {
		h.t.Fatalf("stdout is not one JSON object: %v\n%s", err, h.stdout.String())
	}
	return v
}

// assertNoSecrets fails if either stream holds a part of the API key a person should never
// see printed.
func (h *harness) assertNoSecrets() {
	h.t.Helper()
	for _, secret := range []string{"authsecret42", "custodysecret42"} {
		if strings.Contains(h.stdout.String()+h.stderr.String(), secret) {
			h.t.Fatalf("output contains a key secret:\nstdout: %s\nstderr: %s", h.stdout.String(), h.stderr.String())
		}
	}
}
