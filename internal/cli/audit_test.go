package cli

import (
	"strings"
	"testing"
)

// Gitea #404 in the CLI: audit, capabilities and list --status expired.

func accessEntry(at, ip, ua string, failed, signedIn bool) map[string]any {
	return map[string]any{"accessed_at": at, "accessed_ip": ip, "platform": "macOS", "user_agent": ua,
		"failed_passcode": failed, "signed_in": signedIn}
}

func TestAuditNamesClientsAndFollowsTheCursor(t *testing.T) {
	h := newHarness(t)
	h.api.accessLogs = map[string][]map[string]any{"AbC123": {
		accessEntry("2026-10-25T18:00:00Z", "203.0.113.7", chromeUA, true, true),
		accessEntry("2026-10-25T17:00:00Z", "198.51.100.2", "Slackbot-LinkExpanding 1.0", false, false),
		accessEntry("2026-10-25T16:00:00Z", "198.51.100.3", "curl/8.4.0", false, false),
	}}

	h.mustRun("", "audit", "AbC123", "--limit", "2")
	text := h.stdout.String()
	for _, want := range []string{"203.0.113.7", "Chrome", "wrong passcode, signed in", "Slack link preview"} {
		if !strings.Contains(text, want) {
			t.Errorf("missing %q in:\n%s", want, text)
		}
	}
	if strings.Contains(text, "curl") || !strings.Contains(h.stderr.String(), "--all") {
		t.Fatalf("one page only, with a note about the rest; stdout:\n%s\nstderr:\n%s", text, h.stderr.String())
	}

	h.mustRun("", "audit", "AbC123", "--limit", "2", "--all", "--json")
	got := h.jsonOut()
	entries := got["entries"].([]any)
	if len(entries) != 3 || got["next_cursor"] != nil {
		t.Fatalf("--all read %d entries, cursor %v", len(entries), got["next_cursor"])
	}
	last := entries[2].(map[string]any)
	if last["client"] != "curl" || last["client_type"] != "automation" {
		t.Fatalf("entry %v", last)
	}
	if q := h.api.accessQueries[len(h.api.accessQueries)-1]; q.Get("cursor") != "2" || q.Get("limit") != "2" {
		t.Fatalf("the second page asked for %v", q)
	}
}

func TestAuditSinceAndRefusals(t *testing.T) {
	h := newHarness(t)
	h.api.accessLogs = map[string][]map[string]any{"AbC123": {}}
	h.mustRun("", "audit", "AbC123", "--since", "7d", "--until", "2026-10-25T00:00:00Z")
	q := h.api.accessQueries[0]
	if q.Get("from") != "2026-10-18T12:00:00Z" || q.Get("to") != "2026-10-25T00:00:00Z" {
		t.Fatalf("query %v", q)
	}
	if !strings.Contains(h.stderr.String(), "No one has opened AbC123") {
		t.Fatalf("stderr %q", h.stderr.String())
	}

	if code := h.run("", "audit", "Theirs1"); code != exitNotFound {
		t.Fatalf("another account's share exited %d", code)
	}
	for _, bad := range [][]string{{"audit"}, {"audit", "a/b"}, {"audit", "AbC123", "--limit", "500"}, {"audit", "AbC123", "--since", "soon"}} {
		if code := h.run("", bad...); code != exitUsage {
			t.Errorf("%v exited %d", bad, code)
		}
	}
}

func testCapabilities(team bool) map[string]any {
	caps := map[string]any{
		"api_version": "1",
		"key": map[string]any{"key_id": "kid123", "scopes": []string{"shares:write", "audit:read"},
			"custody_level": 1, "organization_id": nil, "rate_limit_rpm": 100},
		"plan":           map[string]any{"code": "business", "name": "Business"},
		"limits":         map[string]any{"max_shares": 500, "remaining_shares": 346, "max_days_access_logs": 90},
		"features":       map[string]any{"secure_requests": true, "zero_knowledge": false},
		"sharing_policy": nil, "field_types": []string{"text"}, "notify_on_events": []string{"viewed"},
	}
	if team {
		caps["key"].(map[string]any)["organization_id"] = "team-1"
		caps["sharing_policy"] = map[string]any{"passcode": "forced", "max_views": map[string]any{"value": 3, "forced": true}}
	}
	return caps
}

func TestCapabilities(t *testing.T) {
	h := newHarness(t)
	h.api.capabilities = testCapabilities(true)
	h.mustRun("", "capabilities")
	text := h.stdout.String()
	for _, want := range []string{"kid123", "shares:write, audit:read", "self", "team-1", "Business", "346 of 500 left",
		"90 days kept", "secure requests", "views at most 3", "passcode required"} {
		if !strings.Contains(text, want) {
			t.Errorf("missing %q in:\n%s", want, text)
		}
	}
	if strings.Contains(text, "zero knowledge") {
		t.Errorf("a feature that is off is listed:\n%s", text)
	}

	h.mustRun("", "capabilities", "--json")
	if got := h.jsonOut(); got["plan"].(map[string]any)["code"] != "business" {
		t.Fatalf("json %v", got)
	}
	h.assertNoSecrets()
}

func TestAuthStatusNamesThePlan(t *testing.T) {
	h := newHarness(t)
	h.api.capabilities = testCapabilities(false)
	h.mustRun("", "auth", "status")
	if !strings.Contains(h.stdout.String(), "Plan: Business") {
		t.Fatalf("stdout %q", h.stdout.String())
	}
}

func TestListExpired(t *testing.T) {
	h := newHarness(t)
	for i := 0; i < 3; i++ {
		h.api.expiredShares = append(h.api.expiredShares, map[string]any{"short_code": "Old" + string(rune('A'+i)), "expired_at": "2026-10-20T09:00:00Z"})
	}
	h.api.expiredRequests = []map[string]any{{"short_code": "ReqOld", "expired_at": "2026-10-21T09:00:00Z"}}

	h.mustRun("", "list", "--status", "expired", "--limit", "2")
	if !strings.Contains(h.stdout.String(), "OldA") || strings.Contains(h.stdout.String(), "OldC") ||
		!strings.Contains(h.stderr.String(), "--status expired --page 2") {
		t.Fatalf("stdout %q stderr %q", h.stdout.String(), h.stderr.String())
	}
	h.mustRun("", "list", "shares", "--status", "expired", "--limit", "2", "--all", "--json")
	if got := len(h.jsonOut()["shares"].([]any)); got != 3 {
		t.Fatalf("--all listed %d", got)
	}
	h.mustRun("", "list", "requests", "--status", "expired", "--json")
	if got := h.jsonOut()["requests"].([]any); len(got) != 1 {
		t.Fatalf("requests %v", got)
	}
	if code := h.run("", "list", "--status", "deleted"); code != exitUsage {
		t.Fatalf("an unknown status exited %d", code)
	}
}

func TestShareNotify(t *testing.T) {
	h := newHarness(t)
	h.term.secrets = []string{"v"}
	h.mustRun("", "share", "--notify", "viewed, denied,viewed")
	got, _ := h.api.shares["SHR001"]["notify_on"].([]any)
	if len(got) != 2 || got[0] != "viewed" || got[1] != "denied" {
		t.Fatalf("notify_on sent as %v", h.api.shares["SHR001"]["notify_on"])
	}

	h.term.secrets = []string{"v"}
	h.mustRun("", "share")
	if _, sent := h.api.shares["SHR002"]["notify_on"]; sent {
		t.Fatal("notify_on was sent without --notify")
	}

	calls := h.api.calls
	if code := h.run("", "share", "--notify", "opened"); code != exitUsage || h.api.calls != calls {
		t.Fatalf("an unknown event exited %d after %d request(s)", code, h.api.calls-calls)
	}
	if len(h.term.prompts) != 2 {
		t.Fatalf("asked for a value before refusing the flag: %v", h.term.prompts)
	}
}
