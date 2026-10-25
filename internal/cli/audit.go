package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	credenshare "github.com/CredenShare/credenshare-sdk-go"
)

// The access log and capabilities are newer than the Go SDK's typed methods, so they go through its Do escape hatch,
// which keeps its authentication, retries and error mapping.

var auditCommand = command{
	name:    "audit",
	summary: "Show who opened a share: its access log",
	help:    auditHelp,
	run:     runAudit,
}

const auditHelp = `Usage: credenshare audit CODE [flags]

Shows a share's access log, newest first: when it was opened, from which IP address and
platform, by which client, and whether a passcode was wrong. Link previews and mail scanners
are named, so a mystery view can be told from a real one.

Only the share's creator can read it, the key needs the audit:read scope, and the plan's
access-log retention applies.

  credenshare audit AbC123
  credenshare audit AbC123 --since 7d --all --json

Flags:
  --limit N      entries per page, 1 to 100 (default 50)
  --all          every page, not only the newest
  --since WHEN   entries after this: 24h, 7d, or a time like 2026-10-01T00:00:00Z
  --until WHEN   entries before this time
`

type auditEntry struct {
	AccessedAt     string  `json:"accessed_at"`
	AccessedIP     string  `json:"accessed_ip"`
	Platform       string  `json:"platform"`
	UserAgent      *string `json:"user_agent"`
	FailedPasscode bool    `json:"failed_passcode"`
	SignedIn       bool    `json:"signed_in"`
	// Added here, from the user agent, as the app labels it.
	ClientType string `json:"client_type"`
	Client     string `json:"client"`
}

type auditPage struct {
	ShortCode     string       `json:"short_code"`
	Entries       []auditEntry `json:"entries"`
	NextCursor    *string      `json:"next_cursor"`
	RetentionDays int          `json:"retention_days"`
	EffectiveFrom string       `json:"effective_from"`
	EffectiveTo   string       `json:"effective_to"`
}

func runAudit(ctx context.Context, a *App, out *output, args []string) error {
	fs := newFlagSet("audit")
	limit := fs.Int("limit", 50, "")
	all := fs.Bool("all", false, "")
	since := fs.String("since", "", "")
	until := fs.String("until", "", "")
	positional, err := parseArgs(fs, "audit", auditHelp, out, args)
	if err != nil {
		return err
	}
	if len(positional) != 1 {
		return usagef("audit", "audit needs one share code")
	}
	code, err := shortCode("audit", positional[0])
	if err != nil {
		return err
	}
	if *limit < 1 || *limit > 100 {
		return usagef("audit", "--limit is between 1 and 100")
	}
	query := url.Values{"limit": {strconv.Itoa(*limit)}}
	for name, text := range map[string]string{"from": *since, "to": *until} {
		if text == "" {
			continue
		}
		at, err := pointInTime(text, a.Now())
		if err != nil {
			return usagef("audit", "--%s: %v", map[string]string{"from": "since", "to": "until"}[name], err)
		}
		query.Set(name, at)
	}

	client, err := a.client()
	if err != nil {
		return err
	}
	var result auditPage
	for cursor := ""; ; {
		q := url.Values{}
		for k, v := range query {
			q[k] = v
		}
		if cursor != "" {
			q.Set("cursor", cursor)
		}
		data, err := client.Do(ctx, credenshare.Call{Path: "/shares/" + url.PathEscape(code) + "/access-log", Query: q})
		if err != nil {
			return err
		}
		var page auditPage
		if err := remarshal(data, &page); err != nil {
			return fmt.Errorf("reading the access log: %w", err)
		}
		if result.ShortCode == "" {
			result = page
		} else {
			result.Entries = append(result.Entries, page.Entries...)
			result.NextCursor = page.NextCursor
		}
		if !*all || page.NextCursor == nil || *page.NextCursor == "" {
			break
		}
		cursor = *page.NextCursor
	}
	for i := range result.Entries {
		ua := ""
		if result.Entries[i].UserAgent != nil {
			ua = *result.Entries[i].UserAgent
		}
		c := classifyAccessClient(ua)
		result.Entries[i].ClientType, result.Entries[i].Client = c.Kind, c.Label
	}
	if result.Entries == nil {
		result.Entries = []auditEntry{}
	}

	return out.emit(result, func(o *output) {
		kept := fmt.Sprintf("%d days", result.RetentionDays)
		if result.RetentionDays < 0 {
			kept = "all of it"
		}
		if len(result.Entries) == 0 {
			o.note("No one has opened %s in the plan's access-log window (%s).", code, kept)
			return
		}
		fmt.Fprintf(o.stdout, "%-21s %-16s %-12s %-26s %s\n", "WHEN", "IP", "PLATFORM", "CLIENT", "NOTES")
		for _, e := range result.Entries {
			notes := []string{}
			if e.FailedPasscode {
				notes = append(notes, "wrong passcode")
			}
			if e.SignedIn {
				notes = append(notes, "signed in")
			}
			fmt.Fprintf(o.stdout, "%-21s %-16s %-12s %-26s %s\n",
				e.AccessedAt, e.AccessedIP, e.Platform, e.Client, strings.Join(notes, ", "))
		}
		if result.NextCursor != nil && *result.NextCursor != "" {
			o.note("Showing the newest %d. Add --all for the rest.", len(result.Entries))
		}
		o.note("The plan keeps %s of access history.", kept)
	})
}

// pointInTime turns --since/--until into an RFC 3339 time: a duration back from now, or a time.
func pointInTime(text string, now time.Time) (string, error) {
	if at, err := time.Parse(time.RFC3339, strings.TrimSpace(text)); err == nil {
		return at.UTC().Format(time.RFC3339), nil
	}
	d, err := parseDuration(text)
	if err != nil || d <= 0 {
		return "", fmt.Errorf("%q is not a duration like 24h or 7d, or a time like 2026-10-01T00:00:00Z", text)
	}
	return now.Add(-d).UTC().Format(time.RFC3339), nil
}

// remarshal turns Do's decoded JSON into a typed value.
func remarshal(data map[string]any, into any) error {
	raw, err := json.Marshal(data)
	if err != nil {
		return err
	}
	return json.Unmarshal(raw, into)
}

var capabilitiesCommand = command{
	name:    "capabilities",
	summary: "Show what this key may do: scopes, plan, limits, team policy",
	help:    capabilitiesHelp,
	run:     runCapabilities,
}

const capabilitiesHelp = `Usage: credenshare capabilities

Shows what the key in use may do: its scopes and rate limit, the plan behind it (the team's for
a team key), its limits and features, and the team's sharing policy for a team key.
`

type capabilities struct {
	APIVersion string `json:"api_version"`
	Key        struct {
		KeyID          string   `json:"key_id"`
		Scopes         []string `json:"scopes"`
		CustodyLevel   int      `json:"custody_level"`
		OrganizationID *string  `json:"organization_id"`
		RateLimitRPM   int      `json:"rate_limit_rpm"`
	} `json:"key"`
	Plan struct {
		Code string `json:"code"`
		Name string `json:"name"`
	} `json:"plan"`
	Limits         map[string]int  `json:"limits"`
	Features       map[string]bool `json:"features"`
	SharingPolicy  map[string]any  `json:"sharing_policy"`
	FieldTypes     []string        `json:"field_types"`
	NotifyOnEvents []string        `json:"notify_on_events"`
}

func fetchCapabilities(ctx context.Context, client *credenshare.Client) (map[string]any, *capabilities, error) {
	data, err := client.Do(ctx, credenshare.Call{Path: "/capabilities"})
	if err != nil {
		return nil, nil, err
	}
	var caps capabilities
	if err := remarshal(data, &caps); err != nil {
		return nil, nil, fmt.Errorf("reading the capabilities: %w", err)
	}
	return data, &caps, nil
}

func runCapabilities(ctx context.Context, a *App, out *output, args []string) error {
	if err := noArguments("capabilities", capabilitiesHelp, out, args); err != nil {
		return err
	}
	client, err := a.client()
	if err != nil {
		return err
	}
	raw, caps, err := fetchCapabilities(ctx, client)
	if err != nil {
		return err
	}
	return out.emit(raw, func(o *output) {
		team := "none (a personal key)"
		if caps.Key.OrganizationID != nil {
			team = *caps.Key.OrganizationID
		}
		custody := []string{"none", "self", "account"}
		level := "unknown"
		if caps.Key.CustodyLevel >= 0 && caps.Key.CustodyLevel < len(custody) {
			level = custody[caps.Key.CustodyLevel]
		}
		fmt.Fprintf(o.stdout, "Key          %s\nScopes       %s\nCustody      %s\nTeam         %s\nRate limit   %d requests a minute\n",
			caps.Key.KeyID, strings.Join(caps.Key.Scopes, ", "), level, team, caps.Key.RateLimitRPM)
		fmt.Fprintf(o.stdout, "Plan         %s\n", caps.Plan.Name)
		shares := "unlimited"
		if caps.Limits["max_shares"] >= 0 {
			shares = fmt.Sprintf("%d of %d left", caps.Limits["remaining_shares"], caps.Limits["max_shares"])
		}
		fmt.Fprintf(o.stdout, "Shares       %s\nAccess log   %s\n", shares, days(caps.Limits["max_days_access_logs"]))
		on := []string{}
		for name, enabled := range caps.Features {
			if enabled {
				on = append(on, strings.ReplaceAll(name, "_", " "))
			}
		}
		sort.Strings(on)
		fmt.Fprintf(o.stdout, "Features     %s\n", strings.Join(on, ", "))
		if caps.SharingPolicy != nil {
			fmt.Fprintf(o.stdout, "Team policy  %s\n", describePolicy(caps.SharingPolicy))
		}
	})
}

func days(n int) string {
	if n < 0 {
		return "kept indefinitely"
	}
	return fmt.Sprintf("%d days kept", n)
}

// describePolicy says what a team's sharing policy asks for, in the words of the app's policy box.
func describePolicy(p map[string]any) string {
	parts := []string{}
	rule := func(key, what string) {
		switch p[key] {
		case "forced":
			parts = append(parts, what+" required")
		case "default":
			parts = append(parts, what+" suggested")
		}
	}
	limit := func(key, what, unit string) {
		if m, ok := p[key].(map[string]any); ok {
			value, _ := m["value"].(float64)
			mode := "suggested"
			if forced, _ := m["forced"].(bool); forced {
				mode = "required"
			}
			parts = append(parts, fmt.Sprintf("%s at most %d %s (%s)", what, int(value), unit, mode))
		}
	}
	limit("max_expiry_hours", "expiry", "hours")
	limit("max_views", "views", "")
	rule("passcode", "passcode")
	rule("sign_in", "recipient sign-in")
	rule("mfa", "two-factor")
	rule("reveal", "click to reveal")
	if len(parts) == 0 {
		return "none"
	}
	return strings.ReplaceAll(strings.Join(parts, "; "), "  ", " ")
}

// checkKey proves a key authenticates, and names its plan when the API says. /capabilities needs no scope, so it
// answers for any key; an API without it falls back to /stats, where a key lacking stats:read is still a good key.
func checkKey(ctx context.Context, client *credenshare.Client) (plan string, err error) {
	_, caps, err := fetchCapabilities(ctx, client)
	if err == nil {
		return caps.Plan.Name, nil
	}
	if errors.Is(err, credenshare.ErrAuthentication) {
		return "", err
	}
	if _, err := client.GetStats(ctx); err != nil && !errors.Is(err, credenshare.ErrPermission) {
		return "", err
	}
	return "", nil
}
