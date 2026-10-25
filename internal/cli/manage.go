package cli

import (
	"context"
	"errors"
	"fmt"

	credenshare "github.com/CredenShare/credenshare-sdk-go"
)

var listCommand = command{
	name:    "list",
	summary: "List your shares or requests",
	help:    listHelp,
	run:     runList,
}

const listHelp = `Usage: credenshare list [shares|requests] [flags]

Lists short codes and expiry times, newest first. Never content. Shares are listed when
neither is named.

Flags:
  --status S   active (the default) or expired: shares that have ended, or requests that
               have closed, newest first
  --limit N    per page, 1 to 100 (default 25)
  --page N     which page (default 1)
  --all        every page
`

type listedItem struct {
	ShortCode string  `json:"short_code"`
	ExpiredAt *string `json:"expired_at"`
}

func runList(ctx context.Context, a *App, out *output, args []string) error {
	fs := newFlagSet("list")
	limit := fs.Int("limit", 25, "")
	page := fs.Int("page", 1, "")
	all := fs.Bool("all", false, "")
	status := fs.String("status", "active", "")
	positional, err := parseArgs(fs, "list", listHelp, out, args)
	if err != nil {
		return err
	}
	kind := "shares"
	if len(positional) == 1 {
		kind = positional[0]
	}
	if len(positional) > 1 || (kind != "shares" && kind != "requests") {
		return usagef("list", "list takes shares or requests")
	}
	if *limit < 1 || *limit > 100 {
		return usagef("list", "--limit is between 1 and 100")
	}
	if *page < 1 {
		return usagef("list", "--page is at least 1")
	}
	if *all && flagWasSet(fs, "page") {
		return usagef("list", "use --all or --page, not both")
	}
	if *status != "active" && *status != "expired" {
		return usagef("list", "--status is active or expired")
	}

	client, err := a.client()
	if err != nil {
		return err
	}
	if *status == "expired" {
		return listExpired(ctx, client, out, kind, *limit, *page, *all)
	}

	items := []listedItem{}
	result := map[string]any{}
	var hasMore bool
	var shownPage, totalPages int
	switch {
	case kind == "shares" && *all:
		err = client.IterateShares(ctx, 100, func(s credenshare.ShareSummary) error {
			items = append(items, listedItem{s.ShortCode, s.ExpiredAt})
			return nil
		})
	case kind == "requests" && *all:
		err = client.IterateRequests(ctx, 100, func(r credenshare.RequestSummary) error {
			items = append(items, listedItem{r.ShortCode, r.ExpiredAt})
			return nil
		})
	case kind == "shares":
		var p *credenshare.SharePage
		if p, err = client.ListShares(ctx, *limit, *page); err == nil {
			for _, s := range p.Shares {
				items = append(items, listedItem{s.ShortCode, s.ExpiredAt})
			}
			result["page"], result["limit"], result["total"], result["total_pages"] =
				p.Page, p.Limit, p.Total, p.TotalPages
			hasMore, shownPage, totalPages = p.HasMore(), p.Page, p.TotalPages
		}
	default:
		var p *credenshare.RequestPage
		if p, err = client.ListRequests(ctx, *limit, *page); err == nil {
			for _, r := range p.Requests {
				items = append(items, listedItem{r.ShortCode, r.ExpiredAt})
			}
			result["page"], result["limit"], result["total"], result["total_pages"] =
				p.Page, p.Limit, p.Total, p.TotalPages
			hasMore, shownPage, totalPages = p.HasMore(), p.Page, p.TotalPages
		}
	}
	if err != nil {
		return err
	}
	result[kind] = items

	return out.emit(result, func(o *output) {
		if len(items) == 0 {
			o.note("No %s.", kind)
			return
		}
		fmt.Fprintf(o.stdout, "%-14s %s\n", "CODE", "EXPIRES")
		for _, item := range items {
			fmt.Fprintf(o.stdout, "%-14s %s\n", item.ShortCode, expiryText(item.ExpiredAt))
		}
		if hasMore {
			of := ""
			if totalPages > 0 {
				of = fmt.Sprintf(" of %d", totalPages)
			}
			o.note("Page %d%s. Next: credenshare list %s --page %d", shownPage, of, kind, shownPage+1)
		}
	})
}

func expiryText(at *string) string {
	if at == nil {
		return "never"
	}
	return *at
}

var showCommand = command{
	name:    "show",
	summary: "Show a share's or a request's details (never its content)",
	help:    showHelp,
	run:     runShow,
}

const showHelp = `Usage: credenshare show CODE

Shows whether CODE is a share or a request, and when it expires. For a request, also how
many submissions it has and whether its key is in this keychain.
`

func runShow(ctx context.Context, a *App, out *output, args []string) error {
	positional, err := parseArgs(newFlagSet("show"), "show", showHelp, out, args)
	if err != nil {
		return err
	}
	if len(positional) != 1 {
		return usagef("show", "show needs one short code")
	}
	code, err := shortCode("show", positional[0])
	if err != nil {
		return err
	}
	client, err := a.client()
	if err != nil {
		return err
	}

	share, shareErr := client.GetShare(ctx, code)
	if shareErr == nil {
		return out.emit(map[string]any{
			"kind": "share", "short_code": share.ShortCode, "expired_at": share.ExpiredAt,
		}, func(o *output) {
			fmt.Fprintf(o.stdout, "Share %s\n  Expires: %s\n", share.ShortCode, expiryText(share.ExpiredAt))
		})
	}
	// A key without shares:read can still own requests, so a refusal falls through too.
	if !errors.Is(shareErr, credenshare.ErrNotFound) && !errors.Is(shareErr, credenshare.ErrPermission) {
		return shareErr
	}

	request, requestErr := client.GetRequest(ctx, code)
	if requestErr != nil {
		if errors.Is(requestErr, credenshare.ErrNotFound) {
			if errors.Is(shareErr, credenshare.ErrNotFound) {
				return &notFoundError{fmt.Sprintf("no share or request %s on this account", code)}
			}
			return shareErr
		}
		return requestErr
	}

	// A deleted request answers with its short code and nothing else.
	deleted := request.PublicKey == "" && request.ExpiredAt == nil
	_, keyErr := a.Keyring.Get(seedAccount(a.apiURL(), request.ShortCode))
	keyHere := keyErr == nil
	result := map[string]any{
		"kind": "request", "short_code": request.ShortCode, "expired_at": request.ExpiredAt,
		"deleted": deleted, "key_in_keychain": keyHere,
	}
	submissions := -1
	if !deleted {
		if page, err := client.ListSubmissions(ctx, request.ShortCode); err == nil {
			submissions = len(page.Submissions)
			result["submissions"] = submissions
		}
	}
	return out.emit(result, func(o *output) {
		fmt.Fprintf(o.stdout, "Request %s\n", request.ShortCode)
		if deleted {
			fmt.Fprintln(o.stdout, "  Deleted")
			return
		}
		state := "open"
		if closedBy(request, a.Now()) {
			state = "closed"
		}
		fmt.Fprintf(o.stdout, "  Expires: %s (%s)\n", expiryText(request.ExpiredAt), state)
		if submissions >= 0 {
			fmt.Fprintf(o.stdout, "  Submissions: %d\n", submissions)
		}
		where := "yes"
		if !keyHere {
			where = "no (use --access-link-file with receive)"
		}
		fmt.Fprintf(o.stdout, "  Key in this keychain: %s\n", where)
	})
}

var expireCommand = command{
	name:    "expire",
	summary: "Expire a share now",
	help:    expireHelp,
	run:     runExpire,
}

const expireHelp = `Usage: credenshare expire CODE [--yes]

Expires a share immediately. Its content is gone for good, for everyone, CredenShare
included. Asks first unless --yes is given; without a terminal, --yes is required.

To close or delete a secure request, use ` + "`credenshare request delete CODE`" + `.
`

func runExpire(ctx context.Context, a *App, out *output, args []string) error {
	fs := newFlagSet("expire")
	yes := fs.Bool("yes", false, "")
	positional, err := parseArgs(fs, "expire", expireHelp, out, args)
	if err != nil {
		return err
	}
	if len(positional) != 1 {
		return usagef("expire", "expire needs one share code")
	}
	code, err := shortCode("expire", positional[0])
	if err != nil {
		return err
	}
	client, err := a.client()
	if err != nil {
		return err
	}
	if !*yes {
		if err := confirm(ctx, a, "expire", fmt.Sprintf(
			"Expire share %s? Its content will be gone for good.", code)); err != nil {
			return err
		}
	}
	if err := client.ExpireShare(ctx, code); err != nil {
		return err
	}
	return out.emit(map[string]any{"short_code": code, "expired": true}, func(o *output) {
		fmt.Fprintf(o.stdout, "Share %s expired.\n", code)
	})
}

var statsCommand = command{
	name:    "stats",
	summary: "Show the account's or team's share counts and recent views",
	help:    statsHelp,
	run:     runStats,
}

const statsHelp = `Usage: credenshare stats

Active and expired shares, total views, and views for each of the last 14 days. A team key
shows the team's figures.
`

func runStats(ctx context.Context, a *App, out *output, args []string) error {
	if err := noArguments("stats", statsHelp, out, args); err != nil {
		return err
	}
	client, err := a.client()
	if err != nil {
		return err
	}
	stats, err := client.GetStats(ctx)
	if err != nil {
		return err
	}
	days := make([]map[string]any, 0, len(stats.DailyViews))
	recent := 0
	for _, day := range stats.DailyViews {
		days = append(days, map[string]any{"date": day.Date, "count": day.Count})
		recent += day.Count
	}
	return out.emit(map[string]any{
		"shares": map[string]int{
			"active":       stats.Shares.Active,
			"expired":      stats.Shares.Expired,
			"total_viewed": stats.Shares.TotalViewed,
		},
		"daily_views": days,
	}, func(o *output) {
		fmt.Fprintf(o.stdout, "Active shares   %d\nExpired shares  %d\nTotal views     %d\n",
			stats.Shares.Active, stats.Shares.Expired, stats.Shares.TotalViewed)
		if len(stats.DailyViews) == 0 {
			return
		}
		fmt.Fprintf(o.stdout, "\nViews, last %d days: %d\n", len(stats.DailyViews), recent)
		for _, day := range stats.DailyViews {
			fmt.Fprintf(o.stdout, "  %s  %d\n", day.Date, day.Count)
		}
	})
}
