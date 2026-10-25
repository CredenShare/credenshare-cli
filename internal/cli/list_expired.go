package cli

import (
	"context"
	"fmt"
	"net/url"
	"strconv"

	credenshare "github.com/CredenShare/credenshare-sdk-go"
)

// listExpired is list --status expired. The Go SDK's typed lists have no status yet, so this goes through Do,
// reading the same pagination block they read.
func listExpired(ctx context.Context, client *credenshare.Client, out *output, kind string, limit, page int, all bool) error {
	type listing struct {
		Items      []listedItem `json:"-"`
		Pagination struct {
			Page       int `json:"page"`
			Limit      int `json:"limit"`
			Total      int `json:"total"`
			TotalPages int `json:"total_pages"`
		} `json:"pagination"`
	}
	fetch := func(p int) ([]listedItem, *listing, error) {
		data, err := client.Do(ctx, credenshare.Call{Path: "/" + kind, Query: url.Values{
			"status": {"expired"}, "limit": {strconv.Itoa(limit)}, "page": {strconv.Itoa(p)},
		}})
		if err != nil {
			return nil, nil, err
		}
		var l listing
		if err := remarshal(data, &l); err != nil {
			return nil, nil, fmt.Errorf("reading the list: %w", err)
		}
		var items struct {
			Shares   []listedItem `json:"shares"`
			Requests []listedItem `json:"requests"`
		}
		if err := remarshal(data, &items); err != nil {
			return nil, nil, fmt.Errorf("reading the list: %w", err)
		}
		if kind == "shares" {
			return items.Shares, &l, nil
		}
		return items.Requests, &l, nil
	}

	items := []listedItem{}
	var last *listing
	for p := page; ; p++ {
		batch, l, err := fetch(p)
		if err != nil {
			return err
		}
		items = append(items, batch...)
		last = l
		// Ends on the page count, or on a short page when there is none, as the SDK's iterators do.
		if !all || (l.Pagination.TotalPages > 0 && p >= l.Pagination.TotalPages) ||
			(l.Pagination.TotalPages == 0 && len(batch) < limit) {
			break
		}
	}

	result := map[string]any{kind: items, "status": "expired"}
	if !all {
		result["page"], result["limit"], result["total"], result["total_pages"] =
			last.Pagination.Page, last.Pagination.Limit, last.Pagination.Total, last.Pagination.TotalPages
	}
	return out.emit(result, func(o *output) {
		if len(items) == 0 {
			o.note("No expired %s.", kind)
			return
		}
		fmt.Fprintf(o.stdout, "%-14s %s\n", "CODE", "ENDED")
		for _, item := range items {
			fmt.Fprintf(o.stdout, "%-14s %s\n", item.ShortCode, expiryText(item.ExpiredAt))
		}
		if !all && last.Pagination.TotalPages > last.Pagination.Page {
			o.note("Page %d of %d. Next: credenshare list %s --status expired --page %d",
				last.Pagination.Page, last.Pagination.TotalPages, kind, last.Pagination.Page+1)
		}
	})
}
