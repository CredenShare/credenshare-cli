package cli

import (
	"regexp"
	"strings"
)

// Who opened a share, by kind: a person's browser, a link scanner, or an automated client.
//
// Chat apps, mail gateways and search engines fetch links on their own, to draw a preview or to check the page
// before the reader clicks, and a view they make is not the recipient. The same labels as the app's Access
// History, from the same user agent, so the two agree about what a mystery view was. A best-effort label from a
// header the client chooses, never a security decision.

type accessClient struct {
	Kind  string // scanner, automation, browser or unknown
	Label string
}

type uaRule struct {
	re    *regexp.Regexp
	label string
}

func rules(pairs ...string) []uaRule {
	out := make([]uaRule, 0, len(pairs)/2)
	for i := 0; i < len(pairs); i += 2 {
		out = append(out, uaRule{regexp.MustCompile("(?i)" + pairs[i]), pairs[i+1]})
	}
	return out
}

// Checked in order: the first match names the client.
var scannerRules = rules(
	`Slackbot-LinkExpanding|Slack-ImgProxy|Slackbot`, "Slack link preview",
	`WhatsApp`, "WhatsApp link preview",
	`TelegramBot`, "Telegram link preview",
	`Discordbot`, "Discord link preview",
	`SkypeUriPreview|Teams/|MicrosoftPreview`, "Microsoft Teams link preview",
	`Microsoft Office|ms-office|Outlook-iOS|Outlook-Android`, "Microsoft Office link check",
	`facebookexternalhit|Facebot|meta-externalagent`, "Facebook / Messenger link preview",
	`Twitterbot`, "X (Twitter) link preview",
	`LinkedInBot`, "LinkedIn link preview",
	`Mattermost`, "Mattermost link preview",
	`redditbot`, "Reddit link preview",
	`Pinterest`, "Pinterest link preview",
	`Viber`, "Viber link preview",
	`Snapchat`, "Snapchat link preview",
	`Applebot`, "Apple (Applebot)",
	`Googlebot|Google-InspectionTool|Google-Read-Aloud|GoogleOther|Google-Safety`, "Google crawler",
	`bingbot|BingPreview|adidxbot`, "Bing crawler",
	`DuckDuckBot|YandexBot|Baiduspider|PetalBot|SeznamBot`, "Search crawler",
	`Proofpoint`, "Proofpoint URL Defense",
	`Mimecast`, "Mimecast URL Protect",
	`Barracuda`, "Barracuda link protection",
	`IronPort|Cisco Secure Email`, "Cisco Secure Email",
	`Symantec|MessageLabs`, "Symantec email security",
	`Trend ?Micro`, "Trend Micro",
	`Zscaler`, "Zscaler",
	`Embedly|Iframely|vkShare|Bitlybot|SkypeShell`, "Link preview service",
	`\b(bot|crawler|spider|preview)\b`, "Bot or link preview",
)

// Scripted and headless clients: real software, not a person reading in a browser.
var automationRules = rules(
	`HeadlessChrome`, "Headless Chrome",
	`PhantomJS`, "PhantomJS",
	`^curl/`, "curl",
	`^Wget/`, "Wget",
	`python-requests|python-urllib|aiohttp|httpx`, "Python script",
	`Go-http-client`, "Go program",
	`^node$|node-fetch|undici|axios/`, "Node.js script",
	`okhttp`, "OkHttp client",
	`^Java/|Apache-HttpClient`, "Java program",
	`libwww-perl`, "Perl script",
	`PostmanRuntime`, "Postman",
	`insomnia`, "Insomnia",
	`HTTPie`, "HTTPie",
)

func browserName(ua string) string {
	switch {
	case strings.Contains(ua, "Edg/"):
		return "Edge"
	case strings.Contains(ua, "OPR/") || strings.Contains(ua, "Opera"):
		return "Opera"
	case strings.Contains(ua, "Firefox/"):
		return "Firefox"
	case strings.Contains(ua, "Chrome/"):
		return "Chrome"
	case strings.Contains(ua, "Safari/"):
		return "Safari"
	}
	return "Browser"
}

func classifyAccessClient(userAgent string) accessClient {
	ua := strings.TrimSpace(userAgent)
	if ua == "" {
		return accessClient{"unknown", "Unknown client"}
	}
	for _, r := range scannerRules {
		if r.re.MatchString(ua) {
			return accessClient{"scanner", r.label}
		}
	}
	for _, r := range automationRules {
		if r.re.MatchString(ua) {
			return accessClient{"automation", r.label}
		}
	}
	if strings.HasPrefix(ua, "Mozilla/") {
		return accessClient{"browser", browserName(ua)}
	}
	return accessClient{"unknown", "Unknown client"}
}
