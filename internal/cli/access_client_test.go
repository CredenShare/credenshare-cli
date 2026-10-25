package cli

import "testing"

// The app's own cases (app/utils/access-client.test.ts), so the CLI and the Access History name a client alike.
const chromeUA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/148.0.0.0 Safari/537.36"

func TestClassifyAccessClient(t *testing.T) {
	for _, c := range []struct{ ua, kind, label string }{
		{"Slackbot-LinkExpanding 1.0 (+https://api.slack.com/robots)", "scanner", "Slack link preview"},
		{"WhatsApp/2.23.20.0 A", "scanner", "WhatsApp link preview"},
		{"TelegramBot (like TwitterBot)", "scanner", "Telegram link preview"},
		{"Mozilla/5.0 (compatible; Discordbot/2.0; +https://discordapp.com)", "scanner", "Discord link preview"},
		{"Mozilla/5.0 (Windows NT 6.1; WOW64) SkypeUriPreview Preview/0.5 skype-url-preview@microsoft.com", "scanner", "Microsoft Teams link preview"},
		{"facebookexternalhit/1.1 (+http://www.facebook.com/externalhit_uatext.php)", "scanner", "Facebook / Messenger link preview"},
		{"Twitterbot/1.0", "scanner", "X (Twitter) link preview"},
		{"LinkedInBot/1.0 (compatible; Mozilla/5.0; Apache-HttpClient +http://www.linkedin.com)", "scanner", "LinkedIn link preview"},
		{"Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)", "scanner", "Google crawler"},
		{"Mozilla/5.0 (Macintosh) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15 (Applebot/0.1)", "scanner", "Apple (Applebot)"},
		{"Proofpoint URL Defense", "scanner", "Proofpoint URL Defense"},
		{"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/148.0.0.0 Safari/537.36", "automation", "Headless Chrome"},
		{"curl/8.4.0", "automation", "curl"},
		{"python-requests/2.31.0", "automation", "Python script"},
		{"Go-http-client/2.0", "automation", "Go program"},
		{"node", "automation", "Node.js script"},
		{chromeUA, "browser", "Chrome"},
		{"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:131.0) Gecko/20100101 Firefox/131.0", "browser", "Firefox"},
		{chromeUA + " Edg/148.0.0.0", "browser", "Edge"},
		{"Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Mobile/15E148 Safari/604.1", "browser", "Safari"},
		{"", "unknown", "Unknown client"},
		{"SomethingElse/1.0", "unknown", "Unknown client"},
		// "bot" inside another word is not a bot.
		{chromeUA + " Robotron/1.0", "browser", "Chrome"},
	} {
		got := classifyAccessClient(c.ua)
		if got.Kind != c.kind || got.Label != c.label {
			t.Errorf("%q: got %+v, want %s %q", c.ua, got, c.kind, c.label)
		}
	}
}
