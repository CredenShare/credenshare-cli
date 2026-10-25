package cli

import (
	"encoding/base64"
	"errors"
	"fmt"
	"net/url"
	"strings"

	credenshare "github.com/CredenShare/credenshare-sdk-go"
	"github.com/zalando/go-keyring"
)

// keyringService names every entry this program keeps, in the macOS Keychain, the Windows
// Credential Manager or the Linux Secret Service.
const keyringService = "credenshare-cli"

// A Keyring holds secrets: the API key, and each secure request's private seed.
//
// There is deliberately no file-based implementation. Where no keychain exists, the API key
// comes from CREDENSHARE_API_KEY and a request's key goes to a file the user names, so a
// secret is never written to disk without someone asking for exactly that.
type Keyring interface {
	Get(account string) (string, error)
	Set(account, secret string) error
	Delete(account string) error
}

var errSecretNotFound = errors.New("not in the keychain")

type systemKeyring struct{}

func (systemKeyring) Get(account string) (string, error) {
	value, err := keyring.Get(keyringService, account)
	if errors.Is(err, keyring.ErrNotFound) {
		return "", errSecretNotFound
	}
	return value, err
}

func (systemKeyring) Set(account, secret string) error {
	return keyring.Set(keyringService, account, secret)
}

func (systemKeyring) Delete(account string) error {
	err := keyring.Delete(keyringService, account)
	if errors.Is(err, keyring.ErrNotFound) {
		return errSecretNotFound
	}
	return err
}

// Entries are per API address, so a production key and a development key can both be kept,
// and a request's seed is found by the address it was created against.
func apiKeyAccount(apiURL string) string { return "api-key " + apiURL }

func seedAccount(apiURL, shortCode string) string {
	return "request-seed " + apiURL + " " + shortCode
}

func encodeSeed(seed []byte) string { return base64.RawURLEncoding.EncodeToString(seed) }

func decodeSeed(text string) ([]byte, error) {
	seed, err := base64.RawURLEncoding.DecodeString(strings.TrimSpace(text))
	if err != nil || len(seed) != credenshare.SeedLength {
		return nil, fmt.Errorf("the stored key for this request is damaged")
	}
	return seed, nil
}

// parseAccessLink reads a request's access link — its collect link with the private seed in
// the fragment — back into the short code and the seed.
func parseAccessLink(link string) (code string, seed []byte, err error) {
	parsed, err := url.Parse(strings.TrimSpace(link))
	if err != nil {
		return "", nil, fmt.Errorf("this is not an access link: %v", err)
	}
	path := strings.Trim(parsed.Path, "/")
	if !strings.HasPrefix(path, "r/") || !shortCodePattern.MatchString(path[2:]) {
		return "", nil, fmt.Errorf("this is not a request's access link (…/r/CODE#KEY)")
	}
	if seed, err = credenshare.DecodeFragment(parsed.Fragment); err != nil {
		return "", nil, fmt.Errorf("the access link's key: %w", err)
	}
	return path[2:], seed, nil
}
