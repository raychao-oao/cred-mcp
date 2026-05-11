package vault

import (
	"fmt"
	"strings"
)

// Item is a vault entry with decrypted metadata.
// The secret (password/TOTP) is deliberately absent — use CopySecret.
type Item struct {
	ID       string
	Name     string
	Username string
	URIs     []string
}

// rawCipher is the wire format from GET /api/ciphers.
type rawCipher struct {
	ID   string `json:"Id"`
	Type int    `json:"Type"` // 1=login, 2=secure note, 3=card, 4=identity
	Name string `json:"Name"`
	Login *struct {
		Username string `json:"Username"`
		Password string `json:"Password"`
		Uris     []struct {
			URI string `json:"Uri"`
		} `json:"Uris"`
	} `json:"Login"`
}

type ciphersResponse struct {
	Data []rawCipher `json:"Data"`
}

// Search returns all login items whose decrypted name or URI contains query
// (case-insensitive). Returns metadata only; no secrets.
func (c *Client) Search(query string) ([]Item, error) {
	if !c.symKeySet {
		return nil, fmt.Errorf("not logged in")
	}

	req, err := c.newReq("GET", "/api/ciphers", nil)
	if err != nil {
		return nil, err
	}

	var raw ciphersResponse
	if err := c.doJSON(req, &raw); err != nil {
		return nil, fmt.Errorf("list ciphers: %w", err)
	}

	q := strings.ToLower(query)
	var results []Item
	for _, r := range raw.Data {
		if r.Type != 1 || r.Login == nil {
			continue
		}
		name, err := c.decryptStr(r.Name)
		if err != nil {
			continue
		}
		username, _ := c.decryptStr(r.Login.Username)

		var uris []string
		for _, u := range r.Login.Uris {
			uri, err := c.decryptStr(u.URI)
			if err == nil && uri != "" {
				uris = append(uris, uri)
			}
		}

		if q == "" || strings.Contains(strings.ToLower(name), q) || urisContain(uris, q) {
			results = append(results, Item{
				ID:       r.ID,
				Name:     name,
				Username: username,
				URIs:     uris,
			})
		}
	}
	return results, nil
}

// Secret returns the decrypted password for the given item ID.
// The caller is responsible for ensuring the value does not enter LLM context.
func (c *Client) Secret(itemID string) (string, error) {
	if !c.symKeySet {
		return "", fmt.Errorf("not logged in")
	}

	req, err := c.newReq("GET", "/api/ciphers/"+itemID, nil)
	if err != nil {
		return "", err
	}

	var raw rawCipher
	if err := c.doJSON(req, &raw); err != nil {
		return "", fmt.Errorf("get cipher: %w", err)
	}
	if raw.Login == nil {
		return "", fmt.Errorf("item %q is not a login type", itemID)
	}
	return c.decryptStr(raw.Login.Password)
}

func urisContain(uris []string, q string) bool {
	for _, u := range uris {
		if strings.Contains(strings.ToLower(u), q) {
			return true
		}
	}
	return false
}
