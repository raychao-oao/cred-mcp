package vault

import (
	"bytes"
	"encoding/json"
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

// encryptStr encrypts a string using the session symmetric key.
func (c *Client) encryptStr(s string) (string, error) {
	return encryptStr(s, c.symKey[:32], c.symKey[32:])
}

// cipherWriteRequest is the wire format for POST /api/ciphers and PUT /api/ciphers/{id}.
type cipherWriteRequest struct {
	Type     int                `json:"type"`
	Name     string             `json:"name"`
	Notes    *string            `json:"notes"`
	Favorite bool               `json:"favorite"`
	Reprompt int                `json:"reprompt"`
	Login    *loginWriteRequest `json:"login"`
	Fields   []any              `json:"fields"`
}

type loginWriteRequest struct {
	Username string             `json:"username"`
	Password string             `json:"password"`
	URIs     []uriWriteRequest  `json:"uris"`
	TOTP     *string            `json:"totp"`
}

type uriWriteRequest struct {
	URI   string `json:"uri"`
	Match *int   `json:"match"`
}

// Add creates a new login item in the vault. The password must not be stored
// by the caller after this call returns — it is encrypted and then discarded.
// Returns the new item's ID.
func (c *Client) Add(name, username, password string, uris []string) (string, error) {
	if !c.symKeySet {
		return "", fmt.Errorf("not logged in")
	}
	encName, err := c.encryptStr(name)
	if err != nil {
		return "", fmt.Errorf("encrypt name: %w", err)
	}
	encUser, err := c.encryptStr(username)
	if err != nil {
		return "", fmt.Errorf("encrypt username: %w", err)
	}
	encPass, err := c.encryptStr(password)
	if err != nil {
		return "", fmt.Errorf("encrypt password: %w", err)
	}
	encURIs, err := c.encryptURIs(uris)
	if err != nil {
		return "", err
	}
	body := cipherWriteRequest{
		Type:     1,
		Name:     encName,
		Favorite: false,
		Reprompt: 0,
		Fields:   []any{},
		Login: &loginWriteRequest{
			Username: encUser,
			Password: encPass,
			URIs:     encURIs,
		},
	}
	data, err := json.Marshal(body)
	if err != nil {
		return "", err
	}
	req, err := c.newReq("POST", "/api/ciphers", bytes.NewReader(data))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")

	var result rawCipher
	if err := c.doJSON(req, &result); err != nil {
		return "", fmt.Errorf("create cipher: %w", err)
	}
	return result.ID, nil
}

// Update modifies an existing login item. Pass non-empty strings to replace
// name/username/password; pass nil for uris to leave them unchanged.
// password="" means do not change the password.
func (c *Client) Update(itemID, name, username, password string, uris []string, updateURIs bool) error {
	if !c.symKeySet {
		return fmt.Errorf("not logged in")
	}

	// Fetch current cipher to preserve fields we are not changing.
	req, err := c.newReq("GET", "/api/ciphers/"+itemID, nil)
	if err != nil {
		return err
	}
	var raw rawCipher
	if err := c.doJSON(req, &raw); err != nil {
		return fmt.Errorf("get cipher: %w", err)
	}
	if raw.Login == nil {
		return fmt.Errorf("item %q is not a login type", itemID)
	}

	// Resolve final plaintext values (keep existing if not overriding).
	finalName := name
	if finalName == "" {
		finalName, _ = c.decryptStr(raw.Name)
	}
	finalUser := username
	if finalUser == "" {
		finalUser, _ = c.decryptStr(raw.Login.Username)
	}

	// Encrypt final values.
	encName, err := c.encryptStr(finalName)
	if err != nil {
		return fmt.Errorf("encrypt name: %w", err)
	}
	encUser, err := c.encryptStr(finalUser)
	if err != nil {
		return fmt.Errorf("encrypt username: %w", err)
	}

	encPass := raw.Login.Password // keep existing encrypted password by default
	if password != "" {
		encPass, err = c.encryptStr(password)
		if err != nil {
			return fmt.Errorf("encrypt password: %w", err)
		}
	}

	// Resolve URIs.
	var encURIs []uriWriteRequest
	if updateURIs {
		encURIs, err = c.encryptURIs(uris)
		if err != nil {
			return err
		}
	} else {
		for _, u := range raw.Login.Uris {
			encURIs = append(encURIs, uriWriteRequest{URI: u.URI, Match: nil})
		}
	}

	body := cipherWriteRequest{
		Type:     1,
		Name:     encName,
		Favorite: false,
		Reprompt: 0,
		Fields:   []any{},
		Login: &loginWriteRequest{
			Username: encUser,
			Password: encPass,
			URIs:     encURIs,
		},
	}
	data, err := json.Marshal(body)
	if err != nil {
		return err
	}
	req, err = c.newReq("PUT", "/api/ciphers/"+itemID, bytes.NewReader(data))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	return c.doJSON(req, nil)
}

func (c *Client) encryptURIs(uris []string) ([]uriWriteRequest, error) {
	out := make([]uriWriteRequest, 0, len(uris))
	for _, u := range uris {
		enc, err := c.encryptStr(u)
		if err != nil {
			return nil, fmt.Errorf("encrypt uri %q: %w", u, err)
		}
		out = append(out, uriWriteRequest{URI: enc, Match: nil})
	}
	return out, nil
}

func urisContain(uris []string, q string) bool {
	for _, u := range uris {
		if strings.Contains(strings.ToLower(u), q) {
			return true
		}
	}
	return false
}
