package vault

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// ErrUnauthorized is returned by vault operations when the Vaultwarden API
// session has expired (HTTP 401). Callers can detect this with errors.Is and
// re-authenticate automatically.
var ErrUnauthorized = fmt.Errorf("vault: session expired (401)")

// Client authenticates with a Vaultwarden instance and provides decrypted
// item access. Create with New; call Login before any search or copy operation.
type Client struct {
	baseURL     string
	http        *http.Client
	cfID        string
	cfSecret    string
	accessToken string   // Bitwarden JWT obtained on Login
	symKey      [64]byte // decrypted symmetric key: [0:32]=enc, [32:64]=mac
	symKeySet   bool
}

// New creates a Client for the given Vaultwarden base URL (e.g. "https://vault.example.com").
// cfClientID and cfClientSecret are the Cloudflare Access service token credentials;
// pass empty strings if CF Access is not in use.
func New(baseURL, cfClientID, cfClientSecret string) *Client {
	t := http.DefaultTransport
	return &Client{
		baseURL:  strings.TrimRight(baseURL, "/"),
		cfID:     cfClientID,
		cfSecret: cfClientSecret,
		http:     &http.Client{Timeout: 30 * time.Second, Transport: t},
	}
}

// Login authenticates with email + masterPassword and derives the symmetric key.
// Must be called before Search or CopySecret.
func (c *Client) Login(email, masterPassword string) error {
	// Step 1: prelogin → KDF params
	kdfType, kdfIter, err := c.prelogin(email)
	if err != nil {
		return fmt.Errorf("prelogin: %w", err)
	}
	if kdfType != 0 {
		return fmt.Errorf("unsupported KDF type %d (only PBKDF2=0 supported)", kdfType)
	}

	// Step 2: derive master key + hash
	masterKey, err := deriveMasterKey(masterPassword, email, kdfIter)
	if err != nil {
		return fmt.Errorf("key derivation: %w", err)
	}
	hash := masterKeyHash(masterKey, masterPassword)
	hashB64 := base64.StdEncoding.EncodeToString(hash)

	// Step 3: stretch master key to get enc+mac for the protected symmetric key
	sk, err := stretchMasterKey(masterKey)
	if err != nil {
		return fmt.Errorf("stretch: %w", err)
	}

	// Step 4: token endpoint → access token + protected symmetric key
	accessToken, protectedKey, err := c.connectToken(email, hashB64)
	if err != nil {
		return fmt.Errorf("connect/token: %w", err)
	}
	c.accessToken = accessToken

	// Step 5: decrypt protected symmetric key → 64-byte symKey
	plainKey, err := decryptEncString(protectedKey, sk.enc[:], sk.mac[:])
	if err != nil {
		return fmt.Errorf("decrypt protected key: %w", err)
	}
	if len(plainKey) != 64 {
		return fmt.Errorf("unexpected symmetric key length %d (want 64)", len(plainKey))
	}
	copy(c.symKey[:], plainKey)
	c.symKeySet = true
	return nil
}

// decryptStr decrypts a vault EncString using the session symmetric key.
func (c *Client) decryptStr(s string) (string, error) {
	if !c.symKeySet {
		return "", fmt.Errorf("not logged in")
	}
	b, err := decryptEncString(s, c.symKey[:32], c.symKey[32:])
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// --- API helpers ---

func (c *Client) newReq(method, path string, body io.Reader) (*http.Request, error) {
	req, err := http.NewRequest(method, c.baseURL+path, body)
	if err != nil {
		return nil, err
	}
	if c.cfID != "" {
		req.Header.Set("CF-Access-Client-Id", c.cfID)
		req.Header.Set("CF-Access-Client-Secret", c.cfSecret)
	}
	if c.accessToken != "" {
		req.Header.Set("Authorization", "Bearer "+c.accessToken)
	}
	return req, nil
}

func (c *Client) doJSON(req *http.Request, out any) error {
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	if resp.StatusCode == 401 {
		return ErrUnauthorized
	}
	if resp.StatusCode >= 400 {
		return fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(data))
	}
	if out != nil {
		return json.Unmarshal(data, out)
	}
	return nil
}

func (c *Client) prelogin(email string) (kdfType, kdfIterations int, err error) {
	body, _ := json.Marshal(map[string]string{"email": email})
	req, err := c.newReq("POST", "/api/accounts/prelogin", bytes.NewReader(body))
	if err != nil {
		return 0, 0, err
	}
	req.Header.Set("Content-Type", "application/json")

	var result struct {
		Kdf           int `json:"kdf"`
		KdfIterations int `json:"kdfIterations"`
	}
	if err := c.doJSON(req, &result); err != nil {
		return 0, 0, err
	}
	return result.Kdf, result.KdfIterations, nil
}

func (c *Client) connectToken(email, masterKeyHashB64 string) (accessToken, protectedKey string, err error) {
	form := url.Values{}
	form.Set("grant_type", "password")
	form.Set("username", email)
	form.Set("password", masterKeyHashB64)
	form.Set("scope", "api offline_access")
	form.Set("client_id", "web")
	form.Set("deviceType", "10") // SDK type
	form.Set("deviceIdentifier", "cred-mcp")
	form.Set("deviceName", "cred-mcp")

	req, err := c.newReq("POST", "/identity/connect/token", strings.NewReader(form.Encode()))
	if err != nil {
		return "", "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Bitwarden-Client-Name", "web")
	req.Header.Set("Bitwarden-Client-Version", "2024.10.2")

	var result struct {
		AccessToken string `json:"access_token"`
		Key         string `json:"Key"`
	}
	if err := c.doJSON(req, &result); err != nil {
		return "", "", err
	}
	if result.AccessToken == "" {
		return "", "", fmt.Errorf("no access_token in response")
	}
	return result.AccessToken, result.Key, nil
}
