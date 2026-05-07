package mcp

import (
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"

	"github.com/raychao-oao/cred-mcp/internal/clipboard"
	"github.com/zalando/go-keyring"
)

// fakeClipboard simulates the OS clipboard for handler tests.
type fakeClipboard struct {
	mu      sync.Mutex
	value   string
	readErr error
	// writeErr applied on each write call.
	writeErr error
	// readHook runs at the start of each read; returns optional override
	// values. If override returns false, default value/err is used.
	readHook func(call int) (string, error, bool)
	reads    int
	writes   []string
}

func (f *fakeClipboard) read() (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.reads++
	if f.readHook != nil {
		if v, err, ok := f.readHook(f.reads); ok {
			return v, err
		}
	}
	if f.readErr != nil {
		return "", f.readErr
	}
	return f.value, nil
}

func (f *fakeClipboard) write(s string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.writeErr != nil {
		return f.writeErr
	}
	f.value = s
	f.writes = append(f.writes, s)
	return nil
}

func (f *fakeClipboard) snapshot() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.value
}

// setupHandlerTest installs a fresh in-memory keychain and clipboard fake.
// The cleanup is registered via t.Cleanup.
func setupHandlerTest(t *testing.T) *fakeClipboard {
	t.Helper()
	keyring.MockInit()
	fake := &fakeClipboard{}
	restore := clipboard.ReplaceSeamsForTesting(fake.read, fake.write)
	t.Cleanup(restore)
	return fake
}

func mustMarshal(t *testing.T, v any) json.RawMessage {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return json.RawMessage(b)
}

// extract pulls (isToolError, text, parsedOkJSON) out of a response. parsedOkJSON
// is nil for tool errors and for non-JSON-content responses.
func extract(t *testing.T, resp response) (isErr bool, text string, parsed map[string]any) {
	t.Helper()
	if resp.Error != nil {
		t.Fatalf("unexpected JSON-RPC error: code=%d msg=%s", resp.Error.Code, resp.Error.Message)
	}
	result, ok := resp.Result.(map[string]any)
	if !ok {
		t.Fatalf("Result is not map[string]any: %T", resp.Result)
	}
	isErr, _ = result["isError"].(bool)
	contents, ok := result["content"].([]map[string]any)
	if !ok || len(contents) == 0 {
		t.Fatalf("missing/empty content: %+v", result)
	}
	text, _ = contents[0]["text"].(string)
	if !isErr {
		if err := json.Unmarshal([]byte(text), &parsed); err != nil {
			t.Fatalf("ok content not valid JSON: %v\ntext: %s", err, text)
		}
	}
	return
}

// ---------- save_stash ----------

func TestSaveStash_RequiresName(t *testing.T) {
	setupHandlerTest(t)
	resp := handleSaveStash("id1", mustMarshal(t, map[string]any{"name": ""}))
	isErr, text, _ := extract(t, resp)
	if !isErr || !strings.Contains(text, "name is required") {
		t.Fatalf("want name-required error, got isErr=%v text=%q", isErr, text)
	}
}

func TestSaveStash_EmptyClipboard(t *testing.T) {
	fake := setupHandlerTest(t)
	fake.value = ""
	resp := handleSaveStash("id1", mustMarshal(t, map[string]any{"name": "foo"}))
	isErr, text, _ := extract(t, resp)
	if !isErr || !strings.Contains(text, "clipboard is empty") {
		t.Fatalf("want empty-clipboard error, got isErr=%v text=%q", isErr, text)
	}
	if _, err := keyring.Get("cred-mcp", "foo"); !errors.Is(err, keyring.ErrNotFound) {
		t.Fatalf("nothing should be stored, got: err=%v", err)
	}
}

func TestSaveStash_ClipboardReadError(t *testing.T) {
	fake := setupHandlerTest(t)
	fake.readErr = errors.New("simulated read failure")
	resp := handleSaveStash("id1", mustMarshal(t, map[string]any{"name": "foo"}))
	isErr, text, _ := extract(t, resp)
	if !isErr || !strings.Contains(text, "clipboard error") {
		t.Fatalf("want clipboard error, got isErr=%v text=%q", isErr, text)
	}
}

// Set failure path: name with ':' is rejected by keychain.validateKey.
func TestSaveStash_KeychainSetFailureLeavesClipboard(t *testing.T) {
	fake := setupHandlerTest(t)
	fake.value = "secret-value"
	resp := handleSaveStash("id1", mustMarshal(t, map[string]any{"name": "bad:name"}))
	isErr, text, _ := extract(t, resp)
	if !isErr || !strings.Contains(text, "keychain error") {
		t.Fatalf("want keychain error, got isErr=%v text=%q", isErr, text)
	}
	if got := fake.snapshot(); got != "secret-value" {
		t.Fatalf("clipboard should be untouched on Set failure, got %q", got)
	}
	if len(fake.writes) != 0 {
		t.Fatalf("no clipboard writes expected, got %d: %v", len(fake.writes), fake.writes)
	}
}

func TestSaveStash_HappyPathLeavesClipboard(t *testing.T) {
	fake := setupHandlerTest(t)
	fake.value = "secret-value"
	resp := handleSaveStash("id1", mustMarshal(t, map[string]any{"name": "foo"}))
	isErr, text, parsed := extract(t, resp)
	if isErr {
		t.Fatalf("unexpected error: %s", text)
	}
	if parsed["status"] != "stored" {
		t.Fatalf("status = %v, want stored", parsed["status"])
	}
	if got := fake.snapshot(); got != "secret-value" {
		t.Fatalf("clipboard should be untouched, got %q", got)
	}
	if len(fake.writes) != 0 {
		t.Fatalf("no clipboard writes expected, got %d: %v", len(fake.writes), fake.writes)
	}
	got, err := keyring.Get("cred-mcp", "foo")
	if err != nil || got != "secret-value" {
		t.Fatalf("keychain.Get foo = %q,%v; want secret-value", got, err)
	}
}

// ---------- delete_stash ----------

func TestDeleteStash_RequiresName(t *testing.T) {
	setupHandlerTest(t)
	resp := handleDeleteStash("id1", mustMarshal(t, map[string]any{"name": ""}))
	isErr, text, _ := extract(t, resp)
	if !isErr || !strings.Contains(text, "name is required") {
		t.Fatalf("want name-required error, got isErr=%v text=%q", isErr, text)
	}
}

func TestDeleteStash_NotFound(t *testing.T) {
	setupHandlerTest(t)
	resp := handleDeleteStash("id1", mustMarshal(t, map[string]any{"name": "ghost"}))
	isErr, text, _ := extract(t, resp)
	if !isErr || !strings.Contains(text, "no stored secret") {
		t.Fatalf("want not-found tool error, got isErr=%v text=%q", isErr, text)
	}
}

func TestDeleteStash_HappyPath(t *testing.T) {
	setupHandlerTest(t)
	if err := keyring.Set("cred-mcp", "foo", "bar"); err != nil {
		t.Fatalf("seed keychain: %v", err)
	}
	resp := handleDeleteStash("id1", mustMarshal(t, map[string]any{"name": "foo"}))
	isErr, text, parsed := extract(t, resp)
	if isErr {
		t.Fatalf("unexpected error: %s", text)
	}
	if parsed["status"] != "deleted" {
		t.Fatalf("status = %v, want deleted", parsed["status"])
	}
	if _, err := keyring.Get("cred-mcp", "foo"); !errors.Is(err, keyring.ErrNotFound) {
		t.Fatalf("expected entry gone, got err=%v", err)
	}
}
