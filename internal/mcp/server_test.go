package mcp

import (
	"encoding/json"
	"errors"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/raychao-oao/cred-mcp/internal/clipboard"
	"github.com/raychao-oao/cred-mcp/internal/index"
	"github.com/raychao-oao/cred-mcp/internal/session"
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

// setupHandlerTest installs a fresh in-memory keychain, clipboard fake,
// per-test index file, and resets the process-wide session. Cleanup is
// registered via t.Cleanup.
func setupHandlerTest(t *testing.T) *fakeClipboard {
	t.Helper()
	keyring.MockInit()
	fake := &fakeClipboard{}
	restore := clipboard.ReplaceSeamsForTesting(fake.read, fake.write)
	session.Default.ResetForTesting()

	prevIndex := defaultIndex
	defaultIndex = index.New(filepath.Join(t.TempDir(), "index.json"))

	t.Cleanup(func() {
		restore()
		session.Default.ResetForTesting()
		defaultIndex = prevIndex
	})
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

// ---------- session gate (dispatch level) ----------

// callTool dispatches a tools/call request through the same chokepoint
// that runs in production, exercising the session gate.
func callTool(t *testing.T, name string, args map[string]any) response {
	t.Helper()
	params, err := json.Marshal(toolCallParams{
		Name:      name,
		Arguments: mustMarshal(t, args),
	})
	if err != nil {
		t.Fatalf("marshal params: %v", err)
	}
	req := &request{
		JSONRPC: "2.0",
		ID:      "test",
		Method:  "tools/call",
		Params:  json.RawMessage(params),
	}
	return handleToolCall(req, "test")
}

func TestSessionGate_PingBypassesExpiredSession(t *testing.T) {
	setupHandlerTest(t)
	session.Default.Lock()
	resp := callTool(t, "ping", map[string]any{})
	isErr, text, parsed := extract(t, resp)
	if isErr {
		t.Fatalf("ping should succeed even when session locked; got error: %s", text)
	}
	if ok, _ := parsed["ok"].(bool); !ok {
		t.Fatalf("ping result missing ok=true: %+v", parsed)
	}
}

func TestSessionGate_StashToolsDeniedWhenExpired(t *testing.T) {
	setupHandlerTest(t)
	// Swap in a session whose unlock policy denies — Lock() alone no longer
	// guarantees denial because Touch() will attempt re-unlock. Together,
	// Lock + denying policy = the "session is expired AND user declined to
	// re-authenticate" path that callers must handle.
	prev := session.Default
	session.Default = session.New(30*time.Minute, 8*time.Hour, func() error {
		return errors.New("denied for test")
	})
	t.Cleanup(func() { session.Default = prev })
	session.Default.Lock()

	for _, name := range []string{"copy_stash", "save_stash", "delete_stash"} {
		t.Run(name, func(t *testing.T) {
			resp := callTool(t, name, map[string]any{"name": "anything"})
			isErr, text, _ := extract(t, resp)
			if !isErr {
				t.Fatalf("expected tool error when session expired; got success text=%q", text)
			}
			if !strings.Contains(text, "session expired") {
				t.Fatalf("error should mention session expired; got %q", text)
			}
		})
	}
}

func TestSessionGate_StashToolsAllowedWhenActive(t *testing.T) {
	fake := setupHandlerTest(t)
	fake.value = "secret-value"

	// First save_stash should auto-unlock the session.
	resp := callTool(t, "save_stash", map[string]any{"name": "alpha"})
	if isErr, text, _ := extract(t, resp); isErr {
		t.Fatalf("save_stash on fresh session should succeed; got error: %s", text)
	}

	state, _, _ := session.Default.Snapshot()
	if state != session.StateActive {
		t.Fatalf("session state after first call = %v, want StateActive", state)
	}

	// Subsequent calls should also pass.
	resp = callTool(t, "delete_stash", map[string]any{"name": "alpha"})
	if isErr, text, _ := extract(t, resp); isErr {
		t.Fatalf("delete_stash on active session should succeed; got error: %s", text)
	}
}

// ---------- list_stash + index integration ----------

func TestListStash_EmptyOnFreshIndex(t *testing.T) {
	setupHandlerTest(t)
	resp := callTool(t, "list_stash", map[string]any{})
	isErr, text, parsed := extract(t, resp)
	if isErr {
		t.Fatalf("list_stash on fresh index should succeed; got error: %s", text)
	}
	if got, _ := parsed["count"].(float64); got != 0 {
		t.Fatalf("count = %v, want 0", parsed["count"])
	}
	entries, _ := parsed["entries"].([]any)
	if len(entries) != 0 {
		t.Fatalf("entries should be empty, got %+v", entries)
	}
}

func TestSaveStash_RecordsInIndex(t *testing.T) {
	fake := setupHandlerTest(t)
	fake.value = "v"
	if isErr, text, _ := extract(t, callTool(t, "save_stash", map[string]any{"name": "alpha"})); isErr {
		t.Fatalf("save_stash alpha: %s", text)
	}
	fake.value = "v"
	if isErr, text, _ := extract(t, callTool(t, "save_stash", map[string]any{"name": "beta"})); isErr {
		t.Fatalf("save_stash beta: %s", text)
	}

	resp := callTool(t, "list_stash", map[string]any{})
	isErr, text, parsed := extract(t, resp)
	if isErr {
		t.Fatalf("list_stash: %s", text)
	}
	if got, _ := parsed["count"].(float64); got != 2 {
		t.Fatalf("count = %v, want 2", parsed["count"])
	}
	entries, _ := parsed["entries"].([]any)
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		em, _ := e.(map[string]any)
		names = append(names, em["name"].(string))
		if em["source"] != "keychain" {
			t.Errorf("source = %v, want keychain", em["source"])
		}
		if _, ok := em["created_at"].(string); !ok {
			t.Errorf("created_at missing/non-string: %v", em["created_at"])
		}
	}
	if names[0] != "alpha" || names[1] != "beta" {
		t.Fatalf("names = %v, want [alpha beta]", names)
	}
}

func TestDeleteStash_RemovesFromIndex(t *testing.T) {
	fake := setupHandlerTest(t)
	fake.value = "v"
	if isErr, text, _ := extract(t, callTool(t, "save_stash", map[string]any{"name": "alpha"})); isErr {
		t.Fatalf("save_stash: %s", text)
	}
	if isErr, text, _ := extract(t, callTool(t, "delete_stash", map[string]any{"name": "alpha"})); isErr {
		t.Fatalf("delete_stash: %s", text)
	}

	resp := callTool(t, "list_stash", map[string]any{})
	_, _, parsed := extract(t, resp)
	if got, _ := parsed["count"].(float64); got != 0 {
		t.Fatalf("count after delete = %v, want 0", parsed["count"])
	}
}

// Even if the keychain entry is missing, delete_stash should still sweep
// the index — handles the case where the user wiped the keychain entry
// out-of-band and now wants to clean up the leftover name.
func TestDeleteStash_NotFound_StillSweepsIndex(t *testing.T) {
	setupHandlerTest(t)
	// Seed index with a name that has no keychain backing.
	if err := defaultIndex.Add("phantom", index.SourceKeychain); err != nil {
		t.Fatalf("seed index: %v", err)
	}

	resp := callTool(t, "delete_stash", map[string]any{"name": "phantom"})
	isErr, text, _ := extract(t, resp)
	if !isErr {
		t.Fatalf("expected not-found tool error; got success text=%q", text)
	}
	if !strings.Contains(text, "no stored secret") {
		t.Fatalf("error should mention not-found; got %q", text)
	}

	// Index should now be empty — the phantom got swept.
	got, err := defaultIndex.List()
	if err != nil {
		t.Fatalf("index List: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("phantom should have been swept; got %+v", got)
	}
}
