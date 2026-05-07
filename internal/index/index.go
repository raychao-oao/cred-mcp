// Package index maintains the list of secret names that cred-mcp knows
// about. The OS keychain has no portable enumeration primitive, so we
// keep our own JSON file alongside the data — simple to inspect with
// `cat` during migration, and prepared (via the Source field) to track
// future Vaultwarden-backed entries in the same index.
//
// The file lives under the OS user config directory:
//
//	macOS:   $HOME/Library/Application Support/cred-mcp/index.json
//	Linux:   $XDG_CONFIG_HOME/cred-mcp/index.json (or $HOME/.config/...)
//	Windows: %AppData%\cred-mcp\index.json
//
// Names are tracked, values are not — secret values stay in their backend
// (keychain today, vault later). If the index ever drifts from the actual
// keychain (e.g., the user deletes an entry out-of-band), list_stash will
// surface a name that copy_stash then fails to fetch; the user can clean
// up via delete_stash.
package index

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"
)

// Schema version. Bump if file format changes incompatibly.
const Version = 1

// Source records which backend an entry lives in. Today everything is
// "keychain"; "vault" will appear once feat/vault lands.
type Source string

const (
	SourceKeychain Source = "keychain"
	SourceVault    Source = "vault"
)

// Entry describes one tracked name. Value is never stored here.
type Entry struct {
	Name      string    `json:"name"`
	Source    Source    `json:"source"`
	CreatedAt time.Time `json:"created_at"`
}

// fileFormat is the on-disk schema.
type fileFormat struct {
	Version int     `json:"version"`
	Entries []Entry `json:"entries"`
}

// Index is a thread-safe handle backed by a JSON file.
type Index struct {
	mu      sync.Mutex
	path    string
	nowFunc func() time.Time
}

// New constructs an Index whose data lives at path.
func New(path string) *Index {
	return &Index{path: path, nowFunc: time.Now}
}

// Default returns an Index rooted at the OS user config directory.
func Default() (*Index, error) {
	d, err := os.UserConfigDir()
	if err != nil {
		return nil, fmt.Errorf("index: cannot determine user config dir: %w", err)
	}
	return New(filepath.Join(d, "cred-mcp", "index.json")), nil
}

// Path exposes the file path (useful for diagnostics and tests).
func (i *Index) Path() string {
	return i.path
}

// SetNowForTesting overrides the clock seam. Returns a restore function.
func (i *Index) SetNowForTesting(nowFn func() time.Time) (restore func()) {
	i.mu.Lock()
	defer i.mu.Unlock()
	prev := i.nowFunc
	i.nowFunc = nowFn
	return func() {
		i.mu.Lock()
		defer i.mu.Unlock()
		i.nowFunc = prev
	}
}

// Add records name with the given source. If name already exists in the
// index its CreatedAt is preserved (Add is treated as "ensure tracked",
// not "bump timestamp").
func (i *Index) Add(name string, source Source) error {
	i.mu.Lock()
	defer i.mu.Unlock()
	f, err := i.load()
	if err != nil {
		return err
	}
	for _, e := range f.Entries {
		if e.Name == name && e.Source == source {
			return nil // already tracked, nothing to do
		}
	}
	f.Entries = append(f.Entries, Entry{
		Name:      name,
		Source:    source,
		CreatedAt: i.nowFunc().UTC(),
	})
	return i.save(f)
}

// Remove deletes the (name, source) pair from the index. It is NOT an
// error if the entry is absent — callers may call this defensively after
// a backend delete without worrying about prior index state.
func (i *Index) Remove(name string, source Source) error {
	i.mu.Lock()
	defer i.mu.Unlock()
	f, err := i.load()
	if err != nil {
		return err
	}
	out := f.Entries[:0]
	for _, e := range f.Entries {
		if e.Name == name && e.Source == source {
			continue
		}
		out = append(out, e)
	}
	f.Entries = out
	return i.save(f)
}

// List returns all entries sorted by (source, name).
func (i *Index) List() ([]Entry, error) {
	i.mu.Lock()
	defer i.mu.Unlock()
	f, err := i.load()
	if err != nil {
		return nil, err
	}
	sort.Slice(f.Entries, func(a, b int) bool {
		if f.Entries[a].Source != f.Entries[b].Source {
			return f.Entries[a].Source < f.Entries[b].Source
		}
		return f.Entries[a].Name < f.Entries[b].Name
	})
	return f.Entries, nil
}

// load reads the file or returns an empty (Version-stamped) format if
// the file does not yet exist. A malformed file is reported as an error
// rather than silently truncated — the user's tracked names are not the
// kind of data to "fix" by overwriting.
func (i *Index) load() (*fileFormat, error) {
	b, err := os.ReadFile(i.path)
	if errors.Is(err, os.ErrNotExist) {
		return &fileFormat{Version: Version}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("index: read %q: %w", i.path, err)
	}
	var f fileFormat
	if err := json.Unmarshal(b, &f); err != nil {
		return nil, fmt.Errorf("index: parse %q (delete the file or restore from backup to recover): %w", i.path, err)
	}
	return &f, nil
}

// save writes the file atomically (tmp + rename). Mode 0600 — only the
// owner reads. Directory mode 0700 to match.
func (i *Index) save(f *fileFormat) error {
	f.Version = Version
	dir := filepath.Dir(i.path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("index: mkdir %q: %w", dir, err)
	}
	b, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		return fmt.Errorf("index: marshal: %w", err)
	}
	tmp := i.path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return fmt.Errorf("index: write %q: %w", tmp, err)
	}
	if err := os.Rename(tmp, i.path); err != nil {
		return fmt.Errorf("index: rename %q -> %q: %w", tmp, i.path, err)
	}
	return nil
}
