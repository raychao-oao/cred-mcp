package index

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func newTestIndex(t *testing.T) *Index {
	t.Helper()
	idx := New(filepath.Join(t.TempDir(), "index.json"))
	frozen := time.Date(2026, 5, 7, 20, 0, 0, 0, time.UTC)
	idx.SetNowForTesting(func() time.Time { return frozen })
	return idx
}

func TestAddListRoundtrip(t *testing.T) {
	idx := newTestIndex(t)

	if err := idx.Add("asablue-ssh", SourceKeychain); err != nil {
		t.Fatalf("Add: %v", err)
	}
	got, err := idx.List()
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(got) != 1 || got[0].Name != "asablue-ssh" || got[0].Source != SourceKeychain {
		t.Fatalf("List = %+v, want one keychain entry named asablue-ssh", got)
	}
}

func TestAddPreservesCreatedAtOnDuplicate(t *testing.T) {
	idx := newTestIndex(t)
	t1 := time.Date(2026, 5, 7, 20, 0, 0, 0, time.UTC)
	t2 := time.Date(2026, 5, 7, 21, 0, 0, 0, time.UTC)

	idx.SetNowForTesting(func() time.Time { return t1 })
	if err := idx.Add("alpha", SourceKeychain); err != nil {
		t.Fatalf("first Add: %v", err)
	}
	idx.SetNowForTesting(func() time.Time { return t2 })
	if err := idx.Add("alpha", SourceKeychain); err != nil {
		t.Fatalf("second Add: %v", err)
	}

	entries, err := idx.List()
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("want one entry, got %d: %+v", len(entries), entries)
	}
	if !entries[0].CreatedAt.Equal(t1) {
		t.Fatalf("CreatedAt = %v, want %v (must not bump on re-add)", entries[0].CreatedAt, t1)
	}
}

func TestRemoveDropsEntryAndIsNoOpIfAbsent(t *testing.T) {
	idx := newTestIndex(t)
	if err := idx.Add("alpha", SourceKeychain); err != nil {
		t.Fatalf("Add alpha: %v", err)
	}
	if err := idx.Add("beta", SourceKeychain); err != nil {
		t.Fatalf("Add beta: %v", err)
	}

	if err := idx.Remove("alpha", SourceKeychain); err != nil {
		t.Fatalf("Remove alpha: %v", err)
	}
	if err := idx.Remove("ghost", SourceKeychain); err != nil {
		t.Fatalf("Remove non-existent should not error, got %v", err)
	}

	got, err := idx.List()
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(got) != 1 || got[0].Name != "beta" {
		t.Fatalf("List = %+v, want [beta]", got)
	}
}

func TestListSortedBySourceThenName(t *testing.T) {
	idx := newTestIndex(t)
	for _, name := range []string{"zeta", "alpha", "mu"} {
		if err := idx.Add(name, SourceKeychain); err != nil {
			t.Fatalf("Add %s: %v", name, err)
		}
	}
	got, err := idx.List()
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	want := []string{"alpha", "mu", "zeta"}
	if len(got) != len(want) {
		t.Fatalf("len mismatch: got %d want %d", len(got), len(want))
	}
	for i := range got {
		if got[i].Name != want[i] {
			t.Fatalf("List[%d].Name = %q, want %q", i, got[i].Name, want[i])
		}
	}
}

func TestPersistsAcrossInstances(t *testing.T) {
	tmp := t.TempDir()
	path := filepath.Join(tmp, "index.json")

	idx1 := New(path)
	if err := idx1.Add("alpha", SourceKeychain); err != nil {
		t.Fatalf("Add: %v", err)
	}

	// Fresh handle, same file.
	idx2 := New(path)
	got, err := idx2.List()
	if err != nil {
		t.Fatalf("List on second handle: %v", err)
	}
	if len(got) != 1 || got[0].Name != "alpha" {
		t.Fatalf("second handle saw %+v, want [alpha]", got)
	}
}

func TestEmptyFileFirstRun(t *testing.T) {
	idx := newTestIndex(t)
	got, err := idx.List()
	if err != nil {
		t.Fatalf("List on fresh index: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("want empty list, got %+v", got)
	}
}

func TestCorruptFileSurfacesError(t *testing.T) {
	tmp := t.TempDir()
	path := filepath.Join(tmp, "index.json")
	if err := os.WriteFile(path, []byte("{not json"), 0o600); err != nil {
		t.Fatalf("seed corrupt file: %v", err)
	}
	idx := New(path)

	_, err := idx.List()
	if err == nil {
		t.Fatalf("expected parse error on corrupt file")
	}
	if !strings.Contains(err.Error(), "parse") {
		t.Fatalf("error should mention parse failure; got %v", err)
	}
}

func TestAtomicWrite(t *testing.T) {
	idx := newTestIndex(t)
	if err := idx.Add("alpha", SourceKeychain); err != nil {
		t.Fatalf("Add: %v", err)
	}
	// Final file should exist; .tmp must be gone.
	if _, err := os.Stat(idx.Path()); err != nil {
		t.Fatalf("stat final: %v", err)
	}
	if _, err := os.Stat(idx.Path() + ".tmp"); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf(".tmp should be gone; stat err=%v", err)
	}
}

func TestMixedSourcesCoexist(t *testing.T) {
	idx := newTestIndex(t)
	if err := idx.Add("shared-name", SourceKeychain); err != nil {
		t.Fatal(err)
	}
	if err := idx.Add("shared-name", SourceVault); err != nil {
		t.Fatal(err)
	}
	got, err := idx.List()
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("want 2 entries (one per source), got %d: %+v", len(got), got)
	}
	if got[0].Source != SourceKeychain || got[1].Source != SourceVault {
		t.Fatalf("sort by source then name: got %+v", got)
	}
}
