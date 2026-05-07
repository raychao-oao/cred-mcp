package keychain

import (
	"errors"
	"testing"

	"github.com/zalando/go-keyring"
)

func TestRoundtrip(t *testing.T) {
	keyring.MockInit()

	const key = "test-roundtrip"
	const value = "hunter2"

	if err := Set(key, value); err != nil {
		t.Fatalf("Set: %v", err)
	}

	got, err := Get(key)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got != value {
		t.Fatalf("Get returned %q, want %q", got, value)
	}

	if err := Delete(key); err != nil {
		t.Fatalf("Delete: %v", err)
	}

	if _, err := Get(key); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Get after Delete: want ErrNotFound, got %v", err)
	}
}

func TestKeyValidation(t *testing.T) {
	keyring.MockInit()

	cases := []struct {
		name string
		key  string
	}{
		{"empty", ""},
		{"contains colon", "foo:bar"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := Set(tc.key, "v"); err == nil {
				t.Errorf("Set(%q) should error, got nil", tc.key)
			}
			if _, err := Get(tc.key); err == nil {
				t.Errorf("Get(%q) should error, got nil", tc.key)
			}
			if err := Delete(tc.key); err == nil {
				t.Errorf("Delete(%q) should error, got nil", tc.key)
			}
		})
	}
}

func TestNotFound(t *testing.T) {
	keyring.MockInit()

	if _, err := Get("nope"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Get nonexistent: want ErrNotFound, got %v", err)
	}
	if err := Delete("nope"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Delete nonexistent: want ErrNotFound, got %v", err)
	}
}
