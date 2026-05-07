// Package clipboard wraps the OS clipboard with an opinionated auto-clear
// behavior: when cred-mcp puts a secret on the clipboard, it should disappear
// after a TTL — but only if the user has not pasted-and-replaced it in the
// meantime, in which case we leave their content alone.
//
// Backed by github.com/atotto/clipboard, which shells out to pbcopy/pbpaste on
// macOS, xclip/xsel on Linux, and clip.exe on Windows. No cgo required.
package clipboard

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/atotto/clipboard"
)

// ErrUnsupported is returned when the platform's clipboard utilities are not
// available (e.g. headless Linux without xclip / xsel installed).
var ErrUnsupported = errors.New("clipboard: not supported on this platform")

// nowFunc is a seam for tests.
var nowFunc = time.Now

// readFunc and writeFunc are seams for tests.
var (
	readFunc  = clipboard.ReadAll
	writeFunc = clipboard.WriteAll
)

// Result describes how an auto-clear operation ended.
type Result int

const (
	// Restored: TTL expired, the clipboard still held our secret, and we
	// restored the previous value (or cleared it if there was none).
	Restored Result = iota
	// UserModified: the user (or another process) changed the clipboard
	// before TTL expired, so we left it alone.
	UserModified
	// ContextCanceled: the caller's context was canceled or deadline hit
	// before TTL expired; the clipboard was NOT cleared.
	ContextCanceled
)

func (r Result) String() string {
	switch r {
	case Restored:
		return "restored"
	case UserModified:
		return "user-modified"
	case ContextCanceled:
		return "context-canceled"
	default:
		return fmt.Sprintf("unknown(%d)", int(r))
	}
}

// SetWithAutoClear puts secret on the clipboard and returns a function that
// blocks until either the TTL expires or ctx is canceled. The returned
// function reports how the wait ended; callers can ignore the return value.
//
// Behavior:
//   - The previous clipboard value is captured before writing the secret.
//   - When the TTL expires, the clipboard is checked. If it still contains the
//     secret we wrote, the previous value is restored. If it no longer holds
//     the secret (user replaced it), it is left alone.
//   - If ctx is canceled before TTL, the clipboard is NOT modified — the
//     caller is responsible for deciding what to do.
//
// SetWithAutoClear returns an error only for the initial write or context
// readiness; the auto-clear phase reports its outcome via the wait function's
// return value.
func SetWithAutoClear(ctx context.Context, secret string, ttl time.Duration) (wait func() Result, err error) {
	if clipboard.Unsupported {
		return nil, ErrUnsupported
	}
	if ttl <= 0 {
		return nil, fmt.Errorf("clipboard: ttl must be positive, got %v", ttl)
	}

	prev, err := readFunc()
	if err != nil {
		// Reading the previous value failed; treat as empty so we can still
		// clear our secret afterwards. (Some Linux setups error when the
		// clipboard is empty; we accept the gap.)
		prev = ""
	}

	if err := writeFunc(secret); err != nil {
		return nil, fmt.Errorf("clipboard: write: %w", err)
	}

	wait = func() Result {
		timer := time.NewTimer(ttl)
		defer timer.Stop()

		select {
		case <-ctx.Done():
			return ContextCanceled
		case <-timer.C:
		}

		current, err := readFunc()
		if err != nil {
			// Best effort: try to restore.
			_ = writeFunc(prev)
			return Restored
		}
		if current != secret {
			return UserModified
		}
		_ = writeFunc(prev)
		return Restored
	}
	return wait, nil
}

// Clear unconditionally writes an empty string to the clipboard.
func Clear() error {
	if clipboard.Unsupported {
		return ErrUnsupported
	}
	if err := writeFunc(""); err != nil {
		return fmt.Errorf("clipboard: clear: %w", err)
	}
	return nil
}

// Read returns the current clipboard contents. Used by save_stash to ingest
// a secret the user just copied without ever passing it through LLM context.
func Read() (string, error) {
	if clipboard.Unsupported {
		return "", ErrUnsupported
	}
	v, err := readFunc()
	if err != nil {
		return "", fmt.Errorf("clipboard: read: %w", err)
	}
	return v, nil
}

var _ = nowFunc // reserved for future timing-dependent helpers
