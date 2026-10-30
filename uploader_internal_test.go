package restless

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"syscall"
	"testing"
	"time"
)

func TestRetryDelay(t *testing.T) {
	inRange := func(t *testing.T, got, lo, hi time.Duration) {
		t.Helper()
		if got < lo || got > hi {
			t.Errorf("delay %s outside [%s, %s]", got, lo, hi)
		}
	}

	t.Run("Retry-After in seconds", func(t *testing.T) {
		if got := retryDelay("3", 0, time.Second); got != 3*time.Second {
			t.Errorf("got %s, want 3s", got)
		}
		if got := retryDelay("0", 1, time.Second); got != 0 {
			t.Errorf("got %s, want 0", got)
		}
	})
	t.Run("Retry-After is capped at 10s", func(t *testing.T) {
		if got := retryDelay("120", 0, time.Second); got != maxRetryDelay {
			t.Errorf("got %s, want %s", got, maxRetryDelay)
		}
		if got := retryDelay("1e300", 0, time.Second); got != maxRetryDelay {
			t.Errorf("got %s, want %s", got, maxRetryDelay)
		}
	})
	t.Run("Retry-After as an HTTP date", func(t *testing.T) {
		at := time.Now().Add(4 * time.Second).UTC().Format(http.TimeFormat)
		inRange(t, retryDelay(at, 0, time.Second), 2*time.Second, 4*time.Second)
	})
	t.Run("a past date, a negative or garbage value falls back to backoff", func(t *testing.T) {
		past := time.Now().Add(-time.Hour).UTC().Format(http.TimeFormat)
		for _, h := range []string{past, "-5", "soon", "NaN", "Inf", ""} {
			inRange(t, retryDelay(h, 0, time.Second), 500*time.Millisecond, 1500*time.Millisecond)
		}
	})
	t.Run("backoff doubles per retry, jittered", func(t *testing.T) {
		inRange(t, retryDelay("", 1, time.Second), time.Second, 3*time.Second)
		inRange(t, retryDelay("", 5, time.Second), 10*time.Second, maxRetryDelay)
	})
}

func TestNotSent(t *testing.T) {
	refused := &net.OpError{Op: "dial", Net: "tcp", Err: os.NewSyscallError("connect", syscall.ECONNREFUSED)}
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{"connection refused", fmt.Errorf("Post: %w", refused), true},
		{"DNS failure", &net.DNSError{Err: "no such host", Name: "ingress.invalid", IsNotFound: true}, true},
		{"DNS timeout", &net.DNSError{Err: "i/o timeout", Name: "ingress.invalid", IsTimeout: true}, false},
		{"reset after send", &net.OpError{Op: "read", Net: "tcp", Err: os.NewSyscallError("read", syscall.ECONNRESET)}, false},
		{"deadline", fmt.Errorf("Post: %w", context.DeadlineExceeded), false},
		{"unrelated", errors.New("boom"), false},
	}
	for _, c := range cases {
		if got := notSent(c.err); got != c.want {
			t.Errorf("%s: notSent = %v, want %v", c.name, got, c.want)
		}
	}
}
