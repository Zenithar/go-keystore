package backends

import (
	"context"
	"errors"
)

var (
	// ErrWatchNotSupported is raised when trying to access watch feature from a watch disabled backend
	ErrWatchNotSupported = errors.New("backend: Watch prefix not supported for this backend")
	// ErrWatchCanceled is raised when trying to shutdown the backend storage
	ErrWatchCanceled = errors.New("backend: Watch canceled")
)

// WatchOptions represents options for watch operations
type WatchOptions struct {
	WaitIndex uint64
	Keys      []string
}

// WatchOption configures the WatchPrefix operation
type WatchOption func(*WatchOptions)

// WithKeys reduces the scope of keys that can trigger updates to keys (not an exact match)
func WithKeys(keys []string) WatchOption {
	return func(o *WatchOptions) {
		o.Keys = keys
	}
}

// WithWaitIndex sets the WaitIndex of the watcher
func WithWaitIndex(waitIndex uint64) WatchOption {
	return func(o *WatchOptions) {
		o.WaitIndex = waitIndex
	}
}

// Backend Key / Value store contract
type Backend interface {
	Get(ctx context.Context, key string) ([]byte, error)
	Set(ctx context.Context, key string, value []byte) error
	List(ctx context.Context, key string) ([]string, error)
	WatchPrefix(ctx context.Context, prefix string, opts ...WatchOption) (uint64, error)
	Close(ctx context.Context) error
}
